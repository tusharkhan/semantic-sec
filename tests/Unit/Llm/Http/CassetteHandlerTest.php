<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Llm\Http;

use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Llm\Http\Cassette;
use TusharKhan\SemanticSec\Llm\Http\CassetteHandler;
use TusharKhan\SemanticSec\Llm\Http\HttpClientFactory;

final class CassetteHandlerTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/semantic-sec-cassette-' . bin2hex(random_bytes(4));
        mkdir($this->dir);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/*') ?: [] as $file) {
            unlink($file);
        }
        rmdir($this->dir);
    }

    public function testReplaysInOrder(): void
    {
        $path = $this->writeCassette([
            $this->interaction('POST', 'https://api.example.test/v1/one', 200, '{"n":1}'),
            $this->interaction('GET', 'https://api.example.test/v1/two', 429, '{"n":2}'),
        ]);
        $client = HttpClientFactory::create(new CassetteHandler(Cassette::load($path), 'replay'));

        $first = $client->post('https://api.example.test/v1/one', ['body' => '{}']);
        $second = $client->get('https://api.example.test/v1/two', ['http_errors' => false]);

        self::assertSame(200, $first->getStatusCode());
        self::assertSame('{"n":1}', (string) $first->getBody());
        self::assertSame('application/json', $first->getHeaderLine('content-type'));
        self::assertSame(429, $second->getStatusCode());
        self::assertSame('{"n":2}', (string) $second->getBody());
    }

    public function testReplayMismatchNamesExpectedAndActual(): void
    {
        $path = $this->writeCassette([$this->interaction('POST', 'https://api.example.test/v1/one', 200, '{}')]);
        $client = HttpClientFactory::create(new CassetteHandler(Cassette::load($path), 'replay'));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage("cassette {$path}: expected POST https://api.example.test/v1/one, got GET https://api.example.test/v1/other");

        $client->get('https://api.example.test/v1/other');
    }

    public function testReplayPastTheEndFails(): void
    {
        $path = $this->writeCassette([]);
        $client = HttpClientFactory::create(new CassetteHandler(Cassette::load($path), 'replay'));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage("cassette {$path}: expected no more requests, got GET https://api.example.test/v1/one");

        $client->get('https://api.example.test/v1/one');
    }

    public function testRecordScrubsAuthHeaders(): void
    {
        $path = $this->dir . '/recorded.json';
        $inner = new MockHandler([new Response(200, ['content-type' => 'application/json'], '{"ok":true}')]);
        $handler = new CassetteHandler(Cassette::load($path), 'record', $inner);
        $client = HttpClientFactory::create($handler);

        $response = $client->post('https://api.example.test/v1/messages', [
            'headers' => ['x-api-key' => 'sk-test-123', 'Authorization' => 'Bearer sk-test-123', 'api-key' => 'sk-test-123', 'anthropic-version' => '2026-10-21'],
            'body' => '{"q":1}',
        ]);

        self::assertSame('{"ok":true}', (string) $response->getBody());
        $json = (string) file_get_contents($path);
        self::assertStringNotContainsString('sk-test-123', $json);
        $saved = json_decode($json, true, flags: JSON_THROW_ON_ERROR);
        self::assertIsArray($saved);
        $request = $saved['interactions'][0]['request'];
        self::assertSame('<scrubbed>', $request['headers']['x-api-key']);
        self::assertSame('<scrubbed>', $request['headers']['Authorization']);
        self::assertSame('<scrubbed>', $request['headers']['api-key']);
        self::assertSame('2026-10-21', $request['headers']['anthropic-version']);
        self::assertSame('POST', $request['method']);
        self::assertSame('{"q":1}', $request['body']);
        self::assertSame(200, $saved['interactions'][0]['response']['status']);
        self::assertSame('{"ok":true}', $saved['interactions'][0]['response']['body']);

        $replayed = HttpClientFactory::create(new CassetteHandler(Cassette::load($path), 'replay'))
            ->post('https://api.example.test/v1/messages', ['body' => '{"q":1}']);
        self::assertSame('{"ok":true}', (string) $replayed->getBody());
    }

    public function testRejectsUnknownMode(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new CassetteHandler(Cassette::load($this->dir . '/x.json'), 'live');
    }

    public function testFactoryPushesMiddleware(): void
    {
        $seen = [];
        $spy = static function (callable $next) use (&$seen): callable {
            return static function (\Psr\Http\Message\RequestInterface $request, array $options) use ($next, &$seen) {
                $seen[] = $request->getMethod() . ' ' . $request->getUri();

                return $next($request, $options);
            };
        };
        $client = HttpClientFactory::create(new MockHandler([new Response(204)]), ['spy' => $spy]);

        $client->send(new Request('DELETE', 'https://api.example.test/v1/x'));

        self::assertSame(['DELETE https://api.example.test/v1/x'], $seen);
    }

    /** @param list<array<string, mixed>> $interactions */
    private function writeCassette(array $interactions): string
    {
        $path = $this->dir . '/cassette.json';
        file_put_contents($path, json_encode(['interactions' => $interactions], JSON_THROW_ON_ERROR));

        return $path;
    }

    /** @return array<string, mixed> */
    private function interaction(string $method, string $uri, int $status, string $body): array
    {
        return [
            'request' => ['method' => $method, 'uri' => $uri, 'headers' => [], 'body' => ''],
            'response' => ['status' => $status, 'headers' => ['content-type' => 'application/json'], 'body' => $body],
        ];
    }
}
