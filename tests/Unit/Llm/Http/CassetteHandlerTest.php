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

    public function testRecordScrubsSensitiveQueryValuesAndReplayMatchesScrubbedForm(): void
    {
        $path = $this->dir . '/query.json';
        $inner = new MockHandler([new Response(200, [], '{}')]);
        $uri = 'https://api.example.test/v1/x?key=sk-live-999&model=m&access_token=abc&Signature=s1&page=2&password=p&auth=a&client_secret=c';
        HttpClientFactory::create(new CassetteHandler(Cassette::load($path), 'record', $inner))->get($uri);

        $saved = $this->saved($path);
        self::assertSame(
            'https://api.example.test/v1/x?key=<scrubbed>&model=m&access_token=<scrubbed>&Signature=<scrubbed>&page=2&password=<scrubbed>&auth=<scrubbed>&client_secret=<scrubbed>',
            $saved['interactions'][0]['request']['uri'],
        );

        $replay = HttpClientFactory::create(new CassetteHandler(Cassette::load($path), 'replay'));
        self::assertSame(200, $replay->get($uri)->getStatusCode());
    }

    public function testReplayStillRejectsADifferentNonSecretQuery(): void
    {
        $path = $this->writeCassette([$this->interaction('GET', 'https://api.example.test/v1/x?key=<scrubbed>&page=2', 200, '{}')]);
        $client = HttpClientFactory::create(new CassetteHandler(Cassette::load($path), 'replay'));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('expected GET https://api.example.test/v1/x?key=<scrubbed>&page=2, got GET https://api.example.test/v1/x?key=<scrubbed>&page=3');

        $client->get('https://api.example.test/v1/x?key=other&page=3');
    }

    public function testRecordScrubsHeadersByNamePattern(): void
    {
        $path = $this->dir . '/headers.json';
        $inner = new MockHandler([new Response(200, ['Set-Cookie' => 's=1', 'X-Session-Id' => 'abc', 'X-Request-Id' => 'req-1'], '{}')]);
        HttpClientFactory::create(new CassetteHandler(Cassette::load($path), 'record', $inner))->get('https://api.example.test/v1/x', [
            'headers' => ['X-Goog-Api-Key' => 'g', 'Cookie' => 'a=1', 'Proxy-Authorization' => 'Basic x', 'X-Auth-Token' => 't', 'Accept' => 'application/json'],
        ]);

        $saved = $this->saved($path)['interactions'][0];
        foreach (['X-Goog-Api-Key', 'Cookie', 'Proxy-Authorization', 'X-Auth-Token'] as $name) {
            self::assertSame('<scrubbed>', $saved['request']['headers'][$name], $name);
        }
        self::assertSame('application/json', $saved['request']['headers']['Accept']);
        self::assertSame('<scrubbed>', $saved['response']['headers']['Set-Cookie']);
        self::assertSame('<scrubbed>', $saved['response']['headers']['X-Session-Id']);
        self::assertSame('req-1', $saved['response']['headers']['X-Request-Id']);
    }

    public function testRecordReplacesConfiguredSecretsEverywhere(): void
    {
        $path = $this->dir . '/secrets.json';
        $inner = new MockHandler([new Response(400, ['X-Echo' => 'got sk-live-999'], '{"error":"bad key sk-live-999"}')]);
        $handler = new CassetteHandler(Cassette::load($path), 'record', $inner, ['', 'sk-live-999']);
        HttpClientFactory::create($handler)->post('https://api.example.test/v1/sk-live-999/x', [
            'headers' => ['X-Trace' => 'sk-live-999'],
            'body' => '{"prompt":"use sk-live-999 please"}',
            'http_errors' => false,
        ]);

        $json = (string) file_get_contents($path);
        self::assertStringNotContainsString('sk-live-999', $json);
        $saved = $this->saved($path)['interactions'][0];
        self::assertSame('https://api.example.test/v1/<scrubbed>/x', $saved['request']['uri']);
        self::assertSame('<scrubbed>', $saved['request']['headers']['X-Trace']);
        self::assertSame('got <scrubbed>', $saved['response']['headers']['X-Echo']);
        self::assertSame('{"prompt":"use <scrubbed> please"}', $saved['request']['body']);
        self::assertSame('{"error":"bad key <scrubbed>"}', $saved['response']['body']);
    }

    public function testRecordRedactsSecretLookingBodyValuesAndKeepsJsonValid(): void
    {
        $path = $this->dir . '/redact.json';
        $github = 'ghp_' . str_repeat('aB3dE5', 6);
        $aws = 'AKIA' . 'ABCDEFGHIJKLMNOP';
        $inner = new MockHandler([new Response(200, [], "plain text with {$aws} inside")]);
        $body = '{"note":"token ' . $github . ' \"quoted\"","empty":{},"n":1.0,"list":[]}';
        HttpClientFactory::create(new CassetteHandler(Cassette::load($path), 'record', $inner))->post('https://api.example.test/v1/x', ['body' => $body]);

        $json = (string) file_get_contents($path);
        self::assertStringNotContainsString($github, $json);
        self::assertStringNotContainsString($aws, $json);
        $saved = $this->saved($path)['interactions'][0];
        $request = json_decode($saved['request']['body'], false, flags: JSON_THROW_ON_ERROR);
        self::assertInstanceOf(\stdClass::class, $request);
        self::assertSame('token <redacted> "quoted"', $request->note);
        self::assertInstanceOf(\stdClass::class, $request->empty);
        self::assertSame(1.0, $request->n);
        self::assertSame('plain text with <redacted> inside', $saved['response']['body']);
    }

    public function testRecordLeavesCleanJsonBodiesVerbatim(): void
    {
        $path = $this->dir . '/verbatim.json';
        $inner = new MockHandler([new Response(200, [], '{ "ok" : true }')]);
        HttpClientFactory::create(new CassetteHandler(Cassette::load($path), 'record', $inner))->post('https://api.example.test/v1/x', ['body' => "{\n  \"model\": \"claude-opus-5-5\"\n}"]);

        $saved = $this->saved($path)['interactions'][0];
        self::assertSame("{\n  \"model\": \"claude-opus-5-5\"\n}", $saved['request']['body']);
        self::assertSame('{ "ok" : true }', $saved['response']['body']);
    }

    public function testRecordDropsTransportHeaders(): void
    {
        $path = $this->dir . '/transport.json';
        $inner = new MockHandler([new Response(200, ['Content-Encoding' => 'gzip', 'Content-Length' => '11', 'Transfer-Encoding' => 'chunked', 'Content-Type' => 'application/json'], '{"ok":true}')]);
        HttpClientFactory::create(new CassetteHandler(Cassette::load($path), 'record', $inner))->get('https://api.example.test/v1/x');

        self::assertSame(['Content-Type' => 'application/json'], $this->saved($path)['interactions'][0]['response']['headers']);
    }

    public function testRecordOverwritesAnExistingCassette(): void
    {
        $path = $this->writeCassette([
            $this->interaction('GET', 'https://api.example.test/v1/old1', 200, '{}'),
            $this->interaction('GET', 'https://api.example.test/v1/old2', 200, '{}'),
        ]);
        $inner = new MockHandler([new Response(200, [], '{"new":true}')]);
        HttpClientFactory::create(new CassetteHandler(Cassette::load($path), 'record', $inner))->get('https://api.example.test/v1/new');

        $interactions = $this->saved($path)['interactions'];
        self::assertCount(1, $interactions);
        self::assertSame('https://api.example.test/v1/new', $interactions[0]['request']['uri']);
    }

    public function testAssertExhaustedReportsUnusedInteractions(): void
    {
        $path = $this->writeCassette([
            $this->interaction('GET', 'https://api.example.test/v1/one', 200, '{}'),
            $this->interaction('GET', 'https://api.example.test/v1/two', 200, '{}'),
        ]);
        $handler = new CassetteHandler(Cassette::load($path), 'replay');
        $client = HttpClientFactory::create($handler);
        $client->get('https://api.example.test/v1/one');

        try {
            $handler->assertExhausted();
            self::fail('expected unused interactions to be reported');
        } catch (\LogicException $e) {
            self::assertSame("cassette {$path}: 1 unused interactions", $e->getMessage());
        }

        $client->get('https://api.example.test/v1/two');
        $handler->assertExhausted();
    }

    public function testReplayOfMissingFileFails(): void
    {
        $path = $this->dir . '/missing.json';

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage("cassette not found: {$path}");

        new CassetteHandler(Cassette::load($path), 'replay');
    }

    /** @return array{interactions: list<array{request: array{method: string, uri: string, headers: array<string, string>, body: string}, response: array{status: int, headers: array<string, string>, body: string}}>} */
    private function saved(string $path): array
    {
        /** @var array{interactions: list<array{request: array{method: string, uri: string, headers: array<string, string>, body: string}, response: array{status: int, headers: array<string, string>, body: string}}>} */
        return json_decode((string) file_get_contents($path), true, flags: JSON_THROW_ON_ERROR);
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
