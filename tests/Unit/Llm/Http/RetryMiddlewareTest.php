<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Llm\Http;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Middleware;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use TusharKhan\SemanticSec\Llm\Http\Cassette;
use TusharKhan\SemanticSec\Llm\Http\CassetteHandler;
use TusharKhan\SemanticSec\Llm\Http\HttpClientFactory;
use TusharKhan\SemanticSec\Llm\Http\RetryMiddleware;
use TusharKhan\SemanticSec\Llm\LlmException;
use TusharKhan\SemanticSec\Llm\LlmOutcome;
use TusharKhan\SemanticSec\Llm\LlmRequest;
use TusharKhan\SemanticSec\Llm\LlmResponse;
use TusharKhan\SemanticSec\Llm\Provider\AnthropicClient;
use TusharKhan\SemanticSec\Tests\Support\NetworkTrap;

final class RetryMiddlewareTest extends TestCase
{
    private const NOW = 1_800_000_000;

    /** @var list<int> */
    private array $sleeps = [];

    /** @var \ArrayObject<int, array<mixed>> */
    private \ArrayObject $history;

    protected function setUp(): void
    {
        $this->sleeps = [];
        $this->history = new \ArrayObject();
        NetworkTrap::install();
    }

    protected function tearDown(): void
    {
        self::assertSame([], NetworkTrap::uninstall(), 'no network');
    }

    public function testRetriesOn429ThenSucceeds(): void
    {
        $response = $this->send([new Response(429), new Response(200)]);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame([1000], $this->sleeps);
        self::assertCount(2, $this->history);
    }

    public function testRetriesOn529(): void
    {
        $response = $this->send([new Response(529), new Response(200)]);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame([1000], $this->sleeps);
    }

    public function testHonoursRetryAfterSecondsAndHttpDate(): void
    {
        $date = gmdate('D, d M Y H:i:s', self::NOW + 10).' GMT';
        $response = $this->send([
            new Response(429, ['Retry-After' => '3']),
            new Response(503, ['Retry-After' => $date]),
            new Response(200),
        ]);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame([3000, 10000], $this->sleeps);
    }

    public function testShorterRetryAfterLosesToBackoff(): void
    {
        $past = gmdate('D, d M Y H:i:s', self::NOW - 30).' GMT';
        $this->send([new Response(429, ['Retry-After' => '0']), new Response(429, ['Retry-After' => $past]), new Response(429, ['Retry-After' => 'soon']), new Response(200)]);

        self::assertSame([1000, 2000, 4000], $this->sleeps);
    }

    public function testRetryAfterIsCappedAtSixtySeconds(): void
    {
        $far = gmdate('D, d M Y H:i:s', self::NOW + 3600).' GMT';
        $this->send([new Response(429, ['Retry-After' => '120']), new Response(429, ['Retry-After' => $far]), new Response(200)]);

        self::assertSame([60000, 60000], $this->sleeps);
    }

    public function testGivesUpAfterFourAttempts(): void
    {
        $mock = new MockHandler([new Response(503), new Response(503), new Response(503), new Response(429), new Response(200)]);
        $response = $this->send($mock);

        self::assertSame(429, $response->getStatusCode());
        self::assertSame([1000, 2000, 4000], $this->sleeps);
        self::assertCount(4, $this->history);
        self::assertCount(1, $mock);
    }

    #[DataProvider('finalStatuses')]
    public function testNoRetryOn401(int $status): void
    {
        $response = $this->send([new Response($status), new Response(200)]);

        self::assertSame($status, $response->getStatusCode());
        self::assertSame([], $this->sleeps);
        self::assertCount(1, $this->history);
    }

    /** @return iterable<string, array{int}> */
    public static function finalStatuses(): iterable
    {
        foreach ([400, 401, 403, 404, 422] as $status) {
            yield (string) $status => [$status];
        }
    }

    public function testConnectExceptionThenSuccess(): void
    {
        $request = new Request('POST', 'https://api.example.test/v1/messages');
        $response = $this->send([new ConnectException('refused', $request), new Response(200)]);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame([1000], $this->sleeps);
    }

    public function testTimeoutIsRetriedThenSurfacesAsCleanConnectionError(): void
    {
        $timeout = new ConnectException('cURL error 28: Operation timed out after 600000 milliseconds for https://api.anthropic.com/v1/messages', new Request('POST', 'https://api.anthropic.com/v1/messages'));
        $mock = new MockHandler(array_fill(0, 4, $timeout));
        $client = new AnthropicClient($this->http($mock), 'sk-ant-test-0000');

        try {
            $client->analyze(self::request())->wait();
            self::fail('expected an LlmException');
        } catch (LlmException $e) {
            self::assertSame('anthropic request failed: connection error', $e->getMessage());
            self::assertTrue($e->retryable);
        }
        self::assertSame([1000, 2000, 4000], $this->sleeps);
        self::assertCount(4, $this->history);
    }

    public function testTimeoutThenSuccess(): void
    {
        $timeout = new ConnectException('cURL error 28: Operation timed out', new Request('POST', 'https://api.example.test/v1/messages'));

        $response = $this->send([$timeout, new Response(200)]);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame([1000], $this->sleeps);
    }

    public function testConnectExceptionStormRejectsAfterFourAttempts(): void
    {
        $request = new Request('POST', 'https://api.example.test/v1/messages');
        $mock = new MockHandler(array_fill(0, 5, new ConnectException('refused', $request)));

        try {
            $this->send($mock);
            self::fail('expected a ConnectException');
        } catch (ConnectException) {
        }
        self::assertSame([1000, 2000, 4000], $this->sleeps);
        self::assertCount(1, $mock);
    }

    public function testWithoutSleepTheDelayGoesToTheHandler(): void
    {
        $delays = [];
        $queue = [new Response(429, ['Retry-After' => '2']), new Response(500), new Response(200)];
        $handler = static function (RequestInterface $request, array $options) use (&$delays, &$queue): PromiseInterface {
            $delays[] = $options['delay'] ?? null;

            return Create::promiseFor(array_shift($queue));
        };
        $client = HttpClientFactory::create($handler, [RetryMiddleware::create()]);

        $response = $client->post('https://api.example.test/v1/messages', ['http_errors' => false]);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame([null, 2000, 2000], $delays);
    }

    public function testAnthropicClientEndToEndRetries429(): void
    {
        $mock = new MockHandler([new Response(429, ['Retry-After' => '1']), self::anthropicOk()]);
        $client = new AnthropicClient($this->http($mock), 'sk-ant-test-0000');

        $response = $client->analyze(self::request())->wait();

        self::assertInstanceOf(LlmResponse::class, $response);
        self::assertSame(LlmOutcome::Ok, $response->outcome);
        self::assertCount(2, $this->history);
        self::assertSame([1000], $this->sleeps);
    }

    public function testAnthropicClientRejectsWithLastStatusAfter429Storm(): void
    {
        $mock = new MockHandler(array_fill(0, 4, new Response(429)));
        $client = new AnthropicClient($this->http($mock), 'sk-ant-test-0000');

        try {
            $client->analyze(self::request())->wait();
            self::fail('expected an LlmException');
        } catch (LlmException $e) {
            self::assertSame(429, $e->status);
            self::assertTrue($e->retryable);
        }
        self::assertCount(4, $this->history);
    }

    public function testAnthropicClient401FailsAtOnce(): void
    {
        $mock = new MockHandler([new Response(401, [], '{"error":{"type":"authentication_error"}}'), self::anthropicOk()]);
        $client = new AnthropicClient($this->http($mock), 'sk-ant-test-0000');

        try {
            $client->analyze(self::request())->wait();
            self::fail('expected an LlmException');
        } catch (LlmException $e) {
            self::assertSame('anthropic rejected the API key (HTTP 401)', $e->getMessage());
            self::assertStringNotContainsString('sk-ant-test-0000', $e->getMessage());
        }
        self::assertCount(1, $this->history);
    }

    public function testRetriesThroughCassetteReplay(): void
    {
        $path = sys_get_temp_dir().'/semantic-sec-retry-'.bin2hex(random_bytes(4)).'.json';
        $request = ['method' => 'POST', 'uri' => 'https://api.anthropic.com/v1/messages', 'headers' => [], 'body' => ''];
        $ok = self::anthropicOk();
        file_put_contents($path, json_encode(['interactions' => [
            ['request' => $request, 'response' => ['status' => 529, 'headers' => [], 'body' => '{"error":{"type":"overloaded_error"}}']],
            ['request' => $request, 'response' => ['status' => 200, 'headers' => ['content-type' => 'application/json'], 'body' => (string) $ok->getBody()]],
        ]], JSON_THROW_ON_ERROR));

        try {
            $cassette = new CassetteHandler(Cassette::load($path), 'replay');
            $client = new AnthropicClient($this->http($cassette), 'sk-ant-test-0000');

            $response = $client->analyze(self::request())->wait();

            self::assertInstanceOf(LlmResponse::class, $response);
            self::assertSame(LlmOutcome::Ok, $response->outcome);
            self::assertSame([1000], $this->sleeps);
            $cassette->assertExhausted();
        } finally {
            @unlink($path);
        }
    }

    /** @param MockHandler|list<Response|\Throwable> $queue */
    private function send(MockHandler|array $queue): \Psr\Http\Message\ResponseInterface
    {
        $mock = $queue instanceof MockHandler ? $queue : new MockHandler($queue);

        return $this->http($mock)->post('https://api.example.test/v1/messages', ['http_errors' => false]);
    }

    private function http(callable $handler): Client
    {
        $container = $this->history;
        $sleep = function (int $ms): void {
            $this->sleeps[] = $ms;
        };

        return HttpClientFactory::create(Middleware::history($container)($handler), [RetryMiddleware::create($sleep, static fn (): int => self::NOW)]);
    }

    private static function request(): LlmRequest
    {
        return new LlmRequest('001-get-x-1', 'SYSTEM', 'USER PAYLOAD', ['type' => 'object'], 'claude-opus-5-5', 16000, 'high');
    }

    private static function anthropicOk(): Response
    {
        return new Response(200, ['content-type' => 'application/json'], json_encode([
            'model' => 'claude-opus-5-5',
            'stop_reason' => 'end_turn',
            'content' => [['type' => 'text', 'text' => '{"findings":[]}']],
            'usage' => ['input_tokens' => 10, 'output_tokens' => 5],
        ], JSON_THROW_ON_ERROR));
    }
}
