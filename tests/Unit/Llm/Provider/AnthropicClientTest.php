<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Llm\Provider;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Opis\JsonSchema\Validator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use TusharKhan\SemanticSec\Llm\FindingSchema;
use TusharKhan\SemanticSec\Llm\Http\Cassette;
use TusharKhan\SemanticSec\Llm\Http\CassetteHandler;
use TusharKhan\SemanticSec\Llm\Http\HttpClientFactory;
use TusharKhan\SemanticSec\Llm\LlmException;
use TusharKhan\SemanticSec\Llm\LlmOutcome;
use TusharKhan\SemanticSec\Llm\LlmRequest;
use TusharKhan\SemanticSec\Llm\LlmResponse;
use TusharKhan\SemanticSec\Llm\Provider\AnthropicClient;
use TusharKhan\SemanticSec\Tests\Support\NetworkTrap;

final class AnthropicClientTest extends TestCase
{
    private const KEY = 'sk-ant-test-0000';

    private const CASSETTES = __DIR__.'/../../../Fixtures/cassettes/anthropic';

    /** @var \ArrayObject<int, array<mixed>> */
    private \ArrayObject $history;

    private ?CassetteHandler $cassette = null;

    protected function setUp(): void
    {
        $this->history = new \ArrayObject();
        $this->cassette = null;
        NetworkTrap::install();
    }

    protected function tearDown(): void
    {
        self::assertSame([], NetworkTrap::uninstall(), 'no network');
        $this->cassette?->assertExhausted();
    }

    public function testRequestShape(): void
    {
        $this->send($this->replaying('ok'));

        $request = $this->onlyRequest();
        self::assertSame('POST', $request->getMethod());
        self::assertSame('https://api.anthropic.com/v1/messages', (string) $request->getUri());
        self::assertSame(self::KEY, $request->getHeaderLine('x-api-key'));
        self::assertSame('2026-10-21', $request->getHeaderLine('anthropic-version'));
        self::assertSame('server-side-fallback-2026-07-01', $request->getHeaderLine('anthropic-beta'));
        self::assertSame('application/json', $request->getHeaderLine('content-type'));

        $body = self::body($request);
        self::assertSame('claude-opus-5-5', $body['model']);
        self::assertSame(16000, $body['max_tokens']);
        self::assertSame([['type' => 'text', 'text' => 'SYSTEM', 'cache_control' => ['type' => 'ephemeral']]], $body['system']);
        self::assertSame([['role' => 'user', 'content' => 'USER PAYLOAD']], $body['messages']);
        self::assertSame('json_schema', $body['output_config']['format']['type']);
        self::assertSame(FindingSchema::schema(), $body['output_config']['format']['schema']);
        self::assertSame('high', $body['output_config']['effort']);
        self::assertSame('default', $body['fallbacks']);
        foreach (['temperature', 'top_p', 'top_k', 'tools', 'tool_choice', 'thinking'] as $banned) {
            self::assertArrayNotHasKey($banned, $body);
        }
    }

    public function testNullEffortIsOmitted(): void
    {
        $this->send($this->replaying('ok'), self::request(effort: null));

        self::assertArrayNotHasKey('effort', self::body($this->onlyRequest())['output_config']);
    }

    public function testCustomBaseUrlOmitsFallbacks(): void
    {
        $ok = (string) file_get_contents(self::CASSETTES.'/ok.json');
        $body = json_decode($ok, true)['interactions'][0]['response']['body'];
        $client = new AnthropicClient($this->mocking([new Response(200, [], $body)]), self::KEY, 'https://proxy.example.test/anthropic/');

        $response = $client->analyze(self::request())->wait();

        $request = $this->onlyRequest();
        self::assertSame('https://proxy.example.test/anthropic/v1/messages', (string) $request->getUri());
        self::assertFalse($request->hasHeader('anthropic-beta'));
        self::assertArrayNotHasKey('fallbacks', self::body($request));
        self::assertInstanceOf(LlmResponse::class, $response);
        self::assertSame(LlmOutcome::Ok, $response->outcome);
    }

    public function testOkDecodesFirstTextBlockAndUsage(): void
    {
        $response = $this->send($this->replaying('thinking-first'));

        self::assertSame(LlmOutcome::Ok, $response->outcome);
        self::assertSame('payload-1', $response->payloadId);
        self::assertNotNull($response->data);
        self::assertCount(1, $response->data['findings']);
        self::assertSame('idor', $response->data['findings'][0]['category']);
        self::assertSame(1200 + 900 + 100, $response->inputTokens);
        self::assertSame(340, $response->outputTokens);
        self::assertSame('claude-opus-5-5-fallback-test', $response->model);
        self::assertNull($response->detail);
    }

    public function testRefusalIsRefusedOutcome(): void
    {
        $response = $this->send($this->replaying('refusal'));

        self::assertSame(LlmOutcome::Refused, $response->outcome);
        self::assertNull($response->data);
        self::assertSame('cyber', $response->detail);
        self::assertSame(2200, $response->inputTokens);
    }

    public function testMaxTokensIsTruncated(): void
    {
        $response = $this->send($this->replaying('max-tokens'));

        self::assertSame(LlmOutcome::Truncated, $response->outcome);
        self::assertNull($response->data);
        self::assertSame(340, $response->outputTokens);
    }

    public function testInvalidJsonIsInvalidOutcome(): void
    {
        $body = (string) json_encode(['model' => 'claude-opus-5-5', 'content' => [['type' => 'text', 'text' => 'Here are the findings: {"findings": []}']], 'stop_reason' => 'end_turn', 'usage' => ['input_tokens' => 10, 'output_tokens' => 5]]);
        $client = new AnthropicClient($this->mocking([new Response(200, [], $body)]), self::KEY);

        $response = $client->analyze(self::request())->wait();

        self::assertInstanceOf(LlmResponse::class, $response);
        self::assertSame(LlmOutcome::Invalid, $response->outcome);
        self::assertNull($response->data);
        self::assertSame(10, $response->inputTokens);
        self::assertNotNull($response->detail);
    }

    public function testNoTextBlockIsInvalidOutcome(): void
    {
        $body = (string) json_encode(['model' => 'claude-opus-5-5', 'content' => [['type' => 'thinking', 'thinking' => '...']], 'stop_reason' => 'end_turn', 'usage' => ['input_tokens' => 10, 'output_tokens' => 5]]);
        $client = new AnthropicClient($this->mocking([new Response(200, [], $body)]), self::KEY);

        $response = $client->analyze(self::request())->wait();

        self::assertInstanceOf(LlmResponse::class, $response);
        self::assertSame(LlmOutcome::Invalid, $response->outcome);
    }

    public function testAuth401RejectsNonRetryableWithoutKey(): void
    {
        $e = $this->rejection($this->replaying('auth-401'));

        self::assertSame('anthropic rejected the API key (HTTP 401)', $e->getMessage());
        self::assertSame(401, $e->status);
        self::assertFalse($e->retryable);
        self::assertStringNotContainsString(self::KEY, $e->getMessage());
        self::assertNull($e->getPrevious());
    }

    public function testForbiddenRejectsNonRetryable(): void
    {
        $e = $this->rejection(new AnthropicClient($this->mocking([new Response(403, [], '{"type":"error","error":{"type":"permission_error","message":"nope"}}')]), self::KEY));

        self::assertSame('anthropic rejected the API key (HTTP 403)', $e->getMessage());
        self::assertFalse($e->retryable);
    }

    /** @return iterable<string, array{int, string}> */
    public static function retryableErrors(): iterable
    {
        yield '429' => [429, '{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}'];
        yield '500' => [500, '{"type":"error","error":{"type":"api_error","message":"boom"}}'];
        yield '529 overloaded' => [529, '{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}'];
        yield 'overloaded on a 4xx' => [400, '{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}'];
        yield '503 html' => [503, '<html>bad gateway</html>'];
    }

    #[DataProvider('retryableErrors')]
    public function testServerErrorsRejectRetryable(int $status, string $body): void
    {
        $e = $this->rejection(new AnthropicClient($this->mocking([new Response($status, [], $body)]), self::KEY));

        self::assertSame($status, $e->status);
        self::assertTrue($e->retryable);
        self::assertStringContainsString("HTTP {$status}", $e->getMessage());
    }

    public function testOther4xxCarriesScrubbedApiMessage(): void
    {
        $body = (string) json_encode(['type' => 'error', 'error' => ['type' => 'invalid_request_error', 'message' => 'max_tokens too large for key '.self::KEY.' see https://api.anthropic.com/v1/messages?key='.self::KEY]]);
        $e = $this->rejection(new AnthropicClient($this->mocking([new Response(400, [], $body)]), self::KEY));

        self::assertSame(400, $e->status);
        self::assertFalse($e->retryable);
        self::assertStringStartsWith('anthropic request failed (HTTP 400): max_tokens too large', $e->getMessage());
        self::assertStringNotContainsString(self::KEY, $e->getMessage());
        self::assertStringNotContainsString('https://', $e->getMessage());
    }

    public function testTransportErrorHidesUriAndGuzzleMessage(): void
    {
        $uri = 'https://api.anthropic.com/v1/messages?key='.self::KEY;
        $failure = new ConnectException('cURL error 7: could not reach '.$uri, new Request('POST', $uri));
        $e = $this->rejection(new AnthropicClient($this->mocking([$failure]), self::KEY));

        self::assertSame('anthropic request failed: connection error', $e->getMessage());
        self::assertNull($e->status);
        self::assertTrue($e->retryable);
        self::assertNull($e->getPrevious());
    }

    public function testLiveCassetteReplays(): void
    {
        $path = self::CASSETTES.'/live-idor-find-by-id.json';
        if (!is_file($path)) {
            self::markTestSkipped('live-idor-find-by-id.json is not recorded yet; see tests/Live/AnthropicLiveTest.php');
        }

        $response = $this->send($this->replaying('live-idor-find-by-id'));

        self::assertSame(LlmOutcome::Ok, $response->outcome);
        self::assertNotNull($response->data);
        $schema = json_decode((string) json_encode(FindingSchema::schema()), false);
        $data = json_decode((string) json_encode((object) $response->data), false);
        self::assertTrue((new Validator())->validate($data, $schema)->isValid());
        self::assertGreaterThan(0, $response->inputTokens);
    }

    private function replaying(string $name): AnthropicClient
    {
        $this->cassette = new CassetteHandler(Cassette::load(self::CASSETTES."/{$name}.json"), 'replay', secrets: [self::KEY]);

        return new AnthropicClient(HttpClientFactory::create($this->cassette, ['history' => $this->historyMiddleware()]), self::KEY);
    }

    /** @param list<Response|\Throwable> $queue */
    private function mocking(array $queue): Client
    {
        return HttpClientFactory::create(new MockHandler($queue), ['history' => $this->historyMiddleware()]);
    }

    // Same ArrayObject through a local, so the by-reference parameter cannot retype the property.
    private function historyMiddleware(): callable
    {
        $container = $this->history;

        return Middleware::history($container);
    }

    private function send(AnthropicClient $client, ?LlmRequest $request = null): LlmResponse
    {
        $response = $client->analyze($request ?? self::request())->wait();
        self::assertInstanceOf(LlmResponse::class, $response);

        return $response;
    }

    private function rejection(AnthropicClient $client): LlmException
    {
        try {
            $client->analyze(self::request())->wait();
        } catch (LlmException $e) {
            self::assertStringNotContainsString(self::KEY, $e->getMessage());

            return $e;
        }
        self::fail('expected an LlmException');
    }

    private static function request(?string $effort = 'high'): LlmRequest
    {
        return new LlmRequest('payload-1', 'SYSTEM', 'USER PAYLOAD', FindingSchema::schema(), 'claude-opus-5-5', 16000, $effort);
    }

    private function onlyRequest(): RequestInterface
    {
        self::assertCount(1, $this->history);
        $request = $this->history[0]['request'] ?? null;
        self::assertInstanceOf(RequestInterface::class, $request);

        return $request;
    }

    /** @return array<string, mixed> */
    private static function body(RequestInterface $request): array
    {
        $body = json_decode((string) $request->getBody(), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($body);

        return $body;
    }
}
