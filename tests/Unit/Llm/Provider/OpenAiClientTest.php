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
use TusharKhan\SemanticSec\Llm\Provider\OpenAiClient;
use TusharKhan\SemanticSec\Llm\ValidatingClient;
use TusharKhan\SemanticSec\Tests\Support\NetworkTrap;

final class OpenAiClientTest extends TestCase
{
    private const KEY = 'sk-test-0000';

    private const GROQ = 'https://api.groq.com/openai/v1';

    private const CASSETTES = __DIR__.'/../../../Fixtures/cassettes/openai';

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
        self::assertSame('https://api.openai.com/v1/chat/completions', (string) $request->getUri());
        self::assertSame('Bearer '.self::KEY, $request->getHeaderLine('Authorization'));
        self::assertSame('application/json', $request->getHeaderLine('Content-Type'));

        $body = self::body($request);
        self::assertSame('gpt-6-astra', $body['model']);
        self::assertSame([['role' => 'system', 'content' => 'SYSTEM'], ['role' => 'user', 'content' => 'USER PAYLOAD']], $body['messages']);
        self::assertSame(['type' => 'json_schema', 'json_schema' => ['name' => FindingSchema::NAME, 'strict' => true, 'schema' => FindingSchema::schema()]], $body['response_format']);
        self::assertSame(16000, $body['max_completion_tokens']);
        foreach (['temperature', 'seed', 'max_tokens', 'effort', 'reasoning_effort', 'tools', 'tool_choice'] as $banned) {
            self::assertArrayNotHasKey($banned, $body);
        }
    }

    public function testTemperatureAndSeedAreSentWhenSet(): void
    {
        $client = new OpenAiClient($this->mocking([new Response(200, [], self::cassetteBody('ok'))]), self::KEY, temperature: 0.2, seed: 42);

        $this->send($client);

        $body = self::body($this->onlyRequest());
        self::assertSame(0.2, $body['temperature']);
        self::assertSame(42, $body['seed']);
    }

    public function testMaxCompletionTokensFollowsRequest(): void
    {
        $client = new OpenAiClient($this->mocking([new Response(200, [], self::cassetteBody('ok'))]), self::KEY);

        $this->send($client, new LlmRequest('payload-1', 'SYSTEM', 'USER', FindingSchema::schema(), 'gpt-6-astra', 4000, 'high'));

        $body = self::body($this->onlyRequest());
        self::assertSame(4000, $body['max_completion_tokens']);
        self::assertArrayNotHasKey('effort', $body);
    }

    public function testGroqBaseUrl(): void
    {
        $client = new OpenAiClient($this->mocking([new Response(200, [], self::cassetteBody('ok'))]), self::KEY, self::GROQ.'/');

        $this->send($client);

        self::assertSame(self::GROQ.'/chat/completions', (string) $this->onlyRequest()->getUri());
    }

    public function testOkDecodesMessageContentAndUsage(): void
    {
        $response = $this->send($this->replaying('ok'));

        self::assertSame(LlmOutcome::Ok, $response->outcome);
        self::assertSame('payload-1', $response->payloadId);
        self::assertNotNull($response->data);
        self::assertCount(1, $response->data['findings']);
        self::assertSame('idor', $response->data['findings'][0]['category']);
        self::assertSame(2100, $response->inputTokens);
        self::assertSame(340, $response->outputTokens);
        self::assertSame('gpt-6-astra-2026-09-01', $response->model);
        self::assertNull($response->detail);
    }

    public function testEchoedKeyIsScrubbedFromTheAnswer(): void
    {
        $content = (string) json_encode(['findings' => [['title' => 'leak '.self::KEY, 'context' => 'ctx '.self::KEY]]]);
        $body = (string) json_encode([
            'model' => 'm-'.self::KEY,
            'choices' => [['index' => 0, 'message' => ['role' => 'assistant', 'content' => $content, 'refusal' => null], 'finish_reason' => 'stop']],
            'usage' => ['prompt_tokens' => 1, 'completion_tokens' => 1],
        ]);

        $response = $this->send(new OpenAiClient($this->mocking([new Response(200, [], $body)]), self::KEY));

        self::assertSame(LlmOutcome::Ok, $response->outcome);
        self::assertStringNotContainsString(self::KEY, serialize([$response->data, $response->model]));
        self::assertSame('ctx <scrubbed>', $response->data['findings'][0]['context'] ?? null);
    }

    public function testRefusalFieldIsRefused(): void
    {
        $response = $this->send($this->replaying('refusal'));

        self::assertSame(LlmOutcome::Refused, $response->outcome);
        self::assertNull($response->data);
        self::assertSame("I can't help with that request.", $response->detail);
        self::assertSame(2200, $response->inputTokens);
    }

    public function testRefusalDetailIsScrubbed(): void
    {
        $body = self::completion(null, 'no. key '.self::KEY.' see https://example.test/x?k=1', 'stop');
        $response = $this->send(new OpenAiClient($this->mocking([new Response(200, [], $body)]), self::KEY));

        self::assertSame(LlmOutcome::Refused, $response->outcome);
        self::assertNotNull($response->detail);
        self::assertStringNotContainsString(self::KEY, $response->detail);
        self::assertStringNotContainsString('https://', $response->detail);
    }

    public function testRefusalLosesTerminalEscapes(): void
    {
        $body = (string) json_encode(['model' => 'm', 'choices' => [['message' => ['content' => null, 'refusal' => "no \x1b[31mRED\x1b[0m"], 'finish_reason' => 'stop']]]);

        $response = $this->send(new OpenAiClient($this->mocking([new Response(200, [], $body)]), self::KEY));

        self::assertSame(LlmOutcome::Refused, $response->outcome);
        self::assertSame('no  [31mRED [0m', $response->detail);
    }

    public function testDebugOutputOmitsTheKey(): void
    {
        $client = new OpenAiClient($this->mocking([]), self::KEY);

        self::assertStringNotContainsString(self::KEY, print_r($client, true));
        self::assertStringNotContainsString(self::KEY, print_r(new ValidatingClient($client), true));
    }

    public function testContentFilterIsRefused(): void
    {
        $response = $this->send(new OpenAiClient($this->mocking([new Response(200, [], self::completion(null, null, 'content_filter'))]), self::KEY));

        self::assertSame(LlmOutcome::Refused, $response->outcome);
        self::assertSame('content_filter', $response->detail);
    }

    public function testEmptyRefusalStringIsNotRefused(): void
    {
        $response = $this->send(new OpenAiClient($this->mocking([new Response(200, [], self::completion('{"findings":[]}', '', 'stop'))]), self::KEY));

        self::assertSame(LlmOutcome::Ok, $response->outcome);
    }

    public function testFinishReasonLengthIsTruncated(): void
    {
        $response = $this->send($this->replaying('length'));

        self::assertSame(LlmOutcome::Truncated, $response->outcome);
        self::assertNull($response->data);
        self::assertSame(16000, $response->outputTokens);
    }

    /** @return iterable<string, array{?string, string}> */
    public static function invalidAnswers(): iterable
    {
        yield 'prose around json' => ['Here are the findings: {"findings": []}', 'stop'];
        yield 'json array' => ['[]', 'stop'];
        yield 'null content' => [null, 'stop'];
        yield 'tool calls' => [null, 'tool_calls'];
    }

    #[DataProvider('invalidAnswers')]
    public function testUnusableAnswerIsInvalid(?string $content, string $finish): void
    {
        $response = $this->send(new OpenAiClient($this->mocking([new Response(200, [], self::completion($content, null, $finish))]), self::KEY));

        self::assertSame(LlmOutcome::Invalid, $response->outcome);
        self::assertNull($response->data);
        self::assertSame(10, $response->inputTokens);
        self::assertNotNull($response->detail);
    }

    public function testGroqSchemaMismatch400IsInvalidNotException(): void
    {
        $response = $this->send($this->replaying('groq-schema-400', self::GROQ), self::request('openai/gpt-oss-120b'));

        self::assertSame(LlmOutcome::Invalid, $response->outcome);
        self::assertNull($response->data);
        self::assertSame('openai/gpt-oss-120b', $response->model);
        self::assertSame(0, $response->inputTokens);
        self::assertNotNull($response->detail);
        self::assertStringNotContainsString('failed_generation', $response->detail);
    }

    public function testJsonValidateFailedCodeAloneIsInvalid(): void
    {
        $body = (string) json_encode(['error' => ['message' => 'output failed validation', 'type' => 'invalid_request_error', 'code' => 'json_validate_failed']]);
        $response = $this->send(new OpenAiClient($this->mocking([new Response(400, [], $body)]), self::KEY, self::GROQ));

        self::assertSame(LlmOutcome::Invalid, $response->outcome);
    }

    public function testAuth401RejectsNonRetryable(): void
    {
        $e = $this->rejection($this->replaying('auth-401'));

        self::assertSame('openai rejected the API key (HTTP 401)', $e->getMessage());
        self::assertSame(401, $e->status);
        self::assertFalse($e->retryable);
        self::assertStringNotContainsString(self::KEY, $e->getMessage());
        self::assertNull($e->getPrevious());
    }

    public function testForbiddenRejectsNonRetryableEvenOnGroq(): void
    {
        $e = $this->rejection(new OpenAiClient($this->mocking([new Response(403, [], '{"error":{"message":"nope"}}')]), self::KEY, self::GROQ));

        self::assertSame('openai rejected the API key (HTTP 403)', $e->getMessage());
        self::assertFalse($e->retryable);
    }

    /** @return iterable<string, array{int, string}> */
    public static function retryableErrors(): iterable
    {
        yield '429' => [429, '{"error":{"message":"Rate limit reached","type":"requests","code":"rate_limit_exceeded"}}'];
        yield '500' => [500, '{"error":{"message":"boom","type":"server_error"}}'];
        yield '503 html' => [503, '<html>bad gateway</html>'];
    }

    #[DataProvider('retryableErrors')]
    public function testServerErrorsRejectRetryable(int $status, string $body): void
    {
        $e = $this->rejection(new OpenAiClient($this->mocking([new Response($status, [], $body)]), self::KEY));

        self::assertSame("openai is unavailable (HTTP {$status})", $e->getMessage());
        self::assertSame($status, $e->status);
        self::assertTrue($e->retryable);
    }

    public function testOther400CarriesScrubbedApiMessage(): void
    {
        $body = (string) json_encode(['error' => ['message' => 'max_completion_tokens is too large for key '.self::KEY.' see https://api.openai.com/v1/x?key='.self::KEY, 'type' => 'invalid_request_error', 'code' => null]]);
        $e = $this->rejection(new OpenAiClient($this->mocking([new Response(400, [], $body)]), self::KEY));

        self::assertSame(400, $e->status);
        self::assertFalse($e->retryable);
        self::assertStringStartsWith('openai request failed (HTTP 400): max_completion_tokens is too large', $e->getMessage());
        self::assertStringNotContainsString('https://', $e->getMessage());
    }

    public function testUnreadable200Rejects(): void
    {
        $e = $this->rejection(new OpenAiClient($this->mocking([new Response(200, [], '{"choices":[]}')]), self::KEY));

        self::assertSame('openai returned an unreadable response (HTTP 200)', $e->getMessage());
        self::assertFalse($e->retryable);
    }

    public function testTransportErrorHidesUriAndGuzzleMessage(): void
    {
        $uri = 'https://api.openai.com/v1/chat/completions?key='.self::KEY;
        $failure = new ConnectException('cURL error 7: could not reach '.$uri, new Request('POST', $uri));
        $e = $this->rejection(new OpenAiClient($this->mocking([$failure]), self::KEY));

        self::assertSame('openai request failed: connection error', $e->getMessage());
        self::assertNull($e->status);
        self::assertTrue($e->retryable);
        self::assertNull($e->getPrevious());
    }

    public function testRedirectIsNotFollowed(): void
    {
        $client = new OpenAiClient($this->mocking([new Response(302, ['Location' => 'https://evil.example.test/steal']), new Response(200, [], '{}')]), self::KEY);

        $e = $this->rejection($client);

        self::assertSame(302, $e->status);
        self::assertFalse($e->retryable);
        self::assertStringNotContainsString('evil', $e->getMessage());
        self::assertCount(1, $this->history);
    }

    public function testMalformedBaseUrlRejectsWithoutEchoingIt(): void
    {
        $base = 'https://u:SECRET@proxy:99999/';
        $e = $this->rejection(new OpenAiClient($this->mocking([]), self::KEY, $base));

        self::assertSame('openai request could not be built', $e->getMessage());
        self::assertFalse($e->retryable);
        self::assertNull($e->getPrevious());
        self::assertStringNotContainsString('SECRET', $e->getMessage());
        self::assertCount(0, $this->history);
    }

    public function testUnencodableSchemaRejects(): void
    {
        $request = new LlmRequest('payload-1', 'SYSTEM', 'USER', ['x' => INF], 'gpt-6-astra');
        $e = $this->rejection(new OpenAiClient($this->mocking([]), self::KEY), $request);

        self::assertSame('openai request could not be built', $e->getMessage());
        self::assertNull($e->getPrevious());
    }

    public function testLiveGroqCassetteReplays(): void
    {
        $path = self::CASSETTES.'/live-groq-idor-find-by-id.json';
        if (!is_file($path)) {
            self::fail('live-groq-idor-find-by-id.json is missing; re-record it with tests/Live/OpenAiLiveTest.php');
        }

        $response = $this->send($this->replaying('live-groq-idor-find-by-id', self::GROQ), self::request('openai/gpt-oss-120b'));

        self::assertSame(LlmOutcome::Ok, $response->outcome);
        self::assertNotNull($response->data);
        $schema = json_decode((string) json_encode(FindingSchema::schema()), false);
        $data = json_decode((string) json_encode((object) $response->data), false);
        self::assertTrue((new Validator())->validate($data, $schema)->isValid());
        self::assertGreaterThan(0, $response->inputTokens);
    }

    private function replaying(string $name, string $baseUrl = OpenAiClient::DEFAULT_BASE_URL): OpenAiClient
    {
        $this->cassette = new CassetteHandler(Cassette::load(self::CASSETTES."/{$name}.json"), 'replay', secrets: [self::KEY]);

        return new OpenAiClient(HttpClientFactory::create($this->cassette, ['history' => $this->historyMiddleware()]), self::KEY, $baseUrl);
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

    private function send(OpenAiClient $client, ?LlmRequest $request = null): LlmResponse
    {
        $response = $client->analyze($request ?? self::request())->wait();
        self::assertInstanceOf(LlmResponse::class, $response);

        return $response;
    }

    private function rejection(OpenAiClient $client, ?LlmRequest $request = null): LlmException
    {
        try {
            $promise = $client->analyze($request ?? self::request());
        } catch (\Throwable $e) {
            self::fail('analyze() threw synchronously: '.$e::class);
        }
        try {
            $promise->wait();
        } catch (\Throwable $e) {
            self::assertInstanceOf(LlmException::class, $e);
            self::assertStringNotContainsString(self::KEY, $e->getMessage());

            return $e;
        }
        self::fail('expected an LlmException');
    }

    private static function request(string $model = 'gpt-6-astra'): LlmRequest
    {
        return new LlmRequest('payload-1', 'SYSTEM', 'USER PAYLOAD', FindingSchema::schema(), $model);
    }

    private static function cassetteBody(string $name): string
    {
        $json = json_decode((string) file_get_contents(self::CASSETTES."/{$name}.json"), true);

        return $json['interactions'][0]['response']['body'];
    }

    private static function completion(?string $content, ?string $refusal, string $finish): string
    {
        return (string) json_encode([
            'model' => 'gpt-6-astra',
            'choices' => [['index' => 0, 'message' => ['role' => 'assistant', 'content' => $content, 'refusal' => $refusal], 'finish_reason' => $finish]],
            'usage' => ['prompt_tokens' => 10, 'completion_tokens' => 5],
        ]);
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
