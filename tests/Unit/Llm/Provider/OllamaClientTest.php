<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Llm\Provider;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
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
use TusharKhan\SemanticSec\Llm\Provider\OllamaClient;
use TusharKhan\SemanticSec\Tests\Support\NetworkTrap;

final class OllamaClientTest extends TestCase
{
    private const CASSETTES = __DIR__.'/../../../Fixtures/cassettes/ollama';

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
        self::assertSame('http://localhost:11434/api/chat', (string) $request->getUri());
        self::assertSame('', $request->getHeaderLine('Authorization'));

        $body = self::body($request);
        self::assertSame('llama4', $body['model']);
        self::assertFalse($body['stream']);
        self::assertSame(FindingSchema::schema(), $body['format']);
        self::assertSame([['role' => 'system', 'content' => 'SYSTEM'], ['role' => 'user', 'content' => 'USER PAYLOAD']], $body['messages']);
        self::assertSame(['temperature' => 0.0], $body['options']);
    }

    public function testNullTemperatureOmitsOptionsAndBaseUrlIsTrimmed(): void
    {
        $client = new OllamaClient($this->mocking([new Response(200, [], self::cassetteBody('ok'))]), 'http://gpu-box:11434/', null);

        $this->send($client);

        self::assertSame('http://gpu-box:11434/api/chat', (string) $this->onlyRequest()->getUri());
        self::assertArrayNotHasKey('options', self::body($this->onlyRequest()));
    }

    public function testOkUsesEvalCounts(): void
    {
        $response = $this->send($this->replaying('ok'));

        self::assertSame(LlmOutcome::Ok, $response->outcome);
        self::assertSame(['findings' => []], $response->data);
        self::assertSame(1200, $response->inputTokens);
        self::assertSame(85, $response->outputTokens);
        self::assertSame('payload-1', $response->payloadId);
    }

    public function testMissingCountsBecomeZero(): void
    {
        $body = (string) json_encode(['model' => 'llama4', 'message' => ['role' => 'assistant', 'content' => '{"findings":[]}'], 'done' => true, 'done_reason' => 'stop']);

        $response = $this->send(new OllamaClient($this->mocking([new Response(200, [], $body)])));

        self::assertSame(LlmOutcome::Ok, $response->outcome);
        self::assertSame(0, $response->inputTokens);
        self::assertSame(0, $response->outputTokens);
    }

    public function testFencedJsonAccepted(): void
    {
        $response = $this->send($this->replaying('fenced'));

        self::assertSame(LlmOutcome::Ok, $response->outcome);
        self::assertSame(['findings' => []], $response->data);
    }

    public function testProseAroundJsonIsInvalid(): void
    {
        $response = $this->send($this->replaying('prose'));

        self::assertSame(LlmOutcome::Invalid, $response->outcome);
        self::assertNull($response->data);
    }

    public function testDoneReasonLengthIsTruncated(): void
    {
        $body = (string) json_encode(['model' => 'llama4', 'message' => ['role' => 'assistant', 'content' => '{"findings":[{"title":"x'], 'done' => true, 'done_reason' => 'length', 'prompt_eval_count' => 5, 'eval_count' => 9]);

        $response = $this->send(new OllamaClient($this->mocking([new Response(200, [], $body)])));

        self::assertSame(LlmOutcome::Truncated, $response->outcome);
        self::assertNull($response->data);
        self::assertSame(9, $response->outputTokens);
    }

    public function testMissingMessageIsInvalid(): void
    {
        $response = $this->send(new OllamaClient($this->mocking([new Response(200, [], '{"model":"llama4","done":true}')])));

        self::assertSame(LlmOutcome::Invalid, $response->outcome);
    }

    public function testServerErrorRejectsRetryable(): void
    {
        $e = $this->rejection($this->replaying('error-500'));

        self::assertTrue($e->retryable);
        self::assertSame(500, $e->status);
        self::assertSame('ollama is unavailable (HTTP 500)', $e->getMessage());
    }

    public function testModelNotFoundIsFatalAndNamesOnlyTheModel(): void
    {
        $e = $this->rejection($this->replaying('model-not-found'));

        self::assertFalse($e->retryable);
        self::assertSame(404, $e->status);
        self::assertSame('ollama model llama4 not found; pull it first', $e->getMessage());
    }

    public function testOtherClientErrorIsFatalWithoutUri(): void
    {
        $client = new OllamaClient($this->mocking([new Response(400, [], '{"error":"bad request at http://user:pw@host/x"}')]));

        $e = $this->rejection($client);

        self::assertFalse($e->retryable);
        self::assertStringNotContainsString('pw@', $e->getMessage());
        self::assertStringNotContainsString('http://', $e->getMessage());
    }

    public function testConnectionRefusedIsRetryableAndHasNoUri(): void
    {
        $refused = new ConnectException('cURL error 7: Failed to connect to secret-host port 11434 for http://secret-host:11434/api/chat', new Request('POST', 'http://secret-host:11434/api/chat'));
        $client = new OllamaClient($this->mocking([$refused]), 'http://secret-host:11434');

        $e = $this->rejection($client);

        self::assertTrue($e->retryable);
        self::assertSame('ollama is not reachable', $e->getMessage());
        self::assertNull($e->getPrevious());
    }

    public function testUnbuildableRequestRejectsInsteadOfThrowing(): void
    {
        $client = new OllamaClient($this->mocking([]), 'http://user:secret@');

        $e = $this->rejection($client);

        self::assertFalse($e->retryable);
        self::assertStringNotContainsString('secret', $e->getMessage());
    }

    /** @param list<Response|\Throwable> $queue */
    private function mocking(array $queue): Client
    {
        return HttpClientFactory::create(new MockHandler($queue), ['history' => $this->historyMiddleware()]);
    }

    private function replaying(string $name): OllamaClient
    {
        $this->cassette = new CassetteHandler(Cassette::load(self::CASSETTES."/{$name}.json"), 'replay');

        return new OllamaClient(HttpClientFactory::create($this->cassette, ['history' => $this->historyMiddleware()]));
    }

    // Same ArrayObject through a local, so the by-reference parameter cannot retype the property.
    private function historyMiddleware(): callable
    {
        $container = $this->history;

        return Middleware::history($container);
    }

    private function send(OllamaClient $client): LlmResponse
    {
        $response = $client->analyze(self::request())->wait();
        self::assertInstanceOf(LlmResponse::class, $response);

        return $response;
    }

    private function rejection(OllamaClient $client): LlmException
    {
        try {
            $promise = $client->analyze(self::request());
        } catch (\Throwable $e) {
            self::fail('analyze() threw synchronously: '.$e::class);
        }
        try {
            $promise->wait();
        } catch (\Throwable $e) {
            self::assertInstanceOf(LlmException::class, $e);

            return $e;
        }
        self::fail('expected a rejection');
    }

    private static function request(): LlmRequest
    {
        return new LlmRequest('payload-1', 'SYSTEM', 'USER PAYLOAD', FindingSchema::schema(), 'llama4');
    }

    private static function cassetteBody(string $name): string
    {
        $json = json_decode((string) file_get_contents(self::CASSETTES."/{$name}.json"), true);

        return $json['interactions'][0]['response']['body'];
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
        $body = json_decode((string) $request->getBody(), true);
        self::assertIsArray($body);

        return $body;
    }
}
