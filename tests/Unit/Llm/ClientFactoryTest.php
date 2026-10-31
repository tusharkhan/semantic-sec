<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Llm;

use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use TusharKhan\SemanticSec\Analysis\Confidence;
use TusharKhan\SemanticSec\Analysis\Severity;
use TusharKhan\SemanticSec\Config\Config;
use TusharKhan\SemanticSec\Config\ConfigException;
use TusharKhan\SemanticSec\Llm\ClientFactory;
use TusharKhan\SemanticSec\Llm\LlmOutcome;
use TusharKhan\SemanticSec\Llm\LlmRequest;
use TusharKhan\SemanticSec\Llm\LlmResponse;
use TusharKhan\SemanticSec\Llm\Provider\AnthropicClient;
use TusharKhan\SemanticSec\Llm\Provider\OllamaClient;
use TusharKhan\SemanticSec\Llm\Provider\OpenAiClient;
use TusharKhan\SemanticSec\Llm\ValidatingClient;
use TusharKhan\SemanticSec\Tests\Support\NetworkTrap;

final class ClientFactoryTest extends TestCase
{
    private const ENVS = ['ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'GROQ_API_KEY', 'SEMSEC_TEST_KEY'];

    /** @var array<string, string|false> */
    private array $saved = [];

    /** @var list<array{request: RequestInterface, delay: mixed, options: array<string, mixed>}> */
    private array $sent = [];

    /** @var list<Response> */
    private array $queue = [];

    protected function setUp(): void
    {
        foreach (self::ENVS as $name) {
            $this->saved[$name] = getenv($name);
            putenv($name);
        }
        $this->sent = [];
        $this->queue = [];
        NetworkTrap::install();
    }

    protected function tearDown(): void
    {
        foreach ($this->saved as $name => $value) {
            putenv($value === false ? $name : "{$name}={$value}");
        }
        self::assertSame([], NetworkTrap::uninstall(), 'no network');
    }

    public function testMissingKeyMessageNamesEnvNotValue(): void
    {
        putenv('ANTHROPIC_API_KEY=sk-ant-should-not-matter');

        try {
            ClientFactory::create(self::config('anthropic', apiKeyEnv: 'SEMSEC_TEST_KEY'));
            self::fail('expected a ConfigException');
        } catch (ConfigException $e) {
            self::assertSame('SEMSEC_TEST_KEY is not set', $e->getMessage());
            self::assertStringNotContainsString('sk-ant', $e->getMessage());
        }
    }

    public function testDefaultKeyEnvPerProvider(): void
    {
        foreach (['anthropic' => 'ANTHROPIC_API_KEY', 'openai' => 'OPENAI_API_KEY'] as $provider => $env) {
            try {
                ClientFactory::create(self::config($provider));
                self::fail("expected a ConfigException for {$provider}");
            } catch (ConfigException $e) {
                self::assertSame("{$env} is not set", $e->getMessage());
            }
        }
    }

    public function testEmptyKeyCountsAsMissing(): void
    {
        putenv('ANTHROPIC_API_KEY=');

        $this->expectExceptionObject(new ConfigException('ANTHROPIC_API_KEY is not set'));

        ClientFactory::create(self::config('anthropic'));
    }

    public function testRealClientSendsTimeouts(): void
    {
        putenv('OPENAI_API_KEY=sk-secret-3');
        $config = self::config('openai');
        $this->queue = [self::openAiOk()];

        ClientFactory::create($config, $this->handler())->analyze(ClientFactory::request($config, 'p1', 'S', 'U', ['type' => 'object']))->wait();

        self::assertSame(10, $this->sent[0]['options']['connect_timeout'] ?? null);
        self::assertSame(600, $this->sent[0]['options']['timeout'] ?? null);
    }

    public function testWhitespaceOnlyKeyCountsAsMissing(): void
    {
        putenv("ANTHROPIC_API_KEY= \t ");

        $this->expectExceptionObject(new ConfigException('ANTHROPIC_API_KEY is not set'));

        ClientFactory::create(self::config('anthropic'));
    }

    public function testKeyIsTrimmed(): void
    {
        putenv("ANTHROPIC_API_KEY=  sk-ant-secret-1\n");
        $config = self::config('anthropic');
        $this->queue = [self::anthropicOk()];

        ClientFactory::create($config, $this->handler())->analyze(ClientFactory::request($config, 'p1', 'S', 'U', ['type' => 'object']))->wait();

        self::assertSame('sk-ant-secret-1', $this->sent[0]['request']->getHeaderLine('x-api-key'));
    }

    public function testWhitespaceOnlyBaseUrlIsRejected(): void
    {
        putenv('ANTHROPIC_API_KEY=sk-ant-secret-1');

        $this->expectExceptionObject(new ConfigException('base_url must not be empty'));

        ClientFactory::create(self::config('anthropic', baseUrl: "  \n"));
    }

    public function testEmptyBaseUrlIsRejectedWithoutTheKey(): void
    {
        putenv('ANTHROPIC_API_KEY=sk-ant-secret-1');

        try {
            ClientFactory::create(self::config('anthropic', baseUrl: ''));
            self::fail('expected a ConfigException');
        } catch (ConfigException $e) {
            self::assertSame('base_url must not be empty', $e->getMessage());
        }
    }

    public function testAnthropicDefaults(): void
    {
        putenv('ANTHROPIC_API_KEY=sk-ant-secret-1');
        $config = self::config('anthropic');

        $client = ClientFactory::create($config, $this->handler());
        $this->queue = [self::anthropicOk()];
        $client->analyze(ClientFactory::request($config, 'p1', 'S', 'U', ['type' => 'object']))->wait();

        self::assertInstanceOf(AnthropicClient::class, $client);
        $request = $this->sent[0]['request'];
        self::assertSame('https://api.anthropic.com/v1/messages', (string) $request->getUri());
        self::assertSame('sk-ant-secret-1', $request->getHeaderLine('x-api-key'));
        $body = json_decode((string) $request->getBody(), true);
        self::assertIsArray($body);
        self::assertSame('claude-opus-5-5', $body['model']);
        self::assertSame('xhigh', $body['output_config']['effort']);
    }

    public function testRequestDefaults(): void
    {
        $anthropic = ClientFactory::request(self::config('anthropic', model: 'claude-sonnet-x'), 'p1', 'S', 'U', []);
        self::assertEquals(new LlmRequest('p1', 'S', 'U', [], 'claude-sonnet-x', 16000, 'xhigh'), $anthropic);

        $openai = ClientFactory::request(self::config('openai'), 'p1', 'S', 'U', []);
        self::assertSame('gpt-6-astra', $openai->model);
        self::assertNull($openai->effort);
    }

    public function testGroqRecipeBuildsOpenAiClientWithBaseUrl(): void
    {
        putenv('GROQ_API_KEY=gsk-secret-2');
        $config = self::config('openai', model: 'openai/gpt-oss-120b', apiKeyEnv: 'GROQ_API_KEY', baseUrl: 'https://api.groq.com/openai/v1');

        $client = ClientFactory::create($config, $this->handler());
        $this->queue = [self::openAiOk()];
        $response = $client->analyze(ClientFactory::request($config, 'p1', 'S', 'U', ['type' => 'object']))->wait();

        self::assertInstanceOf(OpenAiClient::class, $client);
        self::assertInstanceOf(LlmResponse::class, $response);
        self::assertSame(LlmOutcome::Ok, $response->outcome);
        $request = $this->sent[0]['request'];
        self::assertSame('https://api.groq.com/openai/v1/chat/completions', (string) $request->getUri());
        self::assertSame('Bearer gsk-secret-2', $request->getHeaderLine('Authorization'));
        $body = json_decode((string) $request->getBody(), true);
        self::assertIsArray($body);
        self::assertSame('openai/gpt-oss-120b', $body['model']);
        self::assertArrayNotHasKey('temperature', $body);
        self::assertArrayNotHasKey('seed', $body);
    }

    public function testOllamaNeedsNoKey(): void
    {
        $client = ClientFactory::create(self::config('ollama', model: 'qwen3'));

        self::assertInstanceOf(OllamaClient::class, $client);
    }

    public function testOllamaSendsNoTemperature(): void
    {
        $client = ClientFactory::create(self::config('ollama', model: 'qwen3'), $this->handler());

        $client->analyze(ClientFactory::request(self::config('ollama', model: 'qwen3'), 'p1', 'S', 'U', ['type' => 'object']))->wait(false);

        $body = json_decode((string) $this->sent[0]['request']->getBody(), true);
        self::assertIsArray($body);
        self::assertArrayNotHasKey('options', $body);
    }

    public function testValidatedWrapsTheProviderClient(): void
    {
        self::assertInstanceOf(ValidatingClient::class, ClientFactory::validated(self::config('ollama', model: 'qwen3')));
    }

    public function testOllamaWithoutModelFails(): void
    {
        $this->expectExceptionObject(new ConfigException('ollama needs a model in semantic-sec.yaml'));

        ClientFactory::request(self::config('ollama'), 'p1', 'S', 'U', []);
    }

    public function testRealClientCarriesRetryMiddleware(): void
    {
        putenv('ANTHROPIC_API_KEY=sk-ant-secret-1');
        $config = self::config('anthropic');
        $client = ClientFactory::create($config, $this->handler());
        $this->queue = [new Response(429, ['Retry-After' => '3']), self::anthropicOk()];

        $response = $client->analyze(ClientFactory::request($config, 'p1', 'S', 'U', ['type' => 'object']))->wait();

        self::assertInstanceOf(LlmResponse::class, $response);
        self::assertSame(LlmOutcome::Ok, $response->outcome);
        self::assertCount(2, $this->sent);
        self::assertSame(3000, $this->sent[1]['delay']);
    }

    // Records each request and its Guzzle delay option instead of waiting.
    private function handler(): callable
    {
        return function (RequestInterface $request, array $options): PromiseInterface {
            $this->sent[] = ['request' => $request, 'delay' => $options['delay'] ?? null, 'options' => $options];

            return Create::promiseFor(array_shift($this->queue) ?? throw new \LogicException('no queued response'));
        };
    }

    private static function config(string $provider, ?string $model = null, ?string $apiKeyEnv = null, ?string $baseUrl = null): Config
    {
        return new Config('/nonexistent', $provider, $model, $apiKeyEnv, $baseUrl, 5, null, 8000, 3, Severity::High, Confidence::Medium, [], [], [], Config::DEFAULT_SENSITIVE_FIELDS, [], [], [], 'xhigh');
    }

    private static function anthropicOk(): Response
    {
        return new Response(200, [], json_encode([
            'model' => 'claude-opus-5-5',
            'stop_reason' => 'end_turn',
            'content' => [['type' => 'text', 'text' => '{"findings":[]}']],
            'usage' => ['input_tokens' => 10, 'output_tokens' => 5],
        ], JSON_THROW_ON_ERROR));
    }

    private static function openAiOk(): Response
    {
        return new Response(200, [], json_encode([
            'model' => 'openai/gpt-oss-120b',
            'choices' => [['finish_reason' => 'stop', 'message' => ['role' => 'assistant', 'content' => '{"findings":[]}', 'refusal' => null]]],
            'usage' => ['prompt_tokens' => 10, 'completion_tokens' => 5],
        ], JSON_THROW_ON_ERROR));
    }
}
