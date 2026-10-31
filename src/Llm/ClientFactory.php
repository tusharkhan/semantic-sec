<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Llm;

use TusharKhan\SemanticSec\Config\Config;
use TusharKhan\SemanticSec\Config\ConfigException;
use TusharKhan\SemanticSec\Config\Defaults;
use TusharKhan\SemanticSec\Llm\Http\HttpClientFactory;
use TusharKhan\SemanticSec\Llm\Http\RetryMiddleware;
use TusharKhan\SemanticSec\Llm\Provider\AnthropicClient;
use TusharKhan\SemanticSec\Llm\Provider\OllamaClient;
use TusharKhan\SemanticSec\Llm\Provider\OpenAiClient;

/** Builds the configured provider client and the request defaults that go with it. */
final class ClientFactory
{
    private const KEY_ENVS = ['anthropic' => 'ANTHROPIC_API_KEY', 'openai' => 'OPENAI_API_KEY'];

    /** @param callable|null $handler Guzzle handler under the retry middleware; null is real cURL */
    public static function create(Config $c, ?callable $handler = null): ClientInterface
    {
        if ($c->baseUrl === '') {
            throw new ConfigException('base_url must not be empty');
        }
        $http = static fn () => HttpClientFactory::create($handler, [RetryMiddleware::create()]);

        return match ($c->provider) {
            'anthropic' => new AnthropicClient($http(), self::key($c), $c->baseUrl ?? AnthropicClient::DEFAULT_BASE_URL),
            // Config has no temperature or seed yet, so neither is sent.
            'openai' => new OpenAiClient($http(), self::key($c), $c->baseUrl ?? OpenAiClient::DEFAULT_BASE_URL, null, null),
            'ollama' => new OllamaClient($http(), $c->baseUrl ?? OllamaClient::DEFAULT_BASE_URL),
            default => throw new ConfigException("unknown provider {$c->provider}"),
        };
    }

    /** @param array<string, mixed> $schema */
    public static function request(Config $c, string $payloadId, string $system, string $user, array $schema): LlmRequest
    {
        return new LlmRequest($payloadId, $system, $user, $schema, self::model($c), effort: self::effort($c));
    }

    public static function model(Config $c): string
    {
        return $c->model ?? Defaults::model($c->provider) ?? throw new ConfigException("{$c->provider} needs a model in semantic-sec.yaml");
    }

    // Only Anthropic takes an effort level.
    public static function effort(Config $c): ?string
    {
        return $c->provider === 'anthropic' ? $c->effort : null;
    }

    private static function key(Config $c): string
    {
        $env = $c->apiKeyEnv ?? self::KEY_ENVS[$c->provider];
        $value = getenv($env);
        if (!is_string($value) || $value === '') {
            throw new ConfigException("{$env} is not set");
        }

        return $value;
    }
}
