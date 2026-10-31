<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Config;

use TusharKhan\SemanticSec\Analysis\Confidence;
use TusharKhan\SemanticSec\Analysis\Severity;

final readonly class Config
{
    public const DEFAULT_SENSITIVE_FIELDS = [
        'is_admin', 'role', 'role_id', 'admin', 'balance', 'credits', 'email_verified_at',
        'password', 'user_id', 'owner_id', 'team_id', 'tenant_id', 'status',
    ];

    public const EFFORTS = ['low', 'medium', 'high', 'xhigh', 'max'];

    public const PROVIDERS = ['openai', 'anthropic', 'ollama'];

    private const OVERRIDABLE = ['level', 'min_confidence', 'provider', 'model', 'concurrency', 'budget_tokens', 'paths'];

    /**
     * @param  list<string>  $paths
     * @param  list<string>  $exclude
     * @param  list<string>  $laravelRouteFiles
     * @param  list<string>  $sensitiveFields
     * @param  list<string>  $authHelpers
     * @param  list<CustomRuleset>  $rulesets
     * @param  list<string>  $authMiddleware
     * @param  list<string>  $authorizationMiddleware
     */
    public function __construct(
        public string $projectRoot,
        public string $provider,
        public ?string $model,
        public ?string $apiKeyEnv,
        public ?string $baseUrl,
        public int $concurrency,
        public ?int $budgetTokens,
        public int $maxPayloadTokens,
        public int $maxDepth,
        public Severity $level,
        public Confidence $minConfidence,
        public array $paths,
        public array $exclude,
        public array $laravelRouteFiles,
        public array $sensitiveFields,
        public array $authHelpers,
        public array $rulesets,
        public array $authMiddleware = [],
        public string $effort = 'high',
        public array $authorizationMiddleware = [],
    ) {
    }

    /**
     * A copy with run-time overrides (CLI options), validated like the config file; budget_tokens may be 0 or null.
     *
     * @param  array{level?: mixed, min_confidence?: mixed, provider?: mixed, model?: mixed, concurrency?: mixed, budget_tokens?: mixed, paths?: list<string>}  $overrides
     *
     * @throws ConfigException on an invalid value
     */
    public function with(array $overrides): self
    {
        $unknown = array_diff(array_keys($overrides), self::OVERRIDABLE);
        if ($unknown !== []) {
            throw new \InvalidArgumentException('Config cannot override: '.implode(', ', $unknown));
        }
        $provider = array_key_exists('provider', $overrides) ? self::provider($overrides['provider']) : $this->provider;
        $model = array_key_exists('model', $overrides) ? self::model($overrides['model']) : $this->model;
        if ($model === null && $provider === 'ollama' && Defaults::model($provider) === null) {
            throw new ConfigException('ollama needs a model in semantic-sec.yaml or --model');
        }

        return new self(
            projectRoot: $this->projectRoot,
            provider: $provider,
            model: $model,
            apiKeyEnv: $this->apiKeyEnv,
            baseUrl: $this->baseUrl,
            concurrency: array_key_exists('concurrency', $overrides) ? self::integer($overrides['concurrency'], 'concurrency', 1, 'a positive integer') : $this->concurrency,
            budgetTokens: array_key_exists('budget_tokens', $overrides) ? ($overrides['budget_tokens'] === null ? null : self::integer($overrides['budget_tokens'], 'budget_tokens', 0, 'an integer of 0 or more')) : $this->budgetTokens,
            maxPayloadTokens: $this->maxPayloadTokens,
            maxDepth: $this->maxDepth,
            level: array_key_exists('level', $overrides) ? self::enum(Severity::class, $overrides['level'], 'level') : $this->level,
            minConfidence: array_key_exists('min_confidence', $overrides) ? self::enum(Confidence::class, $overrides['min_confidence'], 'min_confidence') : $this->minConfidence,
            paths: $overrides['paths'] ?? $this->paths,
            exclude: $this->exclude,
            laravelRouteFiles: $this->laravelRouteFiles,
            sensitiveFields: $this->sensitiveFields,
            authHelpers: $this->authHelpers,
            rulesets: $this->rulesets,
            authMiddleware: $this->authMiddleware,
            effort: $this->effort,
            authorizationMiddleware: $this->authorizationMiddleware,
        );
    }

    private static function provider(mixed $value): string
    {
        if (! is_string($value) || ! in_array($value, self::PROVIDERS, true)) {
            throw new ConfigException('"provider" must be one of: '.implode(', ', self::PROVIDERS).'.');
        }

        return $value;
    }

    private static function model(mixed $value): ?string
    {
        if ($value !== null && (! is_string($value) || trim($value) === '')) {
            throw new ConfigException('"model" must be a non-empty string.');
        }

        return $value;
    }

    // An int, or a string of digits as the CLI passes it.
    private static function integer(mixed $value, string $key, int $min, string $what): int
    {
        if (is_string($value) && preg_match('/^-?\d{1,18}$/', $value) === 1) {
            $value = (int) $value;
        }
        if (! is_int($value) || $value < $min) {
            throw new ConfigException(sprintf('"%s" must be %s.', $key, $what));
        }

        return $value;
    }

    /**
     * @template T of \BackedEnum
     *
     * @param  class-string<T>  $enum
     * @return T
     */
    private static function enum(string $enum, mixed $value, string $key): \BackedEnum
    {
        $case = is_string($value) ? $enum::tryFrom($value) : null;
        if ($case === null) {
            $allowed = implode(', ', array_map(static fn (\BackedEnum $c): string => (string) $c->value, $enum::cases()));

            throw new ConfigException(sprintf('"%s" must be one of: %s.', $key, $allowed));
        }

        return $case;
    }
}
