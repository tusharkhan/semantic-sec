<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Config;

use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;
use TusharKhan\SemanticSec\Analysis\Confidence;
use TusharKhan\SemanticSec\Analysis\Severity;

final class ConfigLoader
{
    private const KEYS = [
        'provider', 'model', 'api_key_env', 'base_url', 'concurrency', 'budget_tokens',
        'max_payload_tokens', 'max_depth', 'level', 'min_confidence', 'paths', 'exclude',
        'laravel', 'auth_helpers', 'auth_middleware', 'authorization_middleware', 'rulesets', 'effort',
    ];

    private const LARAVEL_KEYS = ['route_files', 'sensitive_fields'];

    private const RULESET_KEYS = ['name', 'prompt'];

    public function load(string $projectRoot, ?string $configPath = null): Config
    {
        $data = $this->read($projectRoot, $configPath);

        foreach (array_keys($data) as $key) {
            if (! in_array($key, self::KEYS, true)) {
                throw new ConfigException(sprintf('Unknown config key "%s".', $key));
            }
        }

        $laravel = $data['laravel'] ?? [];
        if (! is_array($laravel) || ($laravel !== [] && array_is_list($laravel))) {
            throw new ConfigException('Config key "laravel" must be a mapping.');
        }
        foreach (array_keys($laravel) as $key) {
            if (! in_array($key, self::LARAVEL_KEYS, true)) {
                throw new ConfigException(sprintf('Unknown config key "laravel.%s".', $key));
            }
        }

        $provider = $data['provider'] ?? 'anthropic';
        if (! is_string($provider) || ! in_array($provider, Config::PROVIDERS, true)) {
            throw new ConfigException('Config key "provider" must be one of: '.implode(', ', Config::PROVIDERS).'.');
        }

        $model = $this->nullableString($data['model'] ?? null, 'model');
        if ($model === null && $provider === 'ollama' && Defaults::model($provider) === null) {
            throw new ConfigException('ollama needs a model in semantic-sec.yaml');
        }

        $sensitive = array_values(array_unique([
            ...Config::DEFAULT_SENSITIVE_FIELDS,
            ...$this->stringList($laravel['sensitive_fields'] ?? [], 'laravel.sensitive_fields'),
        ]));

        return new Config(
            projectRoot: $projectRoot,
            provider: $provider,
            model: $model,
            apiKeyEnv: $this->nullableString($data['api_key_env'] ?? null, 'api_key_env'),
            baseUrl: $this->nullableString($data['base_url'] ?? null, 'base_url'),
            concurrency: $this->positiveInt($data['concurrency'] ?? 5, 'concurrency'),
            budgetTokens: isset($data['budget_tokens']) ? $this->positiveInt($data['budget_tokens'], 'budget_tokens') : null,
            maxPayloadTokens: $this->positiveInt($data['max_payload_tokens'] ?? 8000, 'max_payload_tokens'),
            maxDepth: $this->depth($data['max_depth'] ?? 3),
            level: $this->enum(Severity::class, $data['level'] ?? 'high', 'level'),
            minConfidence: $this->enum(Confidence::class, $data['min_confidence'] ?? 'medium', 'min_confidence'),
            paths: $this->stringList($data['paths'] ?? [], 'paths'),
            exclude: $this->stringList($data['exclude'] ?? [], 'exclude'),
            laravelRouteFiles: $this->stringList($laravel['route_files'] ?? [], 'laravel.route_files'),
            sensitiveFields: $sensitive,
            authHelpers: $this->stringList($data['auth_helpers'] ?? [], 'auth_helpers'),
            rulesets: $this->rulesets($data['rulesets'] ?? []),
            authMiddleware: $this->middlewareList($data['auth_middleware'] ?? [], 'auth_middleware'),
            effort: $this->effort($data['effort'] ?? 'high'),
            authorizationMiddleware: $this->middlewareList($data['authorization_middleware'] ?? [], 'authorization_middleware'),
        );
    }

    /** @return array<mixed> */
    private function read(string $projectRoot, ?string $configPath): array
    {
        if ($configPath === null) {
            $configPath = $projectRoot.'/semantic-sec.yaml';
            if (! is_file($configPath)) {
                return [];
            }
        } elseif (! is_file($configPath)) {
            throw new ConfigException(sprintf('Config file not found: %s', $configPath));
        }

        try {
            $data = Yaml::parseFile($configPath);
        } catch (ParseException $e) {
            throw new ConfigException(sprintf('Invalid YAML in %s: %s', $configPath, $e->getMessage()), 0, $e);
        }

        if ($data === null) {
            return [];
        }
        if (! is_array($data) || ($data !== [] && array_is_list($data))) {
            throw new ConfigException(sprintf('Config file %s must contain a mapping at the top level.', $configPath));
        }

        return $data;
    }

    private function nullableString(mixed $value, string $key): ?string
    {
        if ($value === null) {
            return null;
        }
        if (! is_string($value) || trim($value) === '') {
            throw new ConfigException(sprintf('Config key "%s" must be null or a non-empty string.', $key));
        }

        return $value;
    }

    private function positiveInt(mixed $value, string $key): int
    {
        if (! is_int($value) || $value < 1) {
            throw new ConfigException(sprintf('Config key "%s" must be a positive integer.', $key));
        }

        return $value;
    }

    private function depth(mixed $value): int
    {
        if (! is_int($value) || $value < 1 || $value > 5) {
            throw new ConfigException('Config key "max_depth" must be an integer between 1 and 5.');
        }

        return $value;
    }

    /**
     * @template T of \BackedEnum
     *
     * @param  class-string<T>  $enum
     * @return T
     */
    private function enum(string $enum, mixed $value, string $key): \BackedEnum
    {
        $case = is_string($value) ? $enum::tryFrom($value) : null;
        if ($case === null) {
            $allowed = implode(', ', array_map(static fn (\BackedEnum $c): string => (string) $c->value, $enum::cases()));

            throw new ConfigException(sprintf('Config key "%s" must be one of: %s.', $key, $allowed));
        }

        return $case;
    }

    /** @return list<string> */
    private function stringList(mixed $value, string $key, bool $nonEmpty = false): array
    {
        if (! is_array($value) || ! array_is_list($value)) {
            throw new ConfigException(sprintf('Config key "%s" must be a list of strings.', $key));
        }
        foreach ($value as $item) {
            if (! is_string($item) || ($nonEmpty && $item === '')) {
                throw new ConfigException(sprintf('Config key "%s" must be a list of %sstrings.', $key, $nonEmpty ? 'non-empty ' : ''));
            }
        }

        return $value;
    }

    private function effort(mixed $value): string
    {
        if (! is_string($value) || ! in_array($value, Config::EFFORTS, true)) {
            throw new ConfigException('Config key "effort" must be one of: '.implode(', ', Config::EFFORTS).'.');
        }

        return $value;
    }

    /** @return list<string> */
    private function middlewareList(mixed $value, string $key): array
    {
        $list = $this->stringList($value, $key, true);
        foreach ($list as $entry) {
            if (str_contains($entry, ':')) {
                throw new ConfigException(sprintf('Config key "%s" entry "%s" must be an alias or class name without ":" parameters.', $key, $entry));
            }
        }

        return $list;
    }

    /** @return list<CustomRuleset> */
    private function rulesets(mixed $value): array
    {
        if (! is_array($value) || ! array_is_list($value)) {
            throw new ConfigException('Config key "rulesets" must be a list.');
        }

        $out = [];
        foreach ($value as $index => $entry) {
            $where = sprintf('rulesets[%d]', $index);
            if (! is_array($entry)) {
                throw new ConfigException(sprintf('Config entry %s must be a mapping with "name" and "prompt".', $where));
            }
            foreach (array_keys($entry) as $key) {
                if (! in_array($key, self::RULESET_KEYS, true)) {
                    throw new ConfigException(sprintf('Unknown key "%s" in %s.', $key, $where));
                }
            }
            foreach (self::RULESET_KEYS as $key) {
                if (! isset($entry[$key]) || ! is_string($entry[$key]) || $entry[$key] === '') {
                    throw new ConfigException(sprintf('Config entry %s needs a non-empty string "%s".', $where, $key));
                }
            }
            $out[] = new CustomRuleset($entry['name'], $entry['prompt']);
        }

        return $out;
    }
}
