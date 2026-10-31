<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support;

use TusharKhan\SemanticSec\Config\Defaults;

/** Provider profiles, the out-of-credit stop and the cassette choice for the live benchmark run (M6 Task 6 Step 6). */
final class LiveBenchmark
{
    public const CASSETTES = __DIR__.'/../Fixtures/cassettes';

    private const ANTHROPIC = 'anthropic/live-benchmark-laravel11.json';

    private const GROQ = 'openai/live-benchmark-laravel11-groq.json';

    /**
     * SEMANTIC_SEC_LIVE_PROVIDER: anthropic (default) or groq.
     *
     * @return array{name: string, provider: string, model: string, keyEnv: string, cassette: string, yaml: string}
     */
    public static function profile(string|false $env): array
    {
        $name = $env === false || $env === '' ? 'anthropic' : $env;
        [$provider, $model, $keyEnv, $cassette, $baseUrl] = match ($name) {
            'anthropic' => ['anthropic', Defaults::model('anthropic') ?? throw new \LogicException('no default anthropic model'), 'ANTHROPIC_API_KEY', self::ANTHROPIC, null],
            'groq' => ['openai', 'openai/gpt-oss-120b', 'GROQ_API_KEY', self::GROQ, 'https://api.groq.com/openai/v1'],
            default => throw new \InvalidArgumentException("SEMANTIC_SEC_LIVE_PROVIDER must be anthropic or groq, got {$name}"),
        };
        $yaml = "provider: {$provider}\nmodel: {$model}\n".($baseUrl === null ? '' : "base_url: {$baseUrl}\n")."api_key_env: {$keyEnv}\n";

        return ['name' => $name, 'provider' => $provider, 'model' => $model, 'keyEnv' => $keyEnv, 'cassette' => self::CASSETTES.'/'.$cassette, 'yaml' => $yaml];
    }

    // One line naming why the provider can't continue (credit, billing, quota); never echoes the provider's message.
    public static function stopReason(string $name, string $output): ?string
    {
        $why = null;
        foreach (explode("\n", $output) as $line) {
            if (preg_match('~^  payload \S+: .*\(HTTP (\d{3})\)(?::\s*(.*))?$~', $line, $m) !== 1) {
                continue;
            }
            $status = (int) $m[1];
            $why = match (true) {
                $status === 402, $status === 400 && preg_match('~credit|billing|balance|quota|payment~i', $m[2] ?? '') === 1 => "HTTP {$status}, credit or billing",
                $status === 403 => 'HTTP 403, key or billing access',
                $status === 429 => 'HTTP 429, quota or rate limit after retries',
                default => null,
            };
            if ($why !== null) {
                break;
            }
        }
        if ($why === null) {
            return null;
        }

        return "{$name} stopped: {$why}; ".($name === 'anthropic' ? 'rerun with SEMANTIC_SEC_LIVE_PROVIDER=groq' : 'wait for the Groq limit to reset');
    }

    // The recorded run to replay: Anthropic's when it exists, else Groq's, else null.
    public static function recordedCassette(string $dir = self::CASSETTES): ?string
    {
        foreach ([self::ANTHROPIC, self::GROQ] as $file) {
            if (is_file($dir.'/'.$file)) {
                return $dir.'/'.$file;
            }
        }

        return null;
    }
}
