<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Support;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Config\Defaults;
use TusharKhan\SemanticSec\Tests\Support\LiveBenchmark;

final class LiveBenchmarkTest extends TestCase
{
    public function testAnthropicIsTheDefault(): void
    {
        foreach ([false, '', 'anthropic'] as $env) {
            $p = LiveBenchmark::profile($env);
            self::assertSame(['anthropic', 'anthropic', Defaults::model('anthropic'), 'ANTHROPIC_API_KEY'], [$p['name'], $p['provider'], $p['model'], $p['keyEnv']]);
            self::assertStringEndsWith('/cassettes/anthropic/live-benchmark-laravel11.json', $p['cassette']);
        }
    }

    public function testGroqProfile(): void
    {
        $p = LiveBenchmark::profile('groq');

        self::assertSame(['groq', 'openai', 'openai/gpt-oss-120b', 'GROQ_API_KEY'], [$p['name'], $p['provider'], $p['model'], $p['keyEnv']]);
        self::assertStringEndsWith('/cassettes/openai/live-benchmark-laravel11-groq.json', $p['cassette']);
        self::assertSame("provider: openai\nmodel: openai/gpt-oss-120b\nbase_url: https://api.groq.com/openai/v1\napi_key_env: GROQ_API_KEY\n", $p['yaml']);
    }

    public function testUnknownProviderIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        LiveBenchmark::profile('gemini');
    }

    public function testStopReasonOnCreditAndQuota(): void
    {
        $cases = [
            '  payload 002-get-x-1: anthropic request failed (HTTP 400): Your credit balance is too low to access the Anthropic API.' => 'HTTP 400, credit or billing',
            '  payload 002-get-x-1: anthropic request failed (HTTP 402): payment required' => 'HTTP 402, credit or billing',
            '  payload 002-get-x-1: anthropic rejected the API key (HTTP 403)' => 'HTTP 403, key or billing access',
            '  payload 002-get-x-1: anthropic is unavailable (HTTP 429)' => 'HTTP 429, quota or rate limit after retries',
        ];
        foreach ($cases as $line => $why) {
            self::assertSame("anthropic stopped: {$why}; rerun with SEMANTIC_SEC_LIVE_PROVIDER=groq", LiveBenchmark::stopReason('anthropic', "Summary\n\nWarnings\n{$line}\n"));
        }
        self::assertSame('groq stopped: HTTP 429, quota or rate limit after retries; wait for the Groq limit to reset', LiveBenchmark::stopReason('groq', "Warnings\n  payload 1: openai is unavailable (HTTP 429)\n"));
    }

    public function testNoStopOnOtherFailures(): void
    {
        self::assertNull(LiveBenchmark::stopReason('anthropic', "Warnings\n  payload 1: anthropic request failed (HTTP 400): invalid schema\n  payload 2: anthropic is unavailable (HTTP 529)\n"));
        self::assertNull(LiveBenchmark::stopReason('anthropic', "Summary\n  ok 14\n"));
        self::assertNull(LiveBenchmark::stopReason('anthropic', '[HIGH] idor a.php:1 A::b — credit balance (HTTP 400) (high)'), 'only warning lines count');
    }

    public function testStopReasonNeverEchoesTheMessage(): void
    {
        $reason = LiveBenchmark::stopReason('anthropic', "  payload 1: anthropic request failed (HTTP 400): credit low, org org-SECRET123\n");

        self::assertNotNull($reason);
        self::assertStringNotContainsString('SECRET', $reason);
    }

    public function testRecordedCassettePrefersAnthropic(): void
    {
        $dir = sys_get_temp_dir().'/semsec-cassettes-'.bin2hex(random_bytes(4));
        mkdir($dir.'/anthropic', 0777, true);
        mkdir($dir.'/openai', 0777, true);
        try {
            self::assertNull(LiveBenchmark::recordedCassette($dir));
            touch($dir.'/openai/live-benchmark-laravel11-groq.json');
            self::assertSame($dir.'/openai/live-benchmark-laravel11-groq.json', LiveBenchmark::recordedCassette($dir));
            touch($dir.'/anthropic/live-benchmark-laravel11.json');
            self::assertSame($dir.'/anthropic/live-benchmark-laravel11.json', LiveBenchmark::recordedCassette($dir));
        } finally {
            exec('rm -rf '.escapeshellarg($dir));
        }
    }
}
