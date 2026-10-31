<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Live;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Tester\CommandTester;
use TusharKhan\SemanticSec\Config\Config;
use TusharKhan\SemanticSec\Console\Commands\AnalyzeCommand;
use TusharKhan\SemanticSec\Llm\ClientFactory;
use TusharKhan\SemanticSec\Llm\ClientInterface;
use TusharKhan\SemanticSec\Llm\Http\Cassette;
use TusharKhan\SemanticSec\Llm\Http\CassetteHandler;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;

/**
 * `analyze` over a scratch copy of laravel11-app against the live Anthropic API (M6 Task 6 Step 6).
 * Runs only with SEMANTIC_SEC_LIVE=1; records a body-matched cassette with SEMANTIC_SEC_RECORD=1. Prints no key.
 */
final class BenchmarkLiveTest extends TestCase
{
    private const CASSETTE = __DIR__.'/../Fixtures/cassettes/anthropic/live-benchmark-laravel11.json';

    // Caps the cost: about 14 requests fit well inside it; SEMANTIC_SEC_LIVE_BUDGET overrides.
    private const BUDGET = '400000';

    public function testAnalyzeBenchmark(): void
    {
        if (getenv('SEMANTIC_SEC_LIVE') !== '1') {
            self::markTestSkipped('live test; set SEMANTIC_SEC_LIVE=1 to run it');
        }
        require_once __DIR__.'/bootstrap-env.php';
        $key = getenv('ANTHROPIC_API_KEY');
        if (!is_string($key) || $key === '') {
            self::markTestSkipped('ANTHROPIC_API_KEY is not set');
        }

        $base = sys_get_temp_dir().'/semsec-live-bench-'.bin2hex(random_bytes(4));
        mkdir($base, 0777, true);
        exec('cp -R '.escapeshellarg(BenchmarkCorpus::root().'/laravel11-app').' '.escapeshellarg($base.'/app'), $out, $code);
        self::assertSame(0, $code);

        $handler = getenv('SEMANTIC_SEC_RECORD') === '1'
            ? new CassetteHandler(Cassette::load(self::CASSETTE), 'record', secrets: [$key], match: 'body')
            : null;
        $budget = getenv('SEMANTIC_SEC_LIVE_BUDGET');
        try {
            $t = new CommandTester(new AnalyzeCommand(static fn (Config $c): ClientInterface => ClientFactory::create($c, $handler)));
            $exit = $t->execute([
                '--project-root' => $base.'/app',
                '--provider' => 'anthropic',
                '--no-cache' => true,
                '--level' => 'low',
                '--min-confidence' => 'low',
                '--budget' => is_string($budget) && $budget !== '' ? $budget : self::BUDGET,
            ], ['capture_stderr_separately' => true]);
        } finally {
            exec('rm -rf '.escapeshellarg($base));
        }

        fwrite(STDOUT, "\nanalyze exit={$exit}\n".$t->getDisplay().$t->getErrorOutput());
        self::assertStringNotContainsString($key, $t->getDisplay().$t->getErrorOutput());
        self::assertNotSame(2, $exit, $t->getErrorOutput());
        self::assertMatchesRegularExpression('~unsent\s+0\b~', $t->getDisplay(), 'every payload was sent; raise SEMANTIC_SEC_LIVE_BUDGET otherwise');
    }
}
