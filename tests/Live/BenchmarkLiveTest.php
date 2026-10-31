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
use TusharKhan\SemanticSec\Tests\Support\LiveBenchmark;

/**
 * `analyze` over a scratch copy of laravel11-app against a live provider (M6 Task 6 Step 6).
 * Runs only with SEMANTIC_SEC_LIVE=1; records a body-matched cassette with SEMANTIC_SEC_RECORD=1.
 * SEMANTIC_SEC_LIVE_PROVIDER=anthropic (default) or groq. Prints no key.
 */
final class BenchmarkLiveTest extends TestCase
{
    // Worst-case reservations for the 14 payloads total ~531k tokens; SEMANTIC_SEC_LIVE_BUDGET overrides.
    private const BUDGET = '600000';

    public function testAnalyzeBenchmark(): void
    {
        if (getenv('SEMANTIC_SEC_LIVE') !== '1') {
            self::markTestSkipped('live test; set SEMANTIC_SEC_LIVE=1 to run it');
        }
        $profile = LiveBenchmark::profile(getenv('SEMANTIC_SEC_LIVE_PROVIDER'));
        require_once __DIR__.'/bootstrap-env.php';
        $key = getenv($profile['keyEnv']);
        if (!is_string($key) || $key === '') {
            self::markTestSkipped($profile['keyEnv'].' is not set');
        }

        $base = sys_get_temp_dir().'/semsec-live-bench-'.bin2hex(random_bytes(4));
        mkdir($base, 0777, true);
        exec('cp -R '.escapeshellarg(BenchmarkCorpus::root().'/laravel11-app').' '.escapeshellarg($base.'/app'), $out, $code);
        self::assertSame(0, $code);
        file_put_contents($base.'/app/semantic-sec.yaml', $profile['yaml']);

        $recording = getenv('SEMANTIC_SEC_RECORD') === '1';
        $handler = $recording
            ? new CassetteHandler(Cassette::load($profile['cassette']), 'record', secrets: [$key], match: 'body')
            : null;
        $budget = getenv('SEMANTIC_SEC_LIVE_BUDGET');
        try {
            $t = new CommandTester(new AnalyzeCommand(static fn (Config $c): ClientInterface => ClientFactory::create($c, $handler)));
            $exit = $t->execute([
                '--project-root' => $base.'/app',
                '--no-cache' => true,
                '--level' => 'low',
                '--min-confidence' => 'low',
                '--budget' => is_string($budget) && $budget !== '' ? $budget : self::BUDGET,
            ], ['capture_stderr_separately' => true]);
        } finally {
            exec('rm -rf '.escapeshellarg($base));
        }
        $display = $t->getDisplay().$t->getErrorOutput();

        // Checked before anything is printed.
        self::assertStringNotContainsString($key, $display, 'the key leaked into the output');
        $stop = LiveBenchmark::stopReason($profile['name'], $display);
        if ($stop !== null) {
            if ($recording && is_file($profile['cassette'])) {
                unlink($profile['cassette']);
            }
            self::fail($stop);
        }

        fwrite(STDOUT, "\nanalyze provider={$profile['name']} model={$profile['model']} exit={$exit}\n".$display);
        self::assertNotSame(2, $exit, $t->getErrorOutput());
        self::assertMatchesRegularExpression('~unsent\s+0\b~', $t->getDisplay(), 'every payload was sent; raise SEMANTIC_SEC_LIVE_BUDGET otherwise');
    }
}
