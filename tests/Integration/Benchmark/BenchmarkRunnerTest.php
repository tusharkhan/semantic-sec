<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Integration\Benchmark;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Tester\CommandTester;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\BenchmarkCommand;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\Disguise;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\ExpectedCases;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\FakeAnthropicHandler;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\Runner;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\Scorer;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;

/** bin/benchmark's plumbing end to end on laravel10-app: fake-recorded cassette, replay, score, report. No network. */
final class BenchmarkRunnerTest extends TestCase
{
    private const APP = 'laravel10-app';

    private static string $dir = '';

    private string|false $savedKey = false;

    public static function setUpBeforeClass(): void
    {
        self::$dir = sys_get_temp_dir().'/semsec-bench-test-'.bin2hex(random_bytes(4));
        mkdir(self::$dir, 0o777, true);
    }

    public static function tearDownAfterClass(): void
    {
        exec('rm -rf '.escapeshellarg(self::$dir));
    }

    protected function setUp(): void
    {
        $this->savedKey = getenv(Runner::KEY_ENV);
        putenv(Runner::KEY_ENV.'=fake-key');
    }

    protected function tearDown(): void
    {
        putenv($this->savedKey === false ? Runner::KEY_ENV : Runner::KEY_ENV.'='.$this->savedKey);
    }

    public function testMissingReplayCassetteIsAClearError(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('replay cassette missing: '.self::$dir.'/none/benchmark-laravel10-app.json');

        (new Runner(self::$dir.'/none'))->run(self::APP, 'replay', null, 'fake-key');
    }

    public function testFakeRecordThenReplayScores(): void
    {
        $cases = array_values(array_filter(self::cases(), static fn ($c): bool => $c->app === self::APP));
        $runner = new Runner(self::$dir);
        $fake = new FakeAnthropicHandler($cases);
        $recorded = $runner->run(self::APP, 'record', $fake, 'fake-key');
        $cassette = (string) file_get_contents($runner->cassette(self::APP));

        self::assertGreaterThan(0, $fake->calls);
        self::assertSame($fake->calls, $recorded->requests);
        self::assertStringNotContainsString('fake-key', $cassette);
        self::assertSame(['claude-opus-5-5'], $recorded->models);
        self::assertSame(['input' => 1000 * $fake->calls, 'output' => 200 * $fake->calls, 'cacheRead' => 500 * $fake->calls, 'cacheWrite' => 0], $recorded->usage);

        $replayed = $runner->run(self::APP, 'replay', null, 'replay-key');
        self::assertSame($recorded->analyze['findings'], $replayed->analyze['findings']);

        $score = Scorer::score($cases, [self::APP => $replayed->analyze], [self::APP => $replayed->map], [], [self::APP => $replayed->dryRun]);
        $counts = $score->counts();
        self::assertSame([2, 2, 0, 0], [$counts->cases, $counts->found, $counts->flagged, $counts->mapMismatches]);
        self::assertSame([], $score->selectionMisses());
    }

    public function testStaleCassetteIsAnError(): void
    {
        $runner = new Runner(self::$dir.'/stale');
        mkdir(self::$dir.'/stale');
        file_put_contents($runner->cassette(self::APP), json_encode(['interactions' => []]));

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('the cassette is stale');

        $runner->run(self::APP, 'replay', null, 'replay-key');
    }

    #[Depends('testFakeRecordThenReplayScores')]
    public function testCommandReplaysScoresAndWritesTheReport(): void
    {
        $out = self::$dir.'/report.md';
        $tester = new CommandTester(new BenchmarkCommand());
        $exit = $tester->execute(['--app' => [self::APP], '--cassettes' => self::$dir, '--out' => $out]);

        self::assertSame(0, $exit, $tester->getDisplay());
        self::assertStringContainsString('all      PASS', $tester->getDisplay());
        self::assertStringContainsString('| idor-l10-resource | existing | laravel10-app | idor | found |', (string) file_get_contents($out));
        self::assertSame('fake-key', getenv(Runner::KEY_ENV));
    }

    #[Depends('testFakeRecordThenReplayScores')]
    public function testCommandScoresTheCompetitorOnTheDisguisedCopy(): void
    {
        $map = Disguise::run(BenchmarkCorpus::root(), self::$dir.'/m8comp/bench', apps: [self::APP]);
        Disguise::writeMap($map, self::$dir.'/m8comp/disguise-map.json');
        $vulnerable = (string) array_search('app/Http/Controllers/Vuln/ReportController.php', $map['apps'][self::APP]['files'], true);
        $safe = (string) array_search('app/Http/Controllers/Safe/NoteController.php', $map['apps'][self::APP]['files'], true);
        $findings = [
            ['file' => self::APP.'/'.$vulnerable, 'line' => 18, 'severity' => 'HIGH', 'category' => 'authorization_bypass', 'description' => "Any user can read another user's report", 'confidence' => 0.9],
            ['file' => self::APP.'/'.$safe, 'line' => 34, 'severity' => 'MEDIUM', 'category' => 'idor', 'description' => 'Note read by id', 'confidence' => 0.8],
        ];
        file_put_contents(self::$dir.'/m8comp/eval_results.json', json_encode(['repo_name' => 'o/r', 'pr_number' => 1, 'success' => true, 'runtime_seconds' => 1.0, 'findings_count' => 2, 'detected_vulnerabilities' => true, 'error_message' => '', 'findings_summary' => [], 'full_findings' => $findings]));
        file_put_contents(self::$dir.'/m8comp/run-meta.json', json_encode(['sha' => 'abc123', 'model' => 'claude-opus-5-5', 'pr' => 'o/r#1']));

        $out = self::$dir.'/competitive.md';
        $tester = new CommandTester(new BenchmarkCommand());
        $exit = $tester->execute(['--app' => [self::APP], '--cassettes' => self::$dir, '--out' => $out, '--competitor' => self::$dir.'/m8comp/eval_results.json', '--disguise-map' => self::$dir.'/m8comp/disguise-map.json']);
        $report = (string) file_get_contents($out);

        self::assertSame(0, $exit, $tester->getDisplay());
        self::assertStringContainsString('competitor existing  recall 1/2  safe flagged 1/2', $tester->getDisplay());
        self::assertStringContainsString('| existing | Recall (found) | 100.0% (2/2) | 50.0% (1/2) |', $report);
        self::assertStringContainsString('`abc123`', $report);
        self::assertStringContainsString('`App\Http\Controllers\Vuln\ReportController::show`', $report);
    }

    public function testCommandRefusesMissingCassettesAndBadOptions(): void
    {
        $tester = new CommandTester(new BenchmarkCommand());

        self::assertSame(2, $tester->execute(['--cassettes' => self::$dir.'/empty', '--out' => self::$dir.'/x.md']));
        self::assertStringContainsString('replay cassettes missing:', $tester->getDisplay());
        self::assertStringContainsString('benchmark-laravel12-app.json', $tester->getDisplay());
        self::assertFileDoesNotExist(self::$dir.'/x.md');

        self::assertSame(2, $tester->execute(['--set' => 'secret']));
        self::assertSame(2, $tester->execute(['--app' => ['laravel9-app']]));
        self::assertSame(2, $tester->execute(['--competitor' => 'eval_results.json']));
        self::assertStringContainsString('--competitor needs --disguise-map', $tester->getDisplay());
        self::assertSame(2, $tester->execute(['--competitor' => self::$dir.'/none.json', '--disguise-map' => self::$dir.'/none-map.json', '--app' => [self::APP], '--cassettes' => self::$dir]));
        self::assertStringContainsString('cannot read', $tester->getDisplay());
    }

    public function testLiveRunsDefaultToABudgetCap(): void
    {
        self::assertSame('300000', BenchmarkCommand::budget(null, true));
        self::assertSame('5000', BenchmarkCommand::budget('5000', true));
        self::assertNull(BenchmarkCommand::budget(null, false));
    }

    /** @return list<\TusharKhan\SemanticSec\Tests\Support\Benchmark\BenchmarkCase> */
    private static function cases(): array
    {
        return ExpectedCases::load((string) file_get_contents(BenchmarkCorpus::root().'/expected.yaml'));
    }
}
