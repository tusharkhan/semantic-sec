<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Benchmark;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\ExpectedCases;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\Report;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\Score;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\Scorer;

/** Pins the rendered benchmark report; regenerate with UPDATE_SNAPSHOTS=1. */
final class ReportTest extends TestCase
{
    private const SNAPSHOT = __DIR__.'/../../Fixtures/benchmark/report.md';

    public function testRendersDeterministically(): void
    {
        $markdown = Report::markdown(self::score(), self::meta());

        self::assertSame($markdown, Report::markdown(self::score(), self::meta()));
        if (getenv('UPDATE_SNAPSHOTS') === '1') {
            file_put_contents(self::SNAPSHOT, $markdown);
        }
        self::assertFileExists(self::SNAPSHOT, 'run with UPDATE_SNAPSHOTS=1 to create it');
        self::assertSame(file_get_contents(self::SNAPSHOT), $markdown);
    }

    public function testCarriesEverySection(): void
    {
        $markdown = Report::markdown(self::score(), self::meta());

        foreach (['## Gate', '## Gate, failing findings only', '## Selection stage', '## Per app', '### app-a', '## Cases', '## Public routes', '## Run cost', '## Competitive check'] as $heading) {
            self::assertStringContainsString("\n$heading\n", $markdown);
        }
        self::assertStringContainsString('claude-opus-5-5', $markdown);
        self::assertStringContainsString('2026-11-01', $markdown);
        self::assertStringContainsString('$6.45', $markdown);
        self::assertStringContainsString('App\Policies\TransferPolicy::approve', $markdown);
        self::assertStringContainsString('never sent to the LLM', $markdown);
    }

    public function testPipesInModelTextCannotBreakTables(): void
    {
        $analyze = ScorerTest::analyze();
        $finding = ScorerTest::finding('App\Http\Controllers\Vuln\ItemController::show');
        $finding['title'] = "Bad | title\nwith newline";
        $analyze['app-a']['findings'] = [$finding];
        $score = Scorer::score(ExpectedCases::load(ScorerTest::YAML), $analyze, ScorerTest::perfectMaps(), ExpectedCases::publicRoutes(ScorerTest::YAML));

        $markdown = Report::markdown($score, self::meta());

        self::assertStringContainsString('Bad \| title with newline', $markdown);
    }

    public function testCost(): void
    {
        self::assertEqualsWithDelta(6.45, Report::cost(['input' => 1_000_000, 'output' => 100_000, 'cacheRead' => 1_000_000, 'cacheWrite' => 50_000]), 1e-9);
        self::assertSame(0.0, Report::cost(['input' => 0, 'output' => 0, 'cacheRead' => 0, 'cacheWrite' => 0]));
    }

    private static function score(): Score
    {
        $analyze = ScorerTest::analyze();
        $analyze['app-a']['findings'] = [
            ScorerTest::finding('App\Http\Controllers\Vuln\ItemController::show'),
            ScorerTest::finding('App\Policies\TransferPolicy::approve', confidence: 'low'),
            ScorerTest::finding('App\Http\Controllers\Safe\WithdrawalController::approve', 'workflow_bypass', 'medium'),
            ScorerTest::finding('App\Http\Controllers\PostController::show', 'idor', 'low'),
        ];
        $analyze['app-b']['suppressed'] = [ScorerTest::finding('App\Http\Controllers\Vuln\SharedController::show')];
        $maps = ScorerTest::perfectMaps();
        $maps['app-a']['routes'][1]['checks'] = [['kind' => 'authentication', 'strength' => 'authentication']];
        $dryRuns = [
            'app-a' => ['candidates' => [
                ['route' => 'GET /vuln/items/{id}', 'categories' => ['idor']],
                ['route' => 'POST /safe/withdrawals/{withdrawal}/approve', 'categories' => ['idor', 'workflow_bypass']],
            ]],
            'app-b' => ['candidates' => [['route' => 'GET /vuln/shared/{id}', 'categories' => ['idor']]]],
        ];

        return Scorer::score(ExpectedCases::load(ScorerTest::YAML), $analyze, $maps, ExpectedCases::publicRoutes(ScorerTest::YAML), $dryRuns);
    }

    /** @return array<string, mixed> */
    private static function meta(): array
    {
        return [
            'mode' => 'replay',
            'date' => '2026-11-01',
            'models' => ['claude-opus-5-5'],
            'promptVersion' => '2',
            'requests' => 7,
            'usage' => ['input' => 1_000_000, 'output' => 100_000, 'cacheRead' => 1_000_000, 'cacheWrite' => 50_000],
        ];
    }
}
