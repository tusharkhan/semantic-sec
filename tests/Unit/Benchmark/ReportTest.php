<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Benchmark;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\CompetitorConverter;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\CompetitorResult;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\DisguiseMap;
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

        foreach (['## Gate', '## Gate, failing findings only', '## Selection stage', '## Per app', '### app-a', '## Cases', '## Unattributed safe-code findings', '## Public routes', '## Run cost', '## Competitive check'] as $heading) {
            self::assertStringContainsString("\n$heading\n", $markdown);
        }
        self::assertStringContainsString('claude-opus-5-5', $markdown);
        self::assertStringContainsString('2026-11-01', $markdown);
        self::assertStringContainsString('$6.45', $markdown);
        self::assertStringContainsString('App\Policies\TransferPolicy::approve', $markdown);
        self::assertStringContainsString('never sent to the LLM', $markdown);
        self::assertStringContainsString('66.7% (2/3) FAIL', $markdown);
        self::assertStringContainsString('app/Http/Controllers/Safe/StrayController.php', $markdown);
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

    public function testEmptySetColumnShowsNotApplicable(): void
    {
        $score = Scorer::score([], ['app-a' => ScorerTest::analyze()['app-a']], [], [new \TusharKhan\SemanticSec\Tests\Support\Benchmark\PublicRoute('app-a', 'blind', 'GET /p', 'App\Http\Controllers\P::i')]);

        self::assertStringContainsString('| **Gate** | | **n/a** | **n/a** |', Report::markdown($score, self::meta()));
    }

    public function testStrictFoundLineOnlyWithPosthocAccepts(): void
    {
        $yaml = str_replace("      accept: [App\\Policies\\TransferPolicy::approve]\n", "      accept: [App\\Policies\\TransferPolicy::approve]\n      posthoc: true\n", ScorerTest::YAML);
        $analyze = ScorerTest::analyze();
        $analyze['app-a']['findings'] = [ScorerTest::finding('App\Http\Controllers\Vuln\ItemController::show'), ScorerTest::finding('App\Policies\TransferPolicy::approve')];
        $markdown = Report::markdown(Scorer::score(ExpectedCases::load($yaml), $analyze, ScorerTest::perfectMaps()), self::meta());

        self::assertStringContainsString('| Found, strict (no post-hoc accepts) | ≥ 70% | 50.0% (1/2) | 0.0% (0/1) | 33.3% (1/3) |', $markdown);
        self::assertStringContainsString('found (post-hoc accept)', $markdown);
        self::assertStringNotContainsString('strict (no post-hoc accepts)', Report::markdown(self::score(), self::meta()));
    }

    public function testCompetitiveCheckComparesBothToolsWithTheSameScorer(): void
    {
        $fixture = __DIR__.'/../../Fixtures/benchmark/competitor';
        $run = CompetitorConverter::fromMap(DisguiseMap::load($fixture.'/disguise-map.json'))
            ->convert((array) json_decode((string) file_get_contents($fixture.'/eval_results.json'), true));
        $analyze = ScorerTest::analyze();
        $analyze['app-a'] = $run->analyze['app-a'];
        $theirs = Scorer::score(ExpectedCases::load(ScorerTest::YAML), $analyze, [], ExpectedCases::publicRoutes(ScorerTest::YAML));
        $competitor = new CompetitorResult($theirs, $run, ['sha' => '0c6a49f1fa56a1d472575da86a94dbc1edb78eda', 'model' => 'claude-opus-5-5', 'pr' => 'tusharkhan/semantic-sec-bench#1', 'usage' => ['input' => 10, 'output' => 5, 'cacheRead' => 0, 'cacheWrite' => 0], 'cost' => 1.25, 'turns' => 12, 'capped' => false]);

        $markdown = Report::markdown(self::score(), self::meta(), $competitor);

        self::assertStringNotContainsString('_Not run yet._', $markdown);
        self::assertStringContainsString('`0c6a49f1fa56a1d472575da86a94dbc1edb78eda`', $markdown);
        self::assertStringContainsString('| all | Recall (found) | 100.0% (3/3) | 66.7% (2/3) |', $markdown);
        self::assertStringContainsString('| all | Precision | 50.0% (3/6) | 50.0% (2/4) |', $markdown);
        self::assertStringContainsString('| blind | Safe variants flagged | 100.0% (1/1) | 100.0% (1/1) |', $markdown);
        self::assertStringContainsString('| keyword:workflow_bypass | 1 |', $markdown);
        self::assertStringContainsString('| none | 1 |', $markdown);
        self::assertStringContainsString('outside the benchmark apps', $markdown);
        self::assertStringContainsString('`App\Http\Controllers\Safe\WithdrawalController::approve`', $markdown);
        foreach (['### Asymmetries', 'PR diff', 'whole project', '@semantic-sec-ignore', 'any category', 'disguised'] as $text) {
            self::assertStringContainsString($text, $markdown);
        }
        self::assertSame($markdown, Report::markdown(self::score(), self::meta(), $competitor));
    }

    public function testTunedOnCasesAreMarked(): void
    {
        $yaml = str_replace("  - id: policy-accept\n", "  - id: policy-accept\n    tuned_on: true\n", ScorerTest::YAML);
        $cases = ExpectedCases::load($yaml);
        self::assertSame(['policy-accept'], array_values(array_map(static fn ($c): string => $c->id, array_filter($cases, static fn ($c): bool => $c->tunedOn))));
        $markdown = Report::markdown(Scorer::score($cases, ScorerTest::analyze(), ScorerTest::perfectMaps()), self::meta());

        self::assertStringContainsString('| policy-accept | blind (tuned-on) |', $markdown);
        self::assertStringContainsString('Tuned-on cases: policy-accept.', $markdown);
        self::assertStringNotContainsString('tuned-on', Report::markdown(self::score(), self::meta()));
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
        $analyze['app-b']['findings'] = [ScorerTest::finding('App\Http\Controllers\Safe\StrayController::index')];
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
