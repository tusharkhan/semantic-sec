<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Benchmark;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\BenchmarkCase;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\Counts;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\ExpectedCases;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\Gate;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\PublicRoute;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\Score;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\Scorer;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\Variant;

final class ScorerTest extends TestCase
{
    public const YAML = <<<'YAML'
version: 1
cases:
  - id: plain-idor
    app: app-a
    set: existing
    category: idor
    description: "Raw id lookup."
    vulnerable:
      route: GET /vuln/items/{id}
      symbol: App\Http\Controllers\Vuln\ItemController::show
      line: 12
      map: [authentication]
    safe:
      route: GET /safe/items/{id}
      symbol: App\Http\Controllers\Safe\ItemController::show
      map: [authentication, query_scope]
      candidate: false
  - id: policy-accept
    app: app-a
    set: blind
    category: idor
    description: "Policy compares the wrong column."
    vulnerable:
      route: POST /vuln/transfers/{transfer}/approve
      symbol: App\Http\Controllers\Vuln\TransferController::approve
      line: 16
      map: [authentication, controller_ability]
      accept: [App\Policies\TransferPolicy::approve]
    safe:
      route: POST /safe/withdrawals/{withdrawal}/approve
      symbol: App\Http\Controllers\Safe\WithdrawalController::approve
      map: [authentication, controller_ability]
      candidate: false
  - id: suppressed-idor
    app: app-b
    set: existing
    category: idor
    description: "Suppressed raw id lookup."
    vulnerable:
      route: GET /vuln/shared/{id}
      symbol: App\Http\Controllers\Vuln\SharedController::show
      line: 15
      map: [authentication]
      suppressed: true
    safe:
      route: GET /safe/shared/{id}
      symbol: App\Http\Controllers\Safe\SharedController::show
      map: [authentication, query_scope]
      candidate: false
public_routes:
  - app: app-a
    route: GET /posts/{post:slug}
    symbol: App\Http\Controllers\PostController::show
  - app: app-b
    set: blind
    route: GET /stores/{store:slug}
    symbol: App\Http\Controllers\StorefrontController::show
YAML;

    public function testLoadsCasesAndPublicRoutes(): void
    {
        $cases = ExpectedCases::load(self::YAML);

        self::assertSame(['plain-idor', 'policy-accept', 'suppressed-idor'], array_map(static fn (BenchmarkCase $c): string => $c->id, $cases));
        self::assertSame('blind', $cases[1]->set);
        self::assertSame('app/Http/Controllers/Vuln/ItemController.php', $cases[0]->vulnerable->file);
        self::assertSame(['App\Policies\TransferPolicy::approve'], $cases[1]->vulnerable->accept);
        self::assertTrue($cases[2]->vulnerable->suppressed);
        self::assertFalse($cases[0]->safe->candidate);
        self::assertSame(['authentication', 'query_scope'], $cases[0]->safe->map);

        $public = ExpectedCases::publicRoutes(self::YAML);
        self::assertSame(['existing', 'blind'], array_map(static fn (PublicRoute $p): string => $p->set, $public));
    }

    public function testLoadsTheRealCorpus(): void
    {
        $yaml = (string) file_get_contents(dirname(__DIR__, 3).'/benchmark/expected.yaml');
        $cases = ExpectedCases::load($yaml);

        self::assertCount(15, array_filter($cases, static fn (BenchmarkCase $c): bool => $c->set === 'existing'));
        self::assertCount(10, array_filter($cases, static fn (BenchmarkCase $c): bool => $c->set === 'blind'));
        self::assertCount(2, ExpectedCases::publicRoutes($yaml));
    }

    public function testFoundAtSymbol(): void
    {
        $score = $this->score(['app-a' => [self::finding('App\Http\Controllers\Vuln\ItemController::show')]]);
        $verdict = $score->verdict('plain-idor');

        self::assertTrue($verdict->found);
        self::assertSame('App\Http\Controllers\Vuln\ItemController::show', $verdict->foundBy['symbol'] ?? null);
        self::assertSame(1, $score->counts('existing')->found);
    }

    public function testWrongMethodSameFileIsMissed(): void
    {
        $score = $this->score(['app-a' => [
            self::finding('App\Http\Controllers\Vuln\ItemController::index', file: 'app/Http/Controllers/Vuln/ItemController.php'),
        ]]);

        self::assertFalse($score->verdict('plain-idor')->found);
        self::assertNull($score->verdict('plain-idor')->foundBy);
    }

    public function testWrongCategoryOrFileIsMissed(): void
    {
        $score = $this->score(['app-a' => [
            self::finding('App\Http\Controllers\Vuln\ItemController::show', 'mass_assignment'),
            self::finding('App\Http\Controllers\Vuln\ItemController::show', file: 'app/Http/Controllers/Other.php'),
        ]]);

        self::assertFalse($score->verdict('plain-idor')->found);
    }

    public function testAcceptedAlternateSymbol(): void
    {
        $score = $this->score(['app-a' => [self::finding('App\Policies\TransferPolicy::approve')]]);

        self::assertTrue($score->verdict('policy-accept')->found);
        self::assertSame('app/Policies/TransferPolicy.php', $score->verdict('policy-accept')->foundBy['file'] ?? null);
        self::assertFalse($this->score(['app-a' => [self::finding('App\Policies\TransferPolicy::view')]])->verdict('policy-accept')->found);
    }

    public function testSafeFlaggedByAnyCategory(): void
    {
        $score = $this->score(['app-a' => [self::finding('App\Http\Controllers\Safe\ItemController::show', 'workflow_bypass', 'low')]]);
        $verdict = $score->verdict('plain-idor');

        self::assertTrue($verdict->flagged);
        self::assertSame('workflow_bypass', $verdict->flaggedBy['category'] ?? null);
        self::assertFalse($verdict->flaggedFailing);
        self::assertSame(1, $score->counts('existing')->flagged);
        self::assertSame(0, $score->counts('existing', failingOnly: true)->flagged);
    }

    public function testSuppressedCase(): void
    {
        $suppressedVuln = self::finding('App\Http\Controllers\Vuln\SharedController::show');
        $suppressedSafe = self::finding('App\Http\Controllers\Safe\SharedController::show');
        $score = $this->score([], ['app-b' => [$suppressedVuln, $suppressedSafe]]);
        $verdict = $score->verdict('suppressed-idor');

        self::assertTrue($verdict->found);
        self::assertSame('suppressed', $verdict->foundBy['list'] ?? null);
        self::assertFalse($verdict->flagged);

        $other = $this->score([], ['app-a' => [self::finding('App\Http\Controllers\Vuln\ItemController::show')]]);
        self::assertFalse($other->verdict('plain-idor')->found);
    }

    public function testPublicRouteViolation(): void
    {
        $score = $this->score(['app-b' => [self::finding('App\Http\Controllers\StorefrontController::show', 'idor', 'low')]]);

        self::assertSame(0, $score->counts('existing')->publicViolations);
        self::assertSame(1, $score->counts('blind')->publicViolations);
        self::assertSame(0, $score->counts('blind', failingOnly: true)->publicViolations);
        self::assertSame('App\Http\Controllers\StorefrontController::show', $score->publics[1]->by['symbol'] ?? null);
    }

    public function testMapMismatch(): void
    {
        $maps = self::perfectMaps();
        $maps['app-a']['routes'][1]['checks'][] = ['kind' => 'query_scope', 'strength' => 'none'];
        $maps['app-a']['routes'][1]['checks'][] = ['kind' => 'route_ability', 'strength' => 'authorization'];
        $maps['app-a']['routes'][1]['checks'][] = ['kind' => 'route_ability', 'strength' => 'authorization'];
        unset($maps['app-b']['routes'][0]);
        $maps['app-b']['routes'] = array_values($maps['app-b']['routes']);
        $score = Scorer::score(ExpectedCases::load(self::YAML), self::analyze(), $maps, ExpectedCases::publicRoutes(self::YAML));

        $safe = $score->verdict('plain-idor')->mapSafe;
        self::assertFalse($safe['ok']);
        self::assertSame(['authentication', 'query_scope', 'route_ability'], $safe['actual']);
        self::assertTrue($score->verdict('plain-idor')->mapVulnerable['ok']);
        self::assertFalse($score->verdict('suppressed-idor')->mapVulnerable['ok']);
        self::assertNull($score->verdict('suppressed-idor')->mapVulnerable['actual']);
        self::assertSame(2, $score->counts()->mapMismatches);
        self::assertSame(6, $score->counts()->mapVariants);
    }

    public function testSetsReportedSeparately(): void
    {
        $score = $this->score(['app-a' => [
            self::finding('App\Http\Controllers\Vuln\ItemController::show'),
            self::finding('App\Http\Controllers\Safe\WithdrawalController::approve', 'workflow_bypass'),
        ]]);

        $existing = $score->counts('existing');
        $blind = $score->counts('blind');
        $all = $score->counts();
        self::assertSame([2, 1, 0], [$existing->cases, $existing->found, $existing->flagged]);
        self::assertSame([1, 0, 1], [$blind->cases, $blind->found, $blind->flagged]);
        self::assertSame([3, 1, 1], [$all->cases, $all->found, $all->flagged]);
        self::assertSame(1, $score->counts(app: 'app-b')->cases);
        self::assertSame(['app-a', 'app-b'], $score->apps());
    }

    public function testFailingOnlyIgnoresLowConfidence(): void
    {
        $score = $this->score(['app-a' => [
            self::finding('App\Http\Controllers\Vuln\ItemController::show', confidence: 'low'),
            self::finding('App\Policies\TransferPolicy::approve', confidence: 'medium'),
        ]]);

        self::assertTrue($score->verdict('plain-idor')->found);
        self::assertFalse($score->verdict('plain-idor')->foundFailing);
        self::assertTrue($score->verdict('policy-accept')->foundFailing);
        self::assertSame(1, $score->counts(failingOnly: true)->found);
        self::assertSame(2, $score->counts()->found);
    }

    public function testFilteredFindingsStillCount(): void
    {
        $analyze = self::analyze();
        $analyze['app-a']['filtered'][] = self::finding('App\Http\Controllers\Vuln\ItemController::show');
        $score = Scorer::score(ExpectedCases::load(self::YAML), $analyze, self::perfectMaps(), ExpectedCases::publicRoutes(self::YAML));

        self::assertTrue($score->verdict('plain-idor')->found);
    }

    public function testSelectionStage(): void
    {
        $dryRuns = [
            'app-a' => ['candidates' => [
                ['route' => 'GET|HEAD /vuln/items/{id}', 'categories' => ['idor']],
                ['route' => 'POST /vuln/transfers/{transfer}/approve', 'categories' => ['workflow_bypass']],
                ['route' => 'POST /safe/withdrawals/{withdrawal}/approve', 'categories' => ['idor', 'workflow_bypass']],
            ]],
            'app-b' => ['candidates' => []],
        ];
        $score = Scorer::score(ExpectedCases::load(self::YAML), self::analyze(), self::perfectMaps(), ExpectedCases::publicRoutes(self::YAML), $dryRuns);

        self::assertTrue($score->verdict('plain-idor')->selectedVulnerable);
        self::assertFalse($score->verdict('plain-idor')->selectedSafe);
        self::assertFalse($score->verdict('policy-accept')->selectedVulnerable);
        self::assertSame(['idor', 'workflow_bypass'], $score->verdict('policy-accept')->safeCategories);
        self::assertSame(['policy-accept vulnerable', 'policy-accept safe', 'suppressed-idor vulnerable'], array_map(
            static fn (array $m): string => $m['case']->id.' '.$m['variant'],
            $score->selectionMisses(),
        ));
        self::assertNull($this->score([])->verdict('plain-idor')->selectedVulnerable);
    }

    public function testMissingAnalyzeOutputIsAnError(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('no analyze output for app-b');

        Scorer::score(ExpectedCases::load(self::YAML), ['app-a' => self::analyze()['app-a']], self::perfectMaps());
    }

    public function testGateThresholds(): void
    {
        $pass = Gate::evaluate(new Counts(cases: 10, found: 7, flagged: 1, publicRoutes: 2, publicViolations: 0, mapVariants: 20, mapMismatches: 0));
        self::assertSame([true, true, true, true, true], array_column($pass, 'pass'));
        self::assertSame(['found', 'flagged', 'unattributed', 'public', 'map'], array_column($pass, 'criterion'));
        self::assertTrue(Gate::verdict($pass));

        $fail = Gate::evaluate(new Counts(cases: 10, found: 6, flagged: 2, publicRoutes: 2, publicViolations: 1, mapVariants: 20, mapMismatches: 1, unattributed: 1));
        self::assertSame([false, false, false, false, false], array_column($fail, 'pass'));
        self::assertFalse(Gate::verdict($fail));
    }

    public function testEmptySliceIsNotAPass(): void
    {
        $empty = Gate::evaluate(new Counts());
        self::assertSame([null, null, null, null, null], array_column($empty, 'pass'));
        self::assertNull(Gate::verdict($empty));

        self::assertFalse(Gate::verdict(Gate::evaluate(new Counts(publicRoutes: 1, publicViolations: 1))));
        self::assertNull(Gate::verdict(Gate::evaluate(new Counts(publicRoutes: 1))));
    }

    public function testSafeFlaggedBySymbolWithParens(): void
    {
        $score = $this->score(['app-a' => [self::finding('App\Http\Controllers\Safe\ItemController::show()')]]);

        self::assertTrue($score->verdict('plain-idor')->flagged);
    }

    public function testSafeFlaggedByOtherCaseAndDoubledBackslashes(): void
    {
        $score = $this->score(['app-a' => [self::finding('\\app\\http\\controllers\\safe\\itemcontroller::SHOW')]]);

        self::assertTrue($score->verdict('plain-idor')->flagged);
    }

    public function testPublicRouteViolatedByDifferentCase(): void
    {
        $score = $this->score(['app-a' => [self::finding('app\http\controllers\postcontroller::SHOW', file: 'app/Http/Controllers/PostController.php')]]);

        self::assertSame(1, $score->counts('existing')->publicViolations);
    }

    public function testLowerCasedVulnerableSymbolIsFound(): void
    {
        $score = $this->score(['app-a' => [self::finding(strtolower('App\Http\Controllers\Vuln\ItemController::show'), file: 'app/Http/Controllers/Vuln/ItemController.php')]]);

        self::assertTrue($score->verdict('plain-idor')->found);
    }

    public function testPathFormsAreNormalised(): void
    {
        foreach (['app\Http\Controllers\Vuln\ItemController.php', '/app/Http/Controllers/Vuln/ItemController.php', './app/Http/Controllers/Vuln/ItemController.php'] as $file) {
            $score = $this->score(['app-a' => [self::finding('App\Http\Controllers\Vuln\ItemController::show', file: $file)]]);
            self::assertTrue($score->verdict('plain-idor')->found, $file);
        }
    }

    public function testSafeFlaggedByCounterpartOfVulnerableAcceptAndBySafeAccept(): void
    {
        $case = new BenchmarkCase(
            'svc',
            'app-b',
            'existing',
            'workflow_bypass',
            new Variant('POST /v', 'App\Http\Controllers\Vuln\OrderController::cancel', 'app/Http/Controllers/Vuln/OrderController.php', [], 5, false, ['App\Services\Vuln\OrderService::cancel', 'App\Services\OrderService::cancel']),
            new Variant('POST /s', 'App\Http\Controllers\Safe\OrderController::cancel', 'app/Http/Controllers/Safe/OrderController.php', [], null, false, ['App\Services\OrderWorkflow::cancel']),
        );
        $flag = static fn (string $symbol): bool => Scorer::score([$case], ['app-b' => ['findings' => [self::finding($symbol)]]], ['app-b' => []])->verdict('svc')->flagged;

        self::assertTrue($flag('App\Services\Safe\OrderService::cancel'));
        self::assertTrue($flag('App\Services\OrderWorkflow::cancel'));
        self::assertFalse($flag('App\Services\OrderService::cancel'));
    }

    public function testUnattributedSafeFindingsAreCounted(): void
    {
        $score = $this->score([
            'app-a' => [self::finding('App\Http\Controllers\Safe\ItemController::show')],
            'app-b' => [
                self::finding('App\Http\Controllers\Safe\OtherController::index', confidence: 'low'),
                self::finding('App\Models\Thing::scope', file: 'app/Http/Controllers/Safe/Helpers.php'),
                self::finding('App\Http\Controllers\Vuln\OtherController::index'),
            ],
        ]);

        self::assertSame(['app/Http/Controllers/Safe/OtherController.php', 'app/Http/Controllers/Safe/Helpers.php'], array_map(static fn (array $u): string => $u['finding']['file'], $score->unattributed));
        self::assertSame(2, $score->counts('existing')->unattributed);
        self::assertSame(1, $score->counts('existing', failingOnly: true)->unattributed);
        self::assertSame(0, $score->counts('blind')->unattributed);
        self::assertSame(2, $score->counts()->unattributed);
        self::assertFalse(Gate::verdict(Gate::evaluate($score->counts('existing'))));
    }

    public function testSafeBaselinedFindingFlags(): void
    {
        $analyze = self::analyze();
        $analyze['app-a']['baselined'][] = self::finding('App\Http\Controllers\Safe\ItemController::show');
        $score = Scorer::score(ExpectedCases::load(self::YAML), $analyze, self::perfectMaps(), ExpectedCases::publicRoutes(self::YAML));

        self::assertTrue($score->verdict('plain-idor')->flagged);
        self::assertFalse($score->verdict('plain-idor')->found);
    }

    public function testCasesSharingAnAcceptedSymbolAreRejected(): void
    {
        $yaml = str_replace('      suppressed: true', "      suppressed: true\n      accept: ['\\App\\Policies\\transferpolicy::approve()']", self::YAML);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('suppressed-idor and policy-accept both accept idor at app\policies\transferpolicy::approve');

        ExpectedCases::load($yaml);
    }

    public function testScorerRejectsHandBuiltCasesSharingAnAcceptedSymbol(): void
    {
        $make = static fn (string $id, string $symbol): BenchmarkCase => new BenchmarkCase(
            $id,
            'app-a',
            'existing',
            'idor',
            new Variant('GET /v/'.$id, $symbol, ExpectedCases::fileOf($symbol), [], 3, false, ['App\\Svc::x']),
            new Variant('GET /s/'.$id, 'App\\Http\\Controllers\\Safe\\A::m', 'app/Http/Controllers/Safe/A.php', []),
        );

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('c2 and c1 both accept idor at app\\svc::x');

        Scorer::score([$make('c1', 'App\\Http\\Controllers\\Vuln\\A::m'), $make('c2', 'App\\Http\\Controllers\\Vuln\\B::m')], self::analyze(), []);
    }

    public function testSharedAcceptAcrossCategoriesIsAllowed(): void
    {
        $yaml = str_replace('category: idor'."\n".'    description: "Suppressed', 'category: mass_assignment'."\n".'    description: "Suppressed', self::YAML);
        $yaml = str_replace('      suppressed: true', "      suppressed: true\n      accept: [App\\Policies\\TransferPolicy::approve]", $yaml);

        self::assertCount(3, ExpectedCases::load($yaml));
    }

    /**
     * @param array<string, list<array<string, mixed>>> $findings
     * @param array<string, list<array<string, mixed>>> $suppressed
     */
    private function score(array $findings, array $suppressed = []): Score
    {
        $analyze = self::analyze();
        foreach ($findings as $app => $list) {
            $analyze[$app]['findings'] = $list;
        }
        foreach ($suppressed as $app => $list) {
            $analyze[$app]['suppressed'] = $list;
        }

        return Scorer::score(ExpectedCases::load(self::YAML), $analyze, self::perfectMaps(), ExpectedCases::publicRoutes(self::YAML));
    }

    /** @return array<string, array<string, mixed>> */
    public static function analyze(): array
    {
        $empty = ['version' => 1, 'summary' => ['tokens' => 0], 'findings' => [], 'suppressed' => [], 'baselined' => [], 'filtered' => [], 'warnings' => []];

        return ['app-a' => $empty, 'app-b' => $empty];
    }

    /** @return array<string, mixed> */
    public static function finding(string $symbol, string $category = 'idor', string $confidence = 'high', ?string $file = null): array
    {
        $class = explode('::', $symbol)[0];

        return [
            'title' => 'Finding on '.$symbol,
            'category' => $category,
            'severity' => 'high',
            'confidence' => $confidence,
            'file' => $file ?? 'app/'.str_replace('\\', '/', substr($class, 4)).'.php',
            'line' => 10,
            'symbol' => $symbol,
        ];
    }

    // A map that matches every expected list exactly.
    /** @return array<string, array{routes: list<array<string, mixed>>}> */
    public static function perfectMaps(): array
    {
        $maps = ['app-a' => ['routes' => []], 'app-b' => ['routes' => []]];
        foreach (ExpectedCases::load(self::YAML) as $case) {
            foreach ([$case->vulnerable, $case->safe] as $variant) {
                [$method, $uri] = explode(' ', $variant->route, 2);
                $maps[$case->app]['routes'][] = [
                    'methods' => [$method],
                    'uri' => $uri,
                    'checks' => array_map(static fn (string $kind): array => ['kind' => $kind, 'strength' => $kind === 'authentication' ? 'authentication' : 'authorization'], $variant->map),
                ];
            }
        }

        return $maps;
    }
}
