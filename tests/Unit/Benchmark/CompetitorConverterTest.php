<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Benchmark;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\BenchmarkCase;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\CompetitorConverter;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\CompetitorResult;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\CompetitorRun;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\DisguiseMap;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\ExpectedCases;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\PublicRoute;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\Scorer;

/** The competitor's eval_results.json (EvalResult.to_dict, claudecode/evals/run_eval.py) mapped onto our symbols and scored. */
final class CompetitorConverterTest extends TestCase
{
    private const FIXTURE = __DIR__.'/../../Fixtures/benchmark/competitor';

    private static ?CompetitorRun $run = null;

    public function testMapResolvesItsRootAndSymbols(): void
    {
        $map = DisguiseMap::load(self::FIXTURE.'/disguise-map.json');

        self::assertSame(realpath(self::FIXTURE.'/bench'), $map->root);
        self::assertSame(['app-a'], $map->apps());
        self::assertSame('App\Http\Controllers\Vuln\ItemController::show', $map->originalSymbol('app-a', 'App\Http\Controllers\Beta\itemcontroller::show'));
        self::assertSame('App\Models\Item::$fillable', $map->originalSymbol('app-a', 'App\Models\Item::$fillable'));
        self::assertSame('app/Http/Controllers/Safe/ItemController.php', $map->originalFile('app-a', 'app/Http/Controllers/Alpha/ItemController.php'));
        self::assertSame('GET /vuln/items/{id}', $map->originalRoute('app-a', 'GET /beta/items/{id}'));
    }

    public function testMethodLineMapsToTheOriginalSymbol(): void
    {
        $trace = self::competitorRun()->traces[0];

        self::assertSame('app-a', $trace['app']);
        self::assertSame('App\Http\Controllers\Beta\ItemController::show', $trace['disguisedSymbol']);
        self::assertSame('App\Http\Controllers\Vuln\ItemController::show', $trace['symbol']);
        self::assertSame('method', $trace['location']);
        self::assertSame(['idor', 'category-field'], [$trace['category'], $trace['rule']]);
        $finding = self::competitorRun()->analyze['app-a']['findings'][0];
        self::assertSame(['idor', 'high', 'app/Http/Controllers/Vuln/ItemController.php', 13, 'App\Http\Controllers\Vuln\ItemController::show'], [$finding['category'], $finding['confidence'], $finding['file'], $finding['line'], $finding['symbol']]);
    }

    public function testRouteFileLineMapsToTheRouteAction(): void
    {
        $trace = self::competitorRun()->traces[2];

        self::assertSame('route', $trace['location']);
        self::assertSame('App\Http\Controllers\Safe\WithdrawalController::approve', $trace['symbol']);
        self::assertSame(['workflow_bypass', 'keyword:workflow_bypass'], [$trace['category'], $trace['rule']]);
        self::assertSame('medium', self::competitorRun()->analyze['app-a']['findings'][2]['confidence']);
    }

    public function testPropertyLineAndOutsideFilesAndAbsolutePaths(): void
    {
        $run = self::competitorRun();

        self::assertSame(['App\Models\Item::$fillable', 'property'], [$run->traces[3]['symbol'], $run->traces[3]['location']]);
        self::assertNull($run->traces[4]['app']);
        self::assertSame('outside the benchmark apps', $run->traces[4]['location']);
        self::assertSame(1, $run->unmapped());
        self::assertCount(5, $run->analyze['app-a']['findings']);
        self::assertSame(6, $run->meta['findings_count']);
        self::assertTrue($run->meta['success']);

        $absolute = self::converter()->convert(['success' => true, 'full_findings' => [
            ['file' => '/root/code/audit/tusharkhan_semantic-sec-bench_pr1_1730000000/app-a/app/Http/Controllers/Beta/ItemController.php', 'line' => '11', 'category' => 'idor', 'confidence' => 0.8],
            ['file' => 'app-a/routes/web.php', 'line' => 3, 'category' => 'idor'],
        ]]);
        self::assertSame('App\Http\Controllers\Vuln\ItemController::show', $absolute->traces[0]['symbol']);
        self::assertSame(['', 'no route at that line'], [$absolute->traces[1]['symbol'], $absolute->traces[1]['location']]);
    }

    public function testRawAuditOutputAndFailedRuns(): void
    {
        $raw = self::converter()->convert(['findings' => [['file' => 'app-a/app/Policies/TransferPolicy.php', 'line' => 12, 'category' => 'idor', 'severity' => 'LOW']]]);

        self::assertSame('App\Policies\TransferPolicy::approve', $raw->traces[0]['symbol']);
        self::assertSame('low', $raw->analyze['app-a']['findings'][0]['confidence']);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('competitor run failed: Repository setup failed');
        self::converter()->convert(['success' => false, 'error_message' => 'Repository setup failed: x', 'full_findings' => null]);
    }

    public function testScoredByTheSameScorer(): void
    {
        $cases = array_values(array_filter(ExpectedCases::load(ScorerTest::YAML), static fn (BenchmarkCase $c): bool => $c->app === 'app-a'));
        $publics = array_values(array_filter(ExpectedCases::publicRoutes(ScorerTest::YAML), static fn (PublicRoute $p): bool => $p->app === 'app-a'));
        $score = Scorer::score($cases, self::competitorRun()->analyze, [], $publics);

        self::assertTrue($score->verdict('plain-idor')->found);
        self::assertFalse($score->verdict('plain-idor')->flagged);
        self::assertTrue($score->verdict('policy-accept')->found);
        self::assertTrue($score->verdict('policy-accept')->flagged);
        self::assertSame('workflow_bypass', $score->verdict('policy-accept')->flaggedBy['category'] ?? null);
        self::assertSame(1, $score->counts()->publicViolations);
    }

    public function testMissingDisguisedAppIsAnError(): void
    {
        $map = DisguiseMap::fromArray(['version' => 1, 'root' => self::FIXTURE.'/bench', 'apps' => ['app-z' => ['classes' => [], 'files' => [], 'routes' => []]]], self::FIXTURE);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('disguised app missing: '.realpath(self::FIXTURE.'/bench').'/app-z');

        CompetitorConverter::fromMap($map);
    }

    public function testClaudeCodeResultWrapperIsAFallbackInput(): void
    {
        $inner = json_encode(['findings' => [['file' => 'app-a/app/Http/Controllers/Beta/ItemController.php', 'line' => 12, 'category' => 'idor', 'confidence' => 0.9]], 'analysis_summary' => []]);
        $run = self::converter()->convert(['type' => 'result', 'subtype' => 'success', 'result' => "Here it is:\n```json\n{$inner}\n```"]);

        self::assertSame('App\Http\Controllers\Vuln\ItemController::show', $run->traces[0]['symbol']);
        self::assertSame([], self::converter()->convert(['type' => 'result', 'result' => 'no json here'])->traces);
    }

    public function testRunMetaSumsEveryClaudeCall(): void
    {
        $dir = sys_get_temp_dir().'/semsec-meta-'.bin2hex(random_bytes(4));
        mkdir($dir);
        file_put_contents($dir.'/run-meta.json', json_encode(['sha' => 'abc', 'model' => 'claude-opus-5-5']));
        $call = ['type' => 'result', 'subtype' => 'success', 'is_error' => false, 'num_turns' => 9, 'total_cost_usd' => 1.5, 'usage' => ['input_tokens' => 100, 'cache_creation_input_tokens' => 2000, 'cache_read_input_tokens' => 30000, 'output_tokens' => 400]];
        file_put_contents($dir.'/claude-call-1.json', json_encode($call));
        file_put_contents($dir.'/claude-call-2.json', json_encode([...$call, 'subtype' => 'error_max_turns']));

        try {
            $meta = CompetitorResult::readMeta($dir);
        } finally {
            exec('rm -rf '.escapeshellarg($dir));
        }

        self::assertSame('abc', $meta['sha']);
        self::assertSame(['input' => 200, 'output' => 800, 'cacheRead' => 60000, 'cacheWrite' => 4000], $meta['usage']);
        self::assertSame([3.0, 18, 2, true], [$meta['cost'], $meta['turns'], $meta['calls'], $meta['capped']]);
        self::assertSame([], CompetitorResult::readMeta(self::FIXTURE.'/none'));
    }

    private static function converter(): CompetitorConverter
    {
        return CompetitorConverter::fromMap(DisguiseMap::load(self::FIXTURE.'/disguise-map.json'));
    }

    private static function competitorRun(): CompetitorRun
    {
        return self::$run ??= self::converter()->convert((array) json_decode((string) file_get_contents(self::FIXTURE.'/eval_results.json'), true));
    }
}
