<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Engine;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Analysis\Category;
use TusharKhan\SemanticSec\Analysis\Confidence;
use TusharKhan\SemanticSec\Analysis\Severity;
use TusharKhan\SemanticSec\Candidates\Candidate;
use TusharKhan\SemanticSec\Config\Config;
use TusharKhan\SemanticSec\Engine\AnalysisResult;
use TusharKhan\SemanticSec\Engine\Baseline;
use TusharKhan\SemanticSec\Engine\Engine;
use TusharKhan\SemanticSec\Engine\Fingerprinter;
use TusharKhan\SemanticSec\Engine\ResultCache;
use TusharKhan\SemanticSec\Engine\Vulnerability;
use TusharKhan\SemanticSec\Framework\Laravel\RouteAction;
use TusharKhan\SemanticSec\Framework\Laravel\RouteEntry;
use TusharKhan\SemanticSec\Llm\ClientInterface;
use TusharKhan\SemanticSec\Llm\FakeClient;
use TusharKhan\SemanticSec\Llm\GroundingChecker;
use TusharKhan\SemanticSec\Llm\LlmException;
use TusharKhan\SemanticSec\Llm\LlmOutcome;
use TusharKhan\SemanticSec\Llm\LlmResponse;
use TusharKhan\SemanticSec\Parsing\AstGenerator;
use TusharKhan\SemanticSec\Parsing\CallGraph\ExecutionPath;
use TusharKhan\SemanticSec\Parsing\CallGraph\PathNode;
use TusharKhan\SemanticSec\Parsing\ParseResult;
use TusharKhan\SemanticSec\Parsing\SourceFile;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTableBuilder;
use TusharKhan\SemanticSec\Payload\Payload;
use TusharKhan\SemanticSec\Tests\Unit\Llm\ResponseValidatorTest;

final class EngineTest extends TestCase
{
    private const POST = 'app/Http/Controllers/PostController.php';

    private const OTHER = 'app/Http/Controllers/OtherController.php';

    private const SHOW = 'App\Http\Controllers\PostController::show';

    private const DESTROY = 'App\Http\Controllers\PostController::destroy';

    private const OTHER_DESTROY = 'App\Http\Controllers\OtherController::destroy';

    private const MODEL = 'claude-test';

    private const SOURCE = <<<'PHP'
        <?php

        namespace App\Http\Controllers;

        class PostController
        {
            public function show(int $id)
            {
                return Post::findOrFail($id);
            }

            public function destroy(int $id)
            {
                // @semantic-sec-ignore idor: admins only
                Post::findOrFail($id)->delete();
                // @semantic-sec-ignore all
                Post::where('id', $id)->update([]);
                // @semantic-sec-ignore CWE-862: reviewed by security
                return Post::find($id);
            }

            // @semantic-sec-ignore sqli: wrong tool
            public function edit(int $id)
            {
                return Post::find($id);
            }
        }
        PHP;

    private string $base;

    private ParseResult $parsed;

    private SymbolTable $symbols;

    protected function setUp(): void
    {
        $this->base = sys_get_temp_dir().'/semsec-engine-'.bin2hex(random_bytes(4));
        mkdir($this->base.'/cache', 0777, true);
        $other = str_replace(['class PostController', '@semantic-sec-ignore'], ['class OtherController', 'note'], self::SOURCE);
        $files = [];
        foreach ([self::POST => self::SOURCE, self::OTHER => $other] as $path => $code) {
            $files[] = (new AstGenerator())->parse(new SourceFile($path, '/nonexistent/'.$path, $code));
        }
        $this->parsed = new ParseResult($files, []);
        $this->symbols = (new SymbolTableBuilder())->build($this->parsed);
    }

    protected function tearDown(): void
    {
        exec('rm -rf '.escapeshellarg($this->base));
    }

    public function testCacheHitSkipsClient(): void
    {
        $payload = $this->payload('p1', self::POST, self::SHOW, 7, 10);
        $this->cache()->put($payload, self::ok('p1', [ResponseValidatorTest::finding(self::finding(self::SHOW, 9))]));
        $client = new FakeClient([]);

        $result = $this->engine($client)->run([$payload], 1);

        self::assertSame([], $client->requests);
        self::assertCount(1, $result->findings);
        self::assertSame(1, $result->stats['cacheHits']);
        self::assertSame(0, $result->stats['sent']);
    }

    public function testTruncatedPayloadCapsConfidenceAtMedium(): void
    {
        $cut = $this->payload('p1', self::POST, self::SHOW, 7, 10, truncated: true);
        $whole = $this->payload('p2', self::POST, self::SHOW, 7, 10);
        $high = ResponseValidatorTest::finding(self::finding(self::SHOW, 9));
        $low = ResponseValidatorTest::finding([...self::finding(self::SHOW, 8), 'confidence' => 'low', 'category' => 'mass_assignment']);
        $client = new FakeClient(['p1' => self::ok('p1', [$high, $low]), 'p2' => self::ok('p2', [$high])]);

        $cutResult = $this->engine($client)->run([$cut], 1);
        $byCategory = [];
        foreach ($cutResult->findings as $f) {
            $byCategory[$f['vulnerability']->category->value] = $f['vulnerability']->confidence;
        }
        ksort($byCategory);
        self::assertSame(['idor' => Confidence::Medium, 'mass_assignment' => Confidence::Low], $byCategory, 'high is capped, low stays low');

        // Same text, so the cached answer comes back; uncapped this time because the payload is whole.
        $wholeResult = $this->engine($client)->run([$whole], 1);
        $idor = array_values(array_filter($wholeResult->findings, static fn (array $f): bool => $f['vulnerability']->category === Category::Idor));
        self::assertSame(Confidence::High, $idor[0]['vulnerability']->confidence);
    }

    public function testOkPutInCache(): void
    {
        $payload = $this->payload('p1', self::POST, self::SHOW, 7, 10);
        $client = new FakeClient(['p1' => self::ok('p1', [ResponseValidatorTest::finding(self::finding(self::SHOW, 9))])]);

        $result = $this->engine($client)->run([$payload], 1);

        self::assertCount(1, $client->requests);
        self::assertSame($payload->text(), $client->requests[0]->user);
        self::assertSame('SYSTEM PROMPT', $client->requests[0]->system);
        self::assertSame(self::MODEL, $client->requests[0]->model);
        self::assertSame(1, $result->stats['ok']);
        self::assertNotNull($this->cache()->get($payload), 'the Ok answer was cached');
    }

    public function testRefusedNotCached(): void
    {
        $payload = $this->payload('p1', self::POST, self::SHOW, 7, 10);
        $client = new FakeClient(['p1' => new LlmResponse('p1', LlmOutcome::Refused, null, 5, 0, self::MODEL, 'cyber')]);

        $result = $this->engine($client)->run([$payload], 1);

        self::assertSame(1, $result->stats['refused']);
        self::assertNull($this->cache()->get($payload));
        self::assertContains('payload p1: refused (cyber)', $result->warnings);
    }

    public function testDroppedFindingCounted(): void
    {
        $payload = $this->payload('p1', self::POST, self::SHOW, 7, 10);
        $client = new FakeClient(['p1' => self::ok('p1', [
            ResponseValidatorTest::finding(self::finding(self::SHOW, 9)),
            ResponseValidatorTest::finding([...self::finding(self::SHOW, 9), 'file' => 'app/Nope.php']),
            ResponseValidatorTest::finding([...self::finding(self::SHOW, 9), 'file' => 'app/Other.php']),
            ResponseValidatorTest::finding(self::finding(self::SHOW, 99)),
        ])]);

        $result = $this->engine($client)->run([$payload], 1);

        self::assertCount(1, $result->findings);
        self::assertSame(3, $result->stats['dropped']);
        self::assertContains('dropped 2 findings not grounded in the payload: file not in payload', $result->warnings);
        self::assertContains('dropped 1 finding not grounded in the payload: line not in payload', $result->warnings);
        self::assertSame([], array_filter($result->warnings, static fn (string $w): bool => str_contains($w, 'Nope')), 'no per-finding warning');
    }

    public function testSuppressedByCategoryAllAndCwe(): void
    {
        $payload = $this->payload('p1', self::POST, self::DESTROY, 12, 20, self::OTHER, self::OTHER_DESTROY);
        $client = new FakeClient(['p1' => self::ok('p1', [
            ResponseValidatorTest::finding(self::finding(self::DESTROY, 15)),
            ResponseValidatorTest::finding([...self::finding(self::DESTROY, 17), 'category' => 'mass_assignment']),
            ResponseValidatorTest::finding([...self::finding(self::DESTROY, 19), 'category' => 'missing_authorization']),
            ResponseValidatorTest::finding([...self::finding(self::DESTROY, 15), 'category' => 'workflow_bypass']),
            ResponseValidatorTest::finding([...self::finding(self::OTHER_DESTROY, 15), 'file' => self::OTHER]),
        ])]);

        $result = $this->engine($client)->run([$payload], 1);

        $suppressed = array_map(static fn (array $s): array => [$s['vulnerability']->line, $s['vulnerability']->category, $s['suppression']->commentLine], $result->suppressed);
        usort($suppressed, static fn (array $a, array $b): int => $a[0] <=> $b[0]);
        self::assertSame([[15, Category::Idor, 14], [17, Category::MassAssignment, 16], [19, Category::MissingAuthorization, 18]], $suppressed);
        $kept = array_map(static fn (array $f): string => $f['vulnerability']->file.':'.$f['vulnerability']->line.':'.$f['vulnerability']->category->value, $result->findings);
        sort($kept);
        self::assertSame([self::OTHER.':15:idor', self::POST.':15:workflow_bypass'], $kept, 'other category and other file are not covered');
    }

    public function testReasonlessSuppressionWarned(): void
    {
        $payload = $this->payload('p1', self::POST, self::DESTROY, 12, 20);
        $twin = $this->payload('p2', self::POST, self::DESTROY, 12, 20);
        $answer = [ResponseValidatorTest::finding([...self::finding(self::DESTROY, 17), 'category' => 'missing_authorization'])];
        $client = new FakeClient(['p1' => self::ok('p1', $answer), 'p2' => self::ok('p2', $answer)]);

        $result = $this->engine($client)->run([$payload, $twin], 1);

        self::assertCount(1, $result->suppressed);
        self::assertSame([], $result->findings);
        $reasonless = array_values(array_filter($result->warnings, static fn (string $w): bool => str_contains($w, 'without a reason')));
        self::assertSame([self::POST.':16: suppression without a reason honoured'], $reasonless);
        $invalid = array_values(array_filter($result->warnings, static fn (string $w): bool => str_contains($w, 'unknown category')));
        self::assertSame([self::POST.':22: unknown category "sqli"'], $invalid, 'invalid directives pass through once');
    }

    public function testDedupAcrossParts(): void
    {
        $one = $this->payload('p1', self::POST, self::SHOW, 7, 10, part: 1);
        $two = $this->payload('p2', self::POST, self::SHOW, 7, 10, part: 2);
        $client = new FakeClient([
            'p1' => self::ok('p1', [ResponseValidatorTest::finding([...self::finding(self::SHOW, 9), 'severity' => 'medium'])]),
            'p2' => self::ok('p2', [ResponseValidatorTest::finding([...self::finding(self::SHOW, 9), 'severity' => 'critical'])]),
        ]);

        $result = $this->engine($client)->run([$one, $two], 1);

        self::assertCount(1, $result->findings);
        self::assertSame(Severity::Critical, $result->findings[0]['vulnerability']->severity);
    }

    public function testUncoveredLineInSuppressedMethodIsReported(): void
    {
        $one = $this->payload('p1', self::POST, self::DESTROY, 12, 20);
        $two = $this->payload('p2', self::POST, self::DESTROY, 12, 20);
        $client = new FakeClient([
            'p1' => self::ok('p1', [ResponseValidatorTest::finding(self::finding(self::DESTROY, 15))]),
            'p2' => self::ok('p2', [ResponseValidatorTest::finding([...self::finding(self::DESTROY, 19), 'severity' => 'critical'])]),
        ]);

        $result = $this->engine($client)->run([$one, $two], 1);

        self::assertCount(1, $result->findings, 'L19 has no idor suppression');
        self::assertSame([19, Severity::Critical], [$result->findings[0]['vulnerability']->line, $result->findings[0]['vulnerability']->severity]);
        self::assertCount(1, $result->suppressed);
        self::assertSame([15, 14], [$result->suppressed[0]['vulnerability']->line, $result->suppressed[0]['suppression']->commentLine]);
    }

    public function testUncoveredLineInOneAnswerIsReported(): void
    {
        $payload = $this->payload('p1', self::POST, self::DESTROY, 12, 20);
        $client = new FakeClient(['p1' => self::ok('p1', [
            ResponseValidatorTest::finding(self::finding(self::DESTROY, 15)),
            ResponseValidatorTest::finding([...self::finding(self::DESTROY, 19), 'severity' => 'critical', 'title' => 'other statement']),
        ])]);

        $result = $this->engine($client)->run([$payload], 1);

        self::assertSame([19], array_map(static fn (array $f): int => $f['vulnerability']->line, $result->findings));
        self::assertSame([15], array_map(static fn (array $s): int => $s['vulnerability']->line, $result->suppressed));
    }

    public function testCoveredLineStaysSuppressedAcrossPayloads(): void
    {
        $one = $this->payload('p1', self::POST, self::DESTROY, 12, 20);
        $two = $this->payload('p2', self::POST, self::DESTROY, 12, 20);
        $answer = static fn (string $sev): array => [ResponseValidatorTest::finding([...self::finding(self::DESTROY, 15), 'severity' => $sev])];
        $client = new FakeClient(['p1' => self::ok('p1', $answer('medium')), 'p2' => self::ok('p2', $answer('critical'))]);

        $result = $this->engine($client)->run([$one, $two], 1);

        self::assertSame([], $result->findings);
        self::assertCount(1, $result->suppressed);
        self::assertSame(Severity::Critical, $result->suppressed[0]['vulnerability']->severity);
    }

    public function testDuplicatePayloadIdFailsFast(): void
    {
        $payload = $this->payload('p1', self::POST, self::SHOW, 7, 10);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('duplicate payload id p1');

        $this->engine(new FakeClient([]))->run([$payload, $this->payload('p1', self::POST, self::SHOW, 7, 9)], 1);
    }

    public function testBaselined(): void
    {
        $payload = $this->payload('p1', self::POST, self::SHOW, 7, 10);
        $fp = (new Fingerprinter($this->parsed, $this->symbols))->fingerprint(self::POST, self::SHOW, Category::Idor, $payload);
        $client = new FakeClient(['p1' => self::ok('p1', [ResponseValidatorTest::finding(self::finding(self::SHOW, 9))])]);

        $result = $this->engine($client, baseline: Baseline::of([$fp]))->run([$payload], 1);

        self::assertSame([], $result->findings);
        self::assertCount(1, $result->baselined);
        self::assertSame($fp, $result->baselined[0]->fingerprint);
    }

    public function testLevelFilterDropsBelow(): void
    {
        $payload = $this->payload('p1', self::POST, self::SHOW, 7, 10);
        $client = new FakeClient(['p1' => self::ok('p1', [
            ResponseValidatorTest::finding([...self::finding(self::SHOW, 9), 'severity' => 'low']),
            ResponseValidatorTest::finding([...self::finding(self::SHOW, 9), 'severity' => 'high', 'category' => 'missing_authorization']),
        ])]);

        $result = $this->engine($client, level: Severity::Medium)->run([$payload], 1);

        self::assertCount(1, $result->findings);
        self::assertSame(Severity::High, $result->findings[0]['vulnerability']->severity);
        self::assertSame(1, $result->stats['filtered']);
    }

    public function testFilteredFindingsKept(): void
    {
        $payload = $this->payload('p1', self::POST, self::SHOW, 7, 10);
        $client = new FakeClient(['p1' => self::ok('p1', [
            ResponseValidatorTest::finding([...self::finding(self::SHOW, 9), 'severity' => 'low']),
            ResponseValidatorTest::finding([...self::finding(self::SHOW, 9), 'severity' => 'medium', 'category' => 'missing_authorization']),
            ResponseValidatorTest::finding([...self::finding(self::SHOW, 9), 'severity' => 'critical', 'category' => 'mass_assignment']),
        ])]);

        $result = $this->engine($client, level: Severity::High)->run([$payload], 1);

        self::assertCount(1, $result->findings);
        self::assertCount(2, $result->filtered);
        self::assertSame(2, $result->stats['filtered']);
        $severities = array_map(static fn (Vulnerability $v): string => $v->severity->value, $result->filtered);
        sort($severities);
        self::assertSame(['low', 'medium'], $severities);
        self::assertNotSame('', $result->filtered[0]->fingerprint);
    }

    public function testLowConfidenceNotFailing(): void
    {
        $payload = $this->payload('p1', self::POST, self::SHOW, 7, 10);
        $client = new FakeClient(['p1' => self::ok('p1', [
            ResponseValidatorTest::finding([...self::finding(self::SHOW, 9), 'confidence' => 'low']),
            ResponseValidatorTest::finding([...self::finding(self::SHOW, 9), 'confidence' => 'medium', 'category' => 'missing_authorization']),
        ])]);

        $result = $this->engine($client, minConfidence: Confidence::Medium)->run([$payload], 1);

        $failing = [];
        foreach ($result->findings as $f) {
            $failing[$f['vulnerability']->confidence->value] = $f['failing'];
        }
        ksort($failing);
        self::assertSame(['low' => false, 'medium' => true], $failing);
    }

    public function testEmptyPayloadSkipped(): void
    {
        $empty = new Payload('p0', self::candidate(), "Route:\n  GET /x", "<untrusted_code>\n// source not available\n</untrusted_code>", 1, 1, false);
        $client = new FakeClient([]);

        $result = $this->engine($client)->run([$empty], 1);

        self::assertSame([], $client->requests);
        self::assertSame(1, $result->stats['skipped']);
        self::assertSame(0, $result->stats['sent']);
        self::assertContains('payload p0: no source code to send, skipped', $result->warnings);
    }

    public function testFailuresBecomeWarnings(): void
    {
        $payload = $this->payload('p1', self::POST, self::SHOW, 7, 10);
        $client = new FakeClient(['p1' => new LlmException('anthropic HTTP 500', 500, true, null, 40)]);

        $result = $this->engine($client)->run([$payload], 1);

        self::assertContains('payload p1: anthropic HTTP 500', $result->warnings);
        self::assertSame(1, $result->stats['failed']);
        self::assertSame(40, $result->stats['tokens']);
    }

    public function testStatsAddUp(): void
    {
        $show = static fn (): array => [ResponseValidatorTest::finding(self::finding(self::SHOW, 9))];
        $payloads = [
            new Payload('p0', self::candidate(), 'ctx', '<untrusted_code></untrusted_code>', 1, 1, false),
            $this->payload('hit', self::POST, self::SHOW, 7, 10),
            $this->payload('ok', self::POST, self::SHOW, 7, 9),
            $this->payload('refused', self::POST, self::SHOW, 7, 8),
            $this->payload('truncated', self::POST, self::SHOW, 8, 10),
            $this->payload('invalid', self::POST, self::SHOW, 9, 10),
            $this->payload('failed', self::POST, self::SHOW, 9, 9),
        ];
        $this->cache()->put($payloads[1], self::ok('hit', $show()));
        $client = new FakeClient([
            'ok' => self::ok('ok', [...$show(), ResponseValidatorTest::finding(self::finding(self::SHOW, 99))], 10, 5),
            'refused' => new LlmResponse('refused', LlmOutcome::Refused, null, 1, 2, self::MODEL),
            'truncated' => new LlmResponse('truncated', LlmOutcome::Truncated, null, 3, 4, self::MODEL),
            'invalid' => new LlmResponse('invalid', LlmOutcome::Invalid, null, 5, 6, self::MODEL),
            'failed' => new LlmException('timed out', null, true, null, 7),
        ]);

        $result = $this->engine($client)->run($payloads, 3);
        self::assertInstanceOf(AnalysisResult::class, $result);
        $s = $result->stats;

        self::assertSame(3, $s['candidates']);
        self::assertSame(7, $s['payloads']);
        self::assertSame($s['payloads'], $s['skipped'] + $s['unsent'] + $s['cacheHits'] + $s['sent']);
        self::assertSame([1, 0, 1, 5], [$s['skipped'], $s['unsent'], $s['cacheHits'], $s['sent']]);
        self::assertSame(0, $s['filtered']);
        self::assertSame($s['sent'], $s['ok'] + $s['refused'] + $s['truncated'] + $s['invalid'] + $s['failed']);
        self::assertSame([1, 1, 1, 1, 1], [$s['ok'], $s['refused'], $s['truncated'], $s['invalid'], $s['failed']]);
        self::assertSame(1, $s['dropped']);
        self::assertSame(15 + 3 + 7 + 11 + 7, $s['tokens']);
        self::assertFalse($s['budgetExceeded']);
        self::assertCount(1, $result->findings, 'the cache hit and the ok answer dedupe');
    }

    public function testBudgetStopCountsUnsent(): void
    {
        $payload = $this->payload('p1', self::POST, self::SHOW, 7, 10);
        $client = new FakeClient([]);

        $result = $this->engine($client, budget: 10)->run([$payload], 1);

        self::assertSame([], $client->requests);
        self::assertTrue($result->stats['budgetExceeded']);
        self::assertSame([0, 1], [$result->stats['skipped'], $result->stats['unsent']]);
        self::assertSame(1, $result->stats['payloads']);
        self::assertContains('1 payload not sent: token budget exhausted', $result->warnings);
    }

    public function testStatsAddUpWhenTheBudgetStopsDispatch(): void
    {
        $payloads = [
            new Payload('p0', self::candidate(), 'ctx', '<untrusted_code></untrusted_code>', 1, 1, false),
            $this->payload('hit', self::POST, self::SHOW, 7, 10),
            $this->payload('sent', self::POST, self::SHOW, 7, 9),
            $this->payload('late', self::POST, self::SHOW, 8, 10),
        ];
        $this->cache()->put($payloads[1], self::ok('hit', []));
        $client = new FakeClient(['sent' => self::ok('sent', [], 20000, 5), 'late' => self::ok('late', [])]);

        $s = $this->engine($client, budget: 40000)->run($payloads, 1)->stats;

        self::assertSame([1, 1, 1, 1], [$s['skipped'], $s['unsent'], $s['cacheHits'], $s['sent']]);
        self::assertSame($s['payloads'], $s['skipped'] + $s['unsent'] + $s['cacheHits'] + $s['sent']);
        self::assertTrue($s['budgetExceeded']);
    }

    public function testUnvalidatedOkIsTreatedAsInvalid(): void
    {
        $payload = $this->payload('p1', self::POST, self::SHOW, 7, 10);
        $client = new FakeClient(['p1' => new LlmResponse('p1', LlmOutcome::Ok, ['findings' => [['line' => 9]]], 1, 1, self::MODEL)]);

        $result = $this->engine($client)->run([$payload], 1);

        self::assertSame([0, 1], [$result->stats['ok'], $result->stats['invalid']]);
        self::assertSame([], $result->findings);
        self::assertNull($this->cache()->get($payload));
    }

    public function testBaselineSet(): void
    {
        self::assertFalse(Baseline::empty()->contains('a'));
        self::assertTrue(Baseline::of(['a', 'b'])->contains('b'));
        self::assertFalse(Baseline::of(['a'])->contains('c'));
    }

    private function engine(ClientInterface $client, ?Baseline $baseline = null, Severity $level = Severity::Low, Confidence $minConfidence = Confidence::Medium, ?int $budget = null): Engine
    {
        $config = new Config('/nonexistent', 'anthropic', self::MODEL, null, null, 5, $budget, 8000, 3, $level, $minConfidence, [], [], [], [], [], []);

        return new Engine($client, $this->cache(), new Fingerprinter($this->parsed, $this->symbols), new GroundingChecker($this->symbols), $this->parsed, $config, $baseline ?? Baseline::empty());
    }

    private function cache(): ResultCache
    {
        return new ResultCache($this->base.'/cache', 'anthropic', self::MODEL, [], true, systemPrompt: 'SYSTEM PROMPT');
    }

    // A payload showing lines from..to of one method, plus the same method of a second file when given.
    private function payload(string $id, string $file, string $symbol, int $from, int $to, ?string $file2 = null, ?string $symbol2 = null, int $part = 1, bool $truncated = false): Payload
    {
        $code = "<untrusted_code>\n".self::block($file, $symbol, $from, $to);
        if ($file2 !== null && $symbol2 !== null) {
            $code .= self::block($file2, $symbol2, $from, $to);
        }

        return new Payload($id, self::candidate(), "Route:\n  GET /posts/{id}", $code.'</untrusted_code>', $part, $part === 1 ? 1 : 2, $truncated);
    }

    private static function block(string $file, string $symbol, int $from, int $to): string
    {
        $lines = explode("\n", self::SOURCE);
        $out = "// FILE: {$file} :: {$symbol} (L{$from}-L{$to})\n";
        for ($n = $from; $n <= $to; $n++) {
            $out .= 'L'.$n.'| '.$lines[$n - 1]."\n";
        }

        return $out;
    }

    private static function candidate(): Candidate
    {
        $route = new RouteEntry(['GET'], '/posts/{id}', null, new RouteAction('App\Http\Controllers\PostController', 'show'), [], [], [], null, 'routes/web.php', 1);

        return new Candidate($route, new ExecutionPath([new PathNode(self::SHOW, null, null, self::POST, 7, 10, 0, null, null)], []), [], []);
    }

    /** @return array<string, mixed> */
    private static function finding(string $symbol, int $line): array
    {
        return ['file' => self::POST, 'line' => $line, 'symbol' => $symbol, 'path' => [['file' => self::POST, 'line' => $line, 'symbol' => $symbol]]];
    }

    /** @param list<array<string, mixed>> $findings */
    private static function ok(string $id, array $findings, int $in = 1, int $out = 1): LlmResponse
    {
        return new LlmResponse($id, LlmOutcome::Ok, ['findings' => $findings], $in, $out, self::MODEL);
    }
}
