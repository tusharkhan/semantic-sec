<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Integration\Engine;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Analysis\Category;
use TusharKhan\SemanticSec\Console\AnalysisPipeline;
use TusharKhan\SemanticSec\Console\PipelineResult;
use TusharKhan\SemanticSec\Engine\AnalysisResult;
use TusharKhan\SemanticSec\Engine\Baseline;
use TusharKhan\SemanticSec\Engine\Engine;
use TusharKhan\SemanticSec\Engine\Fingerprinter;
use TusharKhan\SemanticSec\Engine\ResultCache;
use TusharKhan\SemanticSec\Llm\ClientInterface;
use TusharKhan\SemanticSec\Llm\FakeClient;
use TusharKhan\SemanticSec\Llm\GroundingChecker;
use TusharKhan\SemanticSec\Llm\Http\Cassette;
use TusharKhan\SemanticSec\Llm\Http\CassetteHandler;
use TusharKhan\SemanticSec\Llm\Http\HttpClientFactory;
use TusharKhan\SemanticSec\Llm\Http\RetryMiddleware;
use TusharKhan\SemanticSec\Llm\LlmOutcome;
use TusharKhan\SemanticSec\Llm\LlmResponse;
use TusharKhan\SemanticSec\Llm\Provider\AnthropicClient;
use TusharKhan\SemanticSec\Llm\Provider\JsonOutput;
use TusharKhan\SemanticSec\Llm\ValidatingClient;
use TusharKhan\SemanticSec\Payload\Payload;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;
use TusharKhan\SemanticSec\Tests\Support\LiveBenchmark;
use TusharKhan\SemanticSec\Tests\Support\NetworkTrap;

final class BenchmarkEngineTest extends TestCase
{
    private const FIXTURES = __DIR__.'/../../Fixtures/cassettes/anthropic';

    private const VULN = 'GET /vuln/invoices/{id}';

    private const SHARED = 'GET /vuln/shared-invoices/{id}';

    private string $base;

    private string $root;

    protected function setUp(): void
    {
        $this->base = sys_get_temp_dir().'/semsec-engine-bench-'.bin2hex(random_bytes(4));
        mkdir($this->base, 0777, true);
        exec('cp -R '.escapeshellarg(BenchmarkCorpus::root().'/laravel11-app').' '.escapeshellarg($this->base.'/app'), $out, $code);
        self::assertSame(0, $code);
        $this->root = $this->base.'/app';
    }

    protected function tearDown(): void
    {
        exec('rm -rf '.escapeshellarg($this->base));
    }

    public function testScriptedRunReportsTheLiveFindingAndHonoursTheBenchmarkSuppression(): void
    {
        $run = (new AnalysisPipeline())->run($this->root, null, null, false, null);
        [$payloads, $candidates] = [$run->payloads(), count($run->results)];
        $live = self::liveFinding();
        $answers = [];
        foreach ($payloads as $payload) {
            $findings = match (true) {
                in_array(self::VULN, $payload->candidate->route->keys(), true) => [$live],
                in_array(self::SHARED, $payload->candidate->route->keys(), true) => [[...$live, 'file' => 'app/Http/Controllers/Vuln/SharedInvoiceController.php', 'line' => 15, 'symbol' => 'App\Http\Controllers\Vuln\SharedInvoiceController::show', 'path' => []]],
                default => [],
            };
            $answers[$payload->id] = new LlmResponse($payload->id, LlmOutcome::Ok, ['findings' => $findings], 100, 10, 'claude-opus-5-5');
        }

        NetworkTrap::install();
        try {
            $client = new FakeClient($answers);
            $first = $this->engine($client, $run)->run($payloads, $candidates);
            $again = new FakeClient([]);
            $second = $this->engine($again, $run)->run($payloads, $candidates);
        } finally {
            self::assertSame([], NetworkTrap::uninstall(), 'no network');
        }

        $sendable = count(array_filter($payloads, static fn (Payload $p): bool => preg_match('~^L\d+\|~m', $p->code) === 1));
        self::assertCount($sendable, $client->requests);
        self::assertSame(['payloads' => count($payloads), 'skipped' => count($payloads) - $sendable, 'sent' => $sendable, 'cacheHits' => 0, 'ok' => $sendable, 'dropped' => 0], self::pick($first));
        self::assertSame([], $again->requests, 'the second run is served from the cache');
        self::assertSame(['payloads' => count($payloads), 'skipped' => count($payloads) - $sendable, 'sent' => 0, 'cacheHits' => $sendable, 'ok' => 0, 'dropped' => 0], self::pick($second));

        foreach ([$first, $second] as $result) {
            self::assertCount(1, $result->findings);
            $v = $result->findings[0]['vulnerability'];
            self::assertTrue($result->findings[0]['failing']);
            self::assertSame([Category::Idor, 'app/Http/Controllers/Vuln/InvoiceController.php', 19, 'App\Http\Controllers\Vuln\InvoiceController::show', self::VULN], [$v->category, $v->file, $v->line, $v->symbol, $v->routeKey]);
            self::assertMatchesRegularExpression('~^[0-9a-f]{64}$~', $v->fingerprint);
            self::assertCount(1, $result->suppressed);
            self::assertSame('shared invoices are public by contract', $result->suppressed[0]['suppression']->reason);
            self::assertSame([], $result->baselined);
        }
        self::assertSame($first->findings[0]['vulnerability']->fingerprint, $second->findings[0]['vulnerability']->fingerprint);
    }

    public function testRecordedBenchmarkCassetteReplays(): void
    {
        $cassette = LiveBenchmark::recordedCassette();
        self::assertNotNull($cassette, 'the live benchmark cassette is committed');
        self::assertStringEndsWith('anthropic/live-benchmark-laravel11.json', $cassette);

        // The live run used --level low --min-confidence low; neither changes a request body.
        $run = (new AnalysisPipeline())->run($this->root, null, null, false, null, ['level' => 'low', 'min_confidence' => 'low']);
        $handler = new CassetteHandler(Cassette::load($cassette), 'replay', match: 'body');
        $client = new ValidatingClient(new AnthropicClient(HttpClientFactory::create($handler, [RetryMiddleware::create()]), 'replay-key'));

        NetworkTrap::install();
        try {
            $result = $this->engine($client, $run)->run($run->payloads(), count($run->results));
        } finally {
            self::assertSame([], NetworkTrap::uninstall(), 'no network');
        }
        $handler->assertExhausted();

        self::assertSame(['sent' => 14, 'ok' => 14, 'dropped' => 0], array_intersect_key($result->stats, array_flip(['sent', 'ok', 'dropped'])));
        $vuln = 'app/Http/Controllers/Vuln/';
        $expected = [
            ['idor', 'app/Services/DownloadService.php', 11, 'App\Services\DownloadService::find'],
            ['idor', $vuln.'InvoiceController.php', 26, 'App\Http\Controllers\Vuln\InvoiceController::update'],
            ['idor', $vuln.'InvoiceController.php', 33, 'App\Http\Controllers\Vuln\InvoiceController::pdf'],
            ['idor', $vuln.'ReceiptController.php', 18, 'App\Http\Controllers\Vuln\ReceiptController::show'],
            ['mass_assignment', $vuln.'AccountController.php', 14, 'App\Http\Controllers\Vuln\AccountController::update'],
            ['insecure_deserialization', $vuln.'CartController.php', 13, 'App\Http\Controllers\Vuln\CartController::restore'],
            ['workflow_bypass', $vuln.'OrderController.php', 18, 'App\Http\Controllers\Vuln\OrderController::refund'],
            ['idor', $vuln.'CommentController.php', 18, 'App\Http\Controllers\Vuln\CommentController::destroy'],
            ['idor', $vuln.'DocumentController.php', 22, 'App\Http\Controllers\Vuln\DocumentController::show'],
            ['workflow_bypass', $vuln.'InvoiceController.php', 26, 'App\Http\Controllers\Vuln\InvoiceController::update'],
            ['mass_assignment', $vuln.'TeamController.php', 14, 'App\Http\Controllers\Vuln\TeamController::store'],
            ['idor', $vuln.'ProjectController.php', 14, 'App\Http\Controllers\Vuln\ProjectController::update'],
            ['idor', $vuln.'InvoiceController.php', 19, 'App\Http\Controllers\Vuln\InvoiceController::show'],
        ];
        $actual = array_map(static fn (array $f): array => [$f['vulnerability']->category->value, $f['vulnerability']->file, $f['vulnerability']->line, $f['vulnerability']->symbol], $result->findings);
        self::assertEqualsCanonicalizing($expected, $actual);
        self::assertCount(13, $result->findings);
        foreach ($result->findings as $f) {
            self::assertTrue($f['failing'], $f['vulnerability']->symbol);
            self::assertStringNotContainsString('/Safe/', $f['vulnerability']->file);
        }
        $low = array_values(array_filter($result->findings, static fn (array $f): bool => $f['vulnerability']->category === Category::WorkflowBypass && $f['vulnerability']->line === 26));
        self::assertSame('low', $low[0]['vulnerability']->confidence->value);

        self::assertCount(1, $result->suppressed);
        $s = $result->suppressed[0]['vulnerability'];
        self::assertSame([Category::Idor, 'App\Http\Controllers\Vuln\SharedInvoiceController::show'], [$s->category, $s->symbol]);
        self::assertSame([], $result->baselined);

        $this->assertBenchmarkMapping($result);
    }

    // Every laravel11 vulnerable case is reported (same file and category) or suppressed; no safe symbol has a finding.
    private function assertBenchmarkMapping(AnalysisResult $result): void
    {
        $reported = array_map(static fn (array $f): array => [$f['vulnerability']->category->value, $f['vulnerability']->file, $f['vulnerability']->symbol], $result->findings);
        $suppressed = array_map(static fn (array $s): string => $s['vulnerability']->symbol, $result->suppressed);
        $app = BenchmarkCorpus::root().'/laravel11-app/';
        $cases = array_filter(BenchmarkCorpus::cases(), static fn (array $c): bool => $c['app'] === 'laravel11-app');
        self::assertCount(13, $cases);
        foreach ($cases as $case) {
            $vulnerable = $case['vulnerable'];
            $symbol = $vulnerable['symbol'];
            if (($vulnerable['suppressed'] ?? false) === true) {
                self::assertContains($symbol, $suppressed, $case['id']);

                continue;
            }
            // The service-layer case is reported at the lookup its controller delegates to.
            [$symbol, $file] = $case['id'] === 'idor-service-layer'
                ? ['App\Services\DownloadService::find', 'app/Services/DownloadService.php']
                : [$symbol, substr(BenchmarkCorpus::fileForSymbol('laravel11-app', $symbol), strlen($app))];
            $hits = array_filter($reported, static fn (array $r): bool => $r[0] === $case['category'] && $r[1] === $file && $r[2] === $symbol);
            self::assertNotEmpty($hits, "{$case['id']}: no {$case['category']} finding at {$symbol}");

            $safe = $case['safe']['symbol'];
            self::assertSame([], array_filter($reported, static fn (array $r): bool => $r[2] === $safe), "{$case['id']}: safe {$safe} has a finding");
        }
    }

    // The engine reuses the pipeline's parse, as AnalyzeCommand does.
    private function engine(ClientInterface $client, PipelineResult $run): Engine
    {
        $project = $run->project;

        return new Engine(
            $client,
            ResultCache::inProject($this->root, $project->config, $run->system, true),
            new Fingerprinter($project->parsed, $project->symbols),
            new GroundingChecker($project->symbols),
            $project->parsed,
            $project->config,
            Baseline::empty(),
        );
    }

    /** @return array<string, mixed> */
    private static function liveFinding(): array
    {
        $cassette = json_decode((string) file_get_contents(self::FIXTURES.'/live-idor-find-by-id.json'), true, 512, JSON_THROW_ON_ERROR);
        $message = json_decode($cassette['interactions'][0]['response']['body'], true, 512, JSON_THROW_ON_ERROR);
        $data = JsonOutput::decode($message['content'][0]['text']);
        self::assertIsArray($data);

        return $data['findings'][0];
    }

    /** @return array<string, int> */
    private static function pick(AnalysisResult $r): array
    {
        return array_intersect_key($r->stats, array_flip(['payloads', 'skipped', 'sent', 'cacheHits', 'ok', 'dropped']));
    }
}
