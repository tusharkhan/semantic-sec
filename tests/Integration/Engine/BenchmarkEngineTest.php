<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Integration\Engine;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Analysis\Category;
use TusharKhan\SemanticSec\Console\AnalysisPipeline;
use TusharKhan\SemanticSec\Console\MapBuilder;
use TusharKhan\SemanticSec\Engine\AnalysisResult;
use TusharKhan\SemanticSec\Engine\Baseline;
use TusharKhan\SemanticSec\Engine\Engine;
use TusharKhan\SemanticSec\Engine\Fingerprinter;
use TusharKhan\SemanticSec\Engine\ResultCache;
use TusharKhan\SemanticSec\Llm\FakeClient;
use TusharKhan\SemanticSec\Llm\GroundingChecker;
use TusharKhan\SemanticSec\Llm\LlmOutcome;
use TusharKhan\SemanticSec\Llm\LlmResponse;
use TusharKhan\SemanticSec\Llm\Provider\JsonOutput;
use TusharKhan\SemanticSec\Payload\Payload;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;
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
        [$payloads, $candidates, $system] = $this->pipeline();
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
            $first = $this->engine($client, $system)->run($payloads, $candidates);
            $again = new FakeClient([]);
            $second = $this->engine($again, $system)->run($payloads, $candidates);
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
        if (!is_file(self::FIXTURES.'/live-benchmark-laravel11.json')) {
            self::markTestSkipped('live-benchmark-laravel11.json is recorded in M6 Task 6; replay assertions land with it');
        }
        self::markTestIncomplete('pin the recorded result here once the cassette exists');
    }

    /** @return array{list<Payload>, int, string} */
    private function pipeline(): array
    {
        [$results, , $system] = (new AnalysisPipeline())->run($this->root, null, null, false, null);
        $payloads = [];
        foreach ($results as $r) {
            array_push($payloads, ...$r['payloads']);
        }

        return [$payloads, count($results), $system];
    }

    private function engine(FakeClient $client, string $system): Engine
    {
        $project = (new MapBuilder())->project($this->root, null, null);

        return new Engine(
            $client,
            ResultCache::inProject($this->root, $project->config, $system, true),
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
