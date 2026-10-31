<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Integration\Console;

use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use TusharKhan\SemanticSec\Console\AnalysisPipeline;
use TusharKhan\SemanticSec\Console\Application;
use TusharKhan\SemanticSec\Console\Commands\AnalyzeCommand;
use TusharKhan\SemanticSec\Console\Commands\BaselineCommand;
use TusharKhan\SemanticSec\Llm\ClientInterface;
use TusharKhan\SemanticSec\Llm\Http\Cassette;
use TusharKhan\SemanticSec\Llm\Http\CassetteHandler;
use TusharKhan\SemanticSec\Llm\Http\HttpClientFactory;
use TusharKhan\SemanticSec\Llm\Http\RetryMiddleware;
use TusharKhan\SemanticSec\Llm\LlmOutcome;
use TusharKhan\SemanticSec\Llm\LlmRequest;
use TusharKhan\SemanticSec\Llm\LlmResponse;
use TusharKhan\SemanticSec\Llm\Provider\AnthropicClient;
use TusharKhan\SemanticSec\Llm\Provider\JsonOutput;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;
use TusharKhan\SemanticSec\Tests\Support\LiveBenchmark;
use TusharKhan\SemanticSec\Tests\Support\NetworkTrap;

final class BaselineCommandTest extends TestCase
{
    private const FIXTURES = __DIR__.'/../../Fixtures/cassettes/anthropic';

    private const VULN = '-get-vuln-invoices-id-1';

    private const SHOW = 'app/Http/Controllers/Vuln/InvoiceController.php';

    private string $base;

    private string $root;

    /** @var list<LlmRequest> */
    private array $requests = [];

    protected function setUp(): void
    {
        $this->base = sys_get_temp_dir().'/semsec-baseline-cmd-'.bin2hex(random_bytes(4));
        mkdir($this->base, 0777, true);
        exec('cp -R '.escapeshellarg(BenchmarkCorpus::root().'/laravel11-app').' '.escapeshellarg($this->base.'/app'), $out, $code);
        self::assertSame(0, $code);
        $this->root = $this->base.'/app';
        $this->requests = [];
    }

    protected function tearDown(): void
    {
        exec('rm -rf '.escapeshellarg($this->base));
    }

    public function testRoundTripBaselinesEverything(): void
    {
        [$code, , $err] = $this->replay(['--generate-baseline' => true]);

        self::assertSame(0, $code, $err);
        $file = $this->root.'/semantic-sec-baseline.json';
        self::assertStringContainsString('wrote 13 fingerprints to '.$file, $err);
        $doc = json_decode((string) file_get_contents($file), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($doc);
        self::assertCount(13, $doc['fingerprints']);

        [$code, $out, $err] = $this->analyze([], $this->refuseAll(), ['--format' => 'json']);

        self::assertSame(0, $code, $err);
        self::assertSame([], $this->requests, 'the second run is served from the cache');
        $report = json_decode($out, true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($report);
        self::assertSame([], $report['findings']);
        self::assertSame([], $report['filtered']);
        self::assertCount(13, $report['baselined']);
        self::assertSame(14, $report['summary']['cacheHits']);
    }

    public function testChangedFindingReappears(): void
    {
        [$code] = $this->replay(['--generate-baseline' => true]);
        self::assertSame(0, $code);

        $source = $this->root.'/'.self::SHOW;
        $code = (string) file_get_contents($source);
        $edited = str_replace('$invoice = Invoice::findOrFail($id);', '$invoice = Invoice::query()->findOrFail($id);', $code);
        self::assertNotSame($code, $edited);
        file_put_contents($source, $edited);

        // Only the edited payload misses the cache; its new body is not in the cassette, so it gets a scripted answer.
        $finding = self::finding();
        $answer = static fn (LlmRequest $r): LlmResponse => str_contains($r->user, 'Invoice::query()->findOrFail')
            ? new LlmResponse($r->payloadId, LlmOutcome::Ok, ['findings' => [$finding]], 100, 10, $r->model)
            : throw new \LogicException('unexpected request '.$r->payloadId);
        [$code, $out, $err] = $this->analyze([], $answer, ['--format' => 'json']);

        self::assertSame(1, $code, $err);
        self::assertCount(1, $this->requests);
        self::assertStringEndsWith(self::VULN, $this->requests[0]->payloadId);
        $report = json_decode($out, true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($report);
        self::assertSame([[self::SHOW, 19, 'App\Http\Controllers\Vuln\InvoiceController::show']], array_map(static fn (array $f): array => [$f['file'], $f['line'], $f['symbol']], $report['findings']));
        self::assertCount(12, $report['baselined']);
        self::assertNotContains($report['findings'][0]['fingerprint'], array_column($report['baselined'], 'fingerprint'));
    }

    public function testBaselineCommandAlias(): void
    {
        $app = new Application();
        self::assertInstanceOf(BaselineCommand::class, $app->find('baseline'));
        $analyze = $app->find('analyze')->getDefinition();
        $baseline = $app->find('baseline')->getDefinition();
        self::assertSame(array_keys($analyze->getOptions()), array_keys($baseline->getOptions()));
        self::assertSame(array_keys($analyze->getArguments()), array_keys($baseline->getArguments()));

        $out = $this->base.'/out/b.json';
        [$code, , $err] = $this->analyze(['--baseline' => $out], $this->vulnOnly(), [], BaselineCommand::class);

        self::assertSame(0, $code, $err);
        self::assertStringContainsString('wrote 1 fingerprints to '.$out, $err);
        self::assertFileExists($out);
        self::assertFileDoesNotExist($this->root.'/semantic-sec-baseline.json');
    }

    public function testGenerateExitsZeroWithFindings(): void
    {
        [$code, $out, $err] = $this->analyze(['--generate-baseline' => true], $this->vulnOnly());

        self::assertSame(0, $code, $err);
        self::assertStringContainsString('File:          '.self::SHOW, $out, 'the normal report is still printed');
        self::assertStringContainsString('wrote 1 fingerprints to '.$this->root.'/semantic-sec-baseline.json', $err);

        [$code] = $this->analyze([], $this->vulnOnly());
        self::assertSame(0, $code, 'the default baseline is picked up');
    }

    public function testGenerateWithDryRunIsExitTwo(): void
    {
        foreach ([AnalyzeCommand::class => ['--generate-baseline' => true, '--dry-run' => true], BaselineCommand::class => ['--dry-run' => true]] as $class => $args) {
            [$code, , $err] = $this->analyze($args, $this->vulnOnly(), [], $class);
            self::assertSame(2, $code, $class);
            self::assertStringContainsString('cannot be used with --dry-run', $err);
        }
        self::assertFileDoesNotExist($this->root.'/.semantic-sec/dry-run');
    }

    public function testMissingExplicitIsExitTwo(): void
    {
        [$code, , $err] = $this->analyze(['--baseline' => $this->base.'/missing.json'], $this->vulnOnly());

        self::assertSame(2, $code);
        self::assertStringStartsWith('Error: ', $err);
        self::assertStringContainsString($this->base.'/missing.json', $err);
        self::assertSame([], $this->requests);
    }

    public function testBadJsonOrVersionIsExitTwo(): void
    {
        foreach (['{"version":', '{"version": 2, "fingerprints": []}', '{"version": 1, "fingerprints": [{"fingerprint": "zz"}]}'] as $json) {
            file_put_contents($this->root.'/semantic-sec-baseline.json', $json);
            [$code, , $err] = $this->analyze([], $this->vulnOnly());
            self::assertSame(2, $code, $json);
            self::assertStringContainsString($this->root.'/semantic-sec-baseline.json', $err);
        }
        self::assertSame([], $this->requests, 'a bad baseline fails before anything is sent');
    }

    public function testGenerateRefusesSymlinkBeforeParsing(): void
    {
        file_put_contents($this->base.'/target.json', 'keep');
        symlink($this->base.'/target.json', $this->root.'/semantic-sec-baseline.json');

        [$code, , $err] = $this->analyze(['--generate-baseline' => true], $this->vulnOnly());

        self::assertSame(2, $code);
        self::assertStringContainsString('symlink', $err);
        self::assertSame([], $this->requests);
        self::assertSame('keep', file_get_contents($this->base.'/target.json'));
    }

    public function testGenerateDoesNotWriteWhenEveryRequestFailed(): void
    {
        $answer = static fn (LlmRequest $r): LlmResponse => new LlmResponse($r->payloadId, LlmOutcome::Refused, null, 10, 0, 'm', 'declined');
        [$code] = $this->analyze(['--generate-baseline' => true], $answer);

        self::assertSame(2, $code);
        self::assertFileDoesNotExist($this->root.'/semantic-sec-baseline.json');
    }

    /**
     * Runs the command with the pinned live cassette replayed by body behind the provider seam.
     *
     * @param  array<string, string|bool>  $args
     * @return array{int, string, string}
     */
    private function replay(array $args): array
    {
        $cassette = LiveBenchmark::recordedCassette() ?? throw new \LogicException('the live benchmark cassette is not committed');
        $handler = new CassetteHandler(Cassette::load($cassette), 'replay', match: 'body');
        $client = new AnthropicClient(HttpClientFactory::create($handler, [RetryMiddleware::create()]), 'replay-key');
        $result = $this->command($args, $client);
        $handler->assertExhausted();

        return $result;
    }

    /**
     * @param  array<string, string|bool>  $args
     * @param  \Closure(LlmRequest): LlmResponse  $answer
     * @param  array<string, string>  $extra
     * @param  class-string<AnalyzeCommand>  $class
     * @return array{int, string, string}
     */
    private function analyze(array $args, \Closure $answer, array $extra = [], string $class = AnalyzeCommand::class): array
    {
        $client = new class (function (LlmRequest $r) use ($answer): LlmResponse {
            $this->requests[] = $r;

            return $answer($r);
        }) implements ClientInterface {
            public function __construct(private readonly \Closure $answer)
            {
            }

            public function analyze(LlmRequest $request): PromiseInterface
            {
                return Create::promiseFor(($this->answer)($request));
            }
        };

        return $this->command([...$args, ...$extra], $client, $class);
    }

    /**
     * @param  array<string, string|bool>  $args
     * @param  class-string<AnalyzeCommand>  $class
     * @return array{int, string, string}
     */
    private function command(array $args, ClientInterface $client, string $class = AnalyzeCommand::class): array
    {
        NetworkTrap::install();
        try {
            /** @var Command $command */
            $command = new $class(static fn (): ClientInterface => $client, new AnalysisPipeline());
            $t = new CommandTester($command);
            $code = $t->execute(['--project-root' => $this->root, ...$args], ['capture_stderr_separately' => true]);
        } finally {
            self::assertSame([], NetworkTrap::uninstall(), 'no network');
        }

        return [$code, $t->getDisplay(), $t->getErrorOutput()];
    }

    /** @return \Closure(LlmRequest): LlmResponse */
    private function vulnOnly(): \Closure
    {
        $finding = self::finding();

        return static fn (LlmRequest $r): LlmResponse => new LlmResponse($r->payloadId, LlmOutcome::Ok, ['findings' => str_ends_with($r->payloadId, self::VULN) ? [$finding] : []], 100, 10, $r->model);
    }

    /** @return \Closure(LlmRequest): LlmResponse */
    private function refuseAll(): \Closure
    {
        return static fn (LlmRequest $r): LlmResponse => throw new \LogicException('unexpected request '.$r->payloadId);
    }

    /** @return array<string, mixed> the finding the live model returned for GET /vuln/invoices/{id} */
    private static function finding(): array
    {
        $cassette = json_decode((string) file_get_contents(self::FIXTURES.'/live-idor-find-by-id.json'), true, 512, JSON_THROW_ON_ERROR);
        $message = json_decode($cassette['interactions'][0]['response']['body'], true, 512, JSON_THROW_ON_ERROR);
        $data = JsonOutput::decode($message['content'][0]['text']);
        self::assertIsArray($data);

        return $data['findings'][0];
    }
}
