<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Integration\Console;

use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Tester\CommandTester;
use TusharKhan\SemanticSec\Config\Config;
use TusharKhan\SemanticSec\Console\AnalysisPipeline;
use TusharKhan\SemanticSec\Console\Commands\AnalyzeCommand;
use TusharKhan\SemanticSec\Console\MapBuilder;
use TusharKhan\SemanticSec\Llm\ClientInterface;
use TusharKhan\SemanticSec\Llm\FakeClient;
use TusharKhan\SemanticSec\Llm\LlmException;
use TusharKhan\SemanticSec\Llm\LlmOutcome;
use TusharKhan\SemanticSec\Llm\LlmRequest;
use TusharKhan\SemanticSec\Llm\LlmResponse;
use TusharKhan\SemanticSec\Llm\Provider\JsonOutput;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;
use TusharKhan\SemanticSec\Tests\Support\NetworkTrap;

final class AnalyzeCommandTest extends TestCase
{
    private const FIXTURES = __DIR__.'/../../Fixtures/cassettes/anthropic';

    // The payload id suffix of GET /vuln/invoices/{id}, the benchmark's plain IDOR.
    private const VULN = '-get-vuln-invoices-id-1';

    private string $base;

    private string $root;

    /** @var list<LlmRequest> */
    private array $requests = [];

    /** @var list<Config> */
    private array $configs = [];

    protected function setUp(): void
    {
        $this->base = sys_get_temp_dir().'/semsec-analyze-cmd-'.bin2hex(random_bytes(4));
        mkdir($this->base, 0777, true);
        exec('cp -R '.escapeshellarg(BenchmarkCorpus::root().'/laravel11-app').' '.escapeshellarg($this->base.'/app'), $out, $code);
        self::assertSame(0, $code);
        $this->root = $this->base.'/app';
        $this->requests = $this->configs = [];
    }

    protected function tearDown(): void
    {
        exec('rm -rf '.escapeshellarg($this->base));
    }

    public function testExitOneOnFailingFinding(): void
    {
        [$code, $out, $err] = $this->analyze([], $this->answers(self::finding()));

        self::assertSame(1, $code, $err);
        self::assertStringContainsString("[!] High Severity: IDOR: any authenticated user can read any invoice by id\n      File:          app/Http/Controllers/Vuln/InvoiceController.php\n      Line:          19\n      Symbol:        App\\Http\\Controllers\\Vuln\\InvoiceController::show", $out);
        self::assertStringContainsString('Confidence:    high', $out);
        self::assertStringNotContainsString('not failing', $out);
        self::assertMatchesRegularExpression('~ok\s+14\b~', $out);
        self::assertCount(14, $this->requests);
    }

    public function testOneBeatsThree(): void
    {
        // The vulnerable payload reports enough tokens to exhaust the budget, so every later one stays unsent.
        [$code, $out, $err] = $this->analyze(['--concurrency' => '1', '--budget' => '1000000'], $this->answers(self::finding(), 990_000));

        self::assertSame(1, $code, $err);
        self::assertStringContainsString('File:          app/Http/Controllers/Vuln/InvoiceController.php', $out);
        self::assertMatchesRegularExpression('~budget\s+1000000 \(exceeded\)~', $out);
        self::assertCount(2, $this->requests);
    }

    public function testExitThreeBudgetOnly(): void
    {
        [$code, $out, $err] = $this->analyze(['--budget' => '0'], $this->answers(self::finding()));

        self::assertSame(3, $code, $err);
        self::assertSame([], $this->requests, 'a budget below one reservation sends nothing');
        self::assertMatchesRegularExpression('~unsent\s+14\b~', $out);
        self::assertStringContainsString('14 payloads not sent: token budget exhausted', $out);
    }

    public function testExitTwoAllFailed(): void
    {
        $answer = static fn (LlmRequest $r): LlmResponse|LlmException => str_ends_with($r->payloadId, self::VULN)
            ? new LlmResponse($r->payloadId, LlmOutcome::Refused, null, 10, 0, 'm', 'declined')
            : new LlmException('HTTP 500 from provider', 500);
        [$code, $out, $err] = $this->analyze([], $answer);

        self::assertSame(2, $code, $err);
        self::assertMatchesRegularExpression('~refused\s+1\b~', $out);
        self::assertMatchesRegularExpression('~failed\s+13\b~', $out);
        self::assertStringContainsString('HTTP 500 from provider', $out);
    }

    public function testExitZeroLowConfidenceOnly(): void
    {
        [$code, $out, $err] = $this->analyze([], $this->answers([...self::finding(), 'confidence' => 'low']));

        self::assertSame(0, $code, $err);
        self::assertStringContainsString('[!] High Severity: IDOR: any authenticated user can read any invoice by id', $out);
        self::assertStringContainsString('Confidence:    low (not failing)', $out);
    }

    public function testStrictReasonInSummary(): void
    {
        $answer = fn (LlmRequest $r): LlmResponse => str_ends_with($r->payloadId, self::VULN)
            ? new LlmResponse($r->payloadId, LlmOutcome::Refused, null, 10, 0, 'm', 'declined')
            : ($this->answers(self::finding()))($r);

        [$code, $out, $err] = $this->analyze([], $answer);
        self::assertSame(0, $code, $err);
        self::assertStringNotContainsString('strict:', $out);

        [$code, $out, $err] = $this->analyze(['--strict' => true], $answer);
        self::assertSame(2, $code, $err);
        self::assertStringContainsString('strict: 1 refused', $out);
        self::assertSame(1, substr_count($out, 'strict:'));
    }

    public function testStrictDoesNotHideAFailingFinding(): void
    {
        [$code, $out, $err] = $this->analyze(['--strict' => true, '--concurrency' => '1', '--budget' => '1000000'], $this->answers(self::finding(), 990_000));

        self::assertSame(1, $code, $err);
        self::assertStringNotContainsString('strict:', $out);
    }

    public function testStrictAcceptedWithDryRun(): void
    {
        $t = new CommandTester(new AnalyzeCommand());
        $code = $t->execute(['--project-root' => $this->root, '--dry-run' => true, '--strict' => true], ['capture_stderr_separately' => true]);

        self::assertSame(0, $code, $t->getErrorOutput());
    }

    public function testFilteredFindingsOnlyCounted(): void
    {
        [$code, $out, $err] = $this->analyze(['--level' => 'critical'], $this->answers(self::finding()));

        self::assertSame(0, $code, $err);
        self::assertMatchesRegularExpression('~filtered\s+1 \(below level critical\)~', $out);
        self::assertStringNotContainsString('InvoiceController::show', $out);
    }

    public function testMissingKeyExitTwoNamesEnvOnly(): void
    {
        $saved = getenv('ANTHROPIC_API_KEY');
        putenv('ANTHROPIC_API_KEY');
        NetworkTrap::install();
        try {
            $t = new CommandTester(new AnalyzeCommand());
            $code = $t->execute(['--project-root' => $this->root], ['capture_stderr_separately' => true]);
        } finally {
            $calls = NetworkTrap::uninstall();
            $saved === false ? putenv('ANTHROPIC_API_KEY') : putenv('ANTHROPIC_API_KEY='.$saved);
        }

        self::assertSame([], $calls, 'no network');
        self::assertSame(2, $code);
        self::assertSame("Error: ANTHROPIC_API_KEY is not set\n", $t->getErrorOutput());
        self::assertFalse(is_dir($this->root.'/.semantic-sec/cache'), 'nothing written before the key check');

        // A key env var that holds only whitespace is missing too, and its value is never printed.
        file_put_contents($this->root.'/semantic-sec.yaml', "api_key_env: SEMSEC_TEST_KEY\n");
        putenv('SEMSEC_TEST_KEY=  ');
        try {
            $t = new CommandTester(new AnalyzeCommand());
            $code = $t->execute(['--project-root' => $this->root], ['capture_stderr_separately' => true]);
        } finally {
            putenv('SEMSEC_TEST_KEY');
        }
        self::assertSame(2, $code);
        self::assertSame("Error: SEMSEC_TEST_KEY is not set\n", $t->getErrorOutput());
    }

    public function testJsonStdoutIsOnlyTheDocument(): void
    {
        [$code, $out, $err] = $this->analyze(['--format' => 'json'], $this->answers(self::finding()));

        self::assertSame(1, $code, $err);
        $doc = json_decode($out, true, 512, JSON_THROW_ON_ERROR);
        self::assertSame(1, $doc['version']);
        self::assertCount(1, $doc['findings']);
        self::assertSame(1, $doc['summary']['exitCode']);
        self::assertStringEndsWith("}\n", $out);
        self::assertMatchesRegularExpression('~^Summary$~m', $err, 'the summary goes to stderr');
        self::assertStringNotContainsString('"findings"', $err);
    }

    public function testJsonOutputWritesTheDocumentToTheFile(): void
    {
        $file = $this->base.'/reports/report.json';
        [$code, $out, $err] = $this->analyze(['--format' => 'json', '--output' => $file], $this->answers(self::finding()));

        self::assertSame(1, $code, $err);
        self::assertSame('', $out);
        $doc = json_decode((string) file_get_contents($file), true, 512, JSON_THROW_ON_ERROR);
        self::assertCount(1, $doc['findings']);
        self::assertMatchesRegularExpression('~^Summary$~m', $err);
        self::assertStringContainsString('Report written to '.$file, $err);
    }

    public function testSarifStdoutIsOnlyTheDocument(): void
    {
        [$code, $out, $err] = $this->analyze(['--format' => 'sarif'], $this->answers(self::finding()));

        self::assertSame(1, $code, $err);
        $doc = json_decode($out, true, 512, JSON_THROW_ON_ERROR);
        self::assertSame('2.1.0', $doc['version']);
        self::assertCount(1, $doc['runs'][0]['results']);
        self::assertSame('error', $doc['runs'][0]['results'][0]['level']);
        self::assertStringEndsWith("}\n", $out);
        self::assertStringNotContainsString($this->root, $out);
        self::assertMatchesRegularExpression('~^Summary$~m', $err, 'the summary goes to stderr');
        self::assertStringNotContainsString('"runs"', $err);
    }

    public function testSarifOutputWritesTheDocumentToTheFile(): void
    {
        $file = $this->base.'/reports/report.sarif';
        [$code, $out, $err] = $this->analyze(['--format' => 'sarif', '--output' => $file], $this->answers(self::finding()));

        self::assertSame(1, $code, $err);
        self::assertSame('', $out);
        $doc = json_decode((string) file_get_contents($file), true, 512, JSON_THROW_ON_ERROR);
        self::assertCount(1, $doc['runs'][0]['results']);
        self::assertStringContainsString('Report written to '.$file, $err);
    }

    public function testGitlabSastStdoutIsOnlyTheDocument(): void
    {
        [$code, $out, $err] = $this->analyze(['--format' => 'gitlab-sast'], $this->answers(self::finding()));

        self::assertSame(1, $code, $err);
        $doc = json_decode($out, true, 512, JSON_THROW_ON_ERROR);
        self::assertSame('15.2.5', $doc['version']);
        self::assertSame('success', $doc['scan']['status']);
        self::assertMatchesRegularExpression('~^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$~', $doc['scan']['start_time']);
        self::assertLessThanOrEqual($doc['scan']['end_time'], $doc['scan']['start_time']);
        self::assertCount(1, $doc['vulnerabilities']);
        self::assertStringStartsWith("{\n", $out);
        self::assertStringEndsWith("}\n", $out);
        self::assertStringNotContainsString($this->root, $out);
        self::assertMatchesRegularExpression('~^Summary$~m', $err, 'the summary goes to stderr');
        self::assertStringNotContainsString('"vulnerabilities"', $err);
    }

    public function testGitlabSastOutputWritesTheDocumentToTheFile(): void
    {
        $file = $this->base.'/reports/gl-sast-report.json';
        [$code, $out, $err] = $this->analyze(['--format' => 'gitlab-sast', '--output' => $file], $this->answers(self::finding()));

        self::assertSame(1, $code, $err);
        self::assertSame('', $out);
        $doc = json_decode((string) file_get_contents($file), true, 512, JSON_THROW_ON_ERROR);
        self::assertCount(1, $doc['vulnerabilities']);
        self::assertStringContainsString('Report written to '.$file, $err);
    }

    public function testUnknownFormatNamesSarif(): void
    {
        [$code, , $err] = $this->analyze(['--format' => 'xml'], $this->answers(self::finding()));

        self::assertSame(2, $code);
        self::assertSame("Error: --format must be console, json, sarif or gitlab-sast\n", $err);
        self::assertSame([], $this->requests);
    }

    public function testOutputWritesFileSummaryToStderr(): void
    {
        $file = $this->base.'/reports/report.txt';
        [$code, $out, $err] = $this->analyze(['--output' => $file, '--strict' => true, '--no-cache' => true], $this->answers(self::finding()));
        [$plainCode, $plain] = $this->analyze(['--strict' => true, '--no-cache' => true], $this->answers(self::finding()));

        self::assertSame(1, $code, $err);
        self::assertSame($plainCode, $code, 'exit codes are unchanged');
        self::assertSame('', $out, 'stdout stays empty');
        self::assertFileExists($file);
        $report = (string) file_get_contents($file);
        self::assertSame($plain, $report, 'the file holds the same report, undecorated');
        self::assertStringContainsString('[!] High Severity: IDOR', $report);
        self::assertStringNotContainsString("\e", $report);
        self::assertStringNotContainsString('[!]', $err, 'findings go to the file only');
        self::assertMatchesRegularExpression('~^Summary$~m', $err);
        self::assertMatchesRegularExpression('~ok\s+14\b~', $err);
        self::assertStringContainsString('Report written to '.$file, $err);
    }

    public function testOutputSymlinkRefused(): void
    {
        file_put_contents($this->base.'/victim', 'keep');
        symlink($this->base.'/victim', $this->base.'/report.txt');
        [$code, $out, $err] = $this->analyze(['--output' => $this->base.'/report.txt'], $this->answers(self::finding()));

        self::assertSame(2, $code);
        self::assertSame('', $out);
        self::assertStringStartsWith('Error: Refusing to write', $err);
        self::assertStringContainsString('is a symlink', $err);
        self::assertSame('keep', file_get_contents($this->base.'/victim'));

        mkdir($this->base.'/dir');
        [$code, , $err] = $this->analyze(['--output' => $this->base.'/dir'], $this->answers(self::finding()));
        self::assertSame(2, $code);
        self::assertStringContainsString('is not a regular file', $err);
    }

    public function testBadOutputFailsBeforeParsing(): void
    {
        mkdir($this->base.'/dir');
        $mapper = new MapBuilder();
        [$code, $out, $err] = $this->analyze(['--output' => $this->base.'/dir'], $this->answers(self::finding()), $mapper);

        self::assertSame(2, $code);
        self::assertSame('', $out);
        self::assertStringContainsString('is not a regular file', $err);
        self::assertSame(0, $mapper->parses(), 'the project is never parsed');
        self::assertSame([], $this->requests);
        self::assertDirectoryDoesNotExist($this->root.'/.semantic-sec/cache');
    }

    public function testOutputRejectedWithDryRun(): void
    {
        $t = new CommandTester(new AnalyzeCommand());
        $code = $t->execute(['--project-root' => $this->root, '--dry-run' => true, '--output' => $this->base.'/r.txt'], ['capture_stderr_separately' => true]);

        self::assertSame(2, $code);
        self::assertSame("Error: --output cannot be used with --dry-run\n", $t->getErrorOutput());
        self::assertFileDoesNotExist($this->base.'/r.txt');
    }

    public function testOverridesApply(): void
    {
        // --level critical filters the high finding out; --model reaches the request.
        [$code, $out, $err] = $this->analyze(['--level' => 'critical', '--model' => 'test-model-x', '--provider' => 'openai', '--concurrency' => '2'], $this->answers(self::finding()));

        self::assertSame(0, $code, $err);
        self::assertStringNotContainsString('[!]', $out);
        self::assertMatchesRegularExpression('~filtered\s+1\b~', $out);
        self::assertSame(['test-model-x'], array_values(array_unique(array_map(static fn (LlmRequest $r): string => $r->model, $this->requests))));
        self::assertSame(['openai', 'test-model-x', 2], [$this->configs[0]->provider, $this->configs[0]->model, $this->configs[0]->concurrency]);

        // --min-confidence high: a medium-confidence finding is reported but does not fail.
        [$code, $out] = $this->analyze(['--min-confidence' => 'high', '--no-cache' => true], $this->answers([...self::finding(), 'confidence' => 'medium']));
        self::assertSame(0, $code);
        self::assertStringContainsString('Confidence:    medium (not failing)', $out);
    }

    public function testInvalidOverridesExitTwoNamingTheFlag(): void
    {
        foreach ([
            [['--level' => 'severe'], '--level must be one of: low, medium, high, critical.'],
            [['--min-confidence' => 'sure'], '--min-confidence must be one of: low, medium, high.'],
            [['--provider' => 'gemini'], '--provider must be one of: openai, anthropic, ollama.'],
            [['--model' => ' '], '--model must be a non-empty string.'],
            [['--concurrency' => '0'], '--concurrency must be a positive integer.'],
            [['--concurrency' => 'two'], '--concurrency must be a positive integer.'],
            [['--budget' => '-1'], '--budget must be an integer ≥ 0.'],
            [['--budget' => '1e6'], '--budget must be an integer ≥ 0.'],
        ] as [$args, $message]) {
            $mapper = new MapBuilder();
            [$code, , $err] = $this->analyze($args, $this->answers(self::finding()), $mapper);
            self::assertSame(2, $code, $message);
            self::assertSame("Error: {$message}\n", $err);
            self::assertSame(0, $mapper->parses(), "{$message}: fails before the project is parsed");
        }
        self::assertSame([], $this->requests);
    }

    public function testConfigFileErrorsStillNameTheKey(): void
    {
        file_put_contents($this->root.'/semantic-sec.yaml', "level: severe\n");
        [$code, , $err] = $this->analyze([], $this->answers(self::finding()));

        self::assertSame(2, $code);
        self::assertSame("Error: Config key \"level\" must be one of: low, medium, high, critical.\n", $err);
    }

    public function testMissingKeyFailsBeforeParsing(): void
    {
        $saved = getenv('ANTHROPIC_API_KEY');
        putenv('ANTHROPIC_API_KEY');
        $mapper = new MapBuilder();
        try {
            $t = new CommandTester(new AnalyzeCommand(null, new AnalysisPipeline($mapper)));
            $code = $t->execute(['--project-root' => $this->root], ['capture_stderr_separately' => true]);
        } finally {
            $saved === false ? putenv('ANTHROPIC_API_KEY') : putenv('ANTHROPIC_API_KEY='.$saved);
        }

        self::assertSame(2, $code);
        self::assertSame("Error: ANTHROPIC_API_KEY is not set\n", $t->getErrorOutput());
        self::assertSame(0, $mapper->parses());
    }

    public function testDryRunSarifIsRejected(): void
    {
        [$code, , $err] = $this->analyze(['--dry-run' => true, '--format' => 'sarif'], $this->answers(self::finding()));

        self::assertSame(2, $code);
        self::assertSame("Error: --format sarif cannot be used with --dry-run\n", $err);
    }

    public function testDryRunGitlabSastIsRejected(): void
    {
        [$code, , $err] = $this->analyze(['--dry-run' => true, '--format' => 'gitlab-sast'], $this->answers(self::finding()));

        self::assertSame(2, $code);
        self::assertSame("Error: --format gitlab-sast cannot be used with --dry-run\n", $err);
    }

    public function testPartialResultsWrittenOnBudget(): void
    {
        // A low-confidence finding comes back before the budget runs out: exit 3, and the finding is still printed.
        [$code, $out, $err] = $this->analyze(['--concurrency' => '1', '--budget' => '1000000'], $this->answers([...self::finding(), 'confidence' => 'low'], 990_000));

        self::assertSame(3, $code, $err);
        self::assertStringContainsString('Confidence:    low (not failing)', $out);
        self::assertMatchesRegularExpression('~ok\s+2\b~', $out);
        self::assertMatchesRegularExpression('~unsent\s+12\b~', $out);
    }

    public function testCacheSymlinkIsExitTwo(): void
    {
        mkdir($this->base.'/elsewhere');
        mkdir($this->root.'/.semantic-sec');
        symlink($this->base.'/elsewhere', $this->root.'/.semantic-sec/cache');

        [$code, , $err] = $this->analyze([], $this->answers(self::finding()));

        self::assertSame(2, $code);
        self::assertStringStartsWith('Error: ', $err);
        self::assertStringContainsString('symlink', $err);
        self::assertSame([], $this->requests);
        self::assertSame(['.', '..'], scandir($this->base.'/elsewhere'));
    }

    public function testSecondRunIsServedFromTheCache(): void
    {
        $this->analyze([], $this->answers(self::finding()));
        $this->requests = [];
        [$code, $out] = $this->analyze([], $this->answers(self::finding()));

        self::assertSame(1, $code);
        self::assertSame([], $this->requests);
        self::assertMatchesRegularExpression('~cache hits\s+14\b~', $out);
    }

    public function testCorruptCacheEntryWarningNamesItsShortKey(): void
    {
        $this->analyze([], $this->answers(self::finding()));
        $entries = glob($this->root.'/.semantic-sec/cache/*.json') ?: [];
        self::assertCount(14, $entries);
        file_put_contents($entries[0], '{not json');
        $short = substr(basename($entries[0], '.json'), 0, 12);

        [, $out] = $this->analyze([], $this->answers(self::finding()));

        self::assertStringContainsString("cache entry {$short}… ignored", $out);
        self::assertStringNotContainsString('<redacted>', substr($out, (int) strpos($out, "\nWarnings\n")), 'the cache key is not redacted');
    }

    public function testEngineThrowableIsExitTwoWithASafeLine(): void
    {
        $boom = static fn (): never => throw new \LogicException("duplicate payload id \e[31m<error>x</error>\nsecond line");
        $t = new CommandTester(new AnalyzeCommand(fn (Config $c): ClientInterface => new FakeClient([]), null, $boom));

        $code = $t->execute(['--project-root' => $this->root], ['capture_stderr_separately' => true]);

        self::assertSame(2, $code);
        self::assertSame("Error: analysis failed: duplicate payload id  [31m<error>x</error> second line\n", $t->getErrorOutput());
        self::assertStringNotContainsString("\e", $t->getErrorOutput());
    }

    public function testModelTextIsStrippedOfControlCharacters(): void
    {
        $finding = [...self::finding(), 'title' => "Evil \e[2J\e]0;pwned\x07 title <error>x</error>"];
        [$code, $out] = $this->analyze([], $this->answers($finding));

        self::assertSame(1, $code);
        self::assertStringNotContainsString("\e", $out);
        self::assertStringNotContainsString("\x07", $out);
        self::assertStringContainsString('<error>x</error>', $out, 'console tags are printed, not interpreted');
    }

    public function testSinglePipelineParse(): void
    {
        $mapper = new MapBuilder();
        [$code] = $this->analyze([], $this->answers(self::finding()), $mapper);

        self::assertSame(1, $code);
        self::assertSame(1, $mapper->parses());
    }

    public function testDryRunStillNeedsNoKey(): void
    {
        $t = new CommandTester(new AnalyzeCommand());
        self::assertSame(0, $t->execute(['--project-root' => $this->root, '--dry-run' => true, '--format' => 'json']));
        self::assertFileExists($this->root.'/.semantic-sec/dry-run/000-system.txt');
    }

    /**
     * Runs analyze with an injected provider client; every request is recorded.
     *
     * @param  array<string, string|bool>  $args
     * @param  \Closure(LlmRequest): (LlmResponse|LlmException)  $answer
     * @return array{int, string, string}
     */
    private function analyze(array $args, \Closure $answer, ?MapBuilder $mapper = null): array
    {
        $record = function (LlmRequest $r) use ($answer): LlmResponse|LlmException {
            $this->requests[] = $r;

            return $answer($r);
        };
        $client = new class ($record) implements ClientInterface {
            public function __construct(private readonly \Closure $answer)
            {
            }

            public function analyze(LlmRequest $request): PromiseInterface
            {
                $a = ($this->answer)($request);

                return $a instanceof LlmException ? Create::rejectionFor($a) : Create::promiseFor($a);
            }
        };
        $provider = function (Config $c) use ($client): ClientInterface {
            $this->configs[] = $c;

            return $client;
        };

        NetworkTrap::install();
        try {
            $t = new CommandTester(new AnalyzeCommand($provider, new AnalysisPipeline($mapper)));
            $code = $t->execute(['--project-root' => $this->root, ...$args], ['capture_stderr_separately' => true]);
        } finally {
            self::assertSame([], NetworkTrap::uninstall(), 'no network');
        }

        return [$code, $t->getDisplay(), $t->getErrorOutput()];
    }

    /**
     * The vulnerable payload answers with $finding; every other payload answers with none.
     *
     * @param  array<string, mixed>  $finding
     * @return \Closure(LlmRequest): LlmResponse
     */
    private function answers(array $finding, int $vulnTokens = 100): \Closure
    {
        return static fn (LlmRequest $r): LlmResponse => str_ends_with($r->payloadId, self::VULN)
            ? new LlmResponse($r->payloadId, LlmOutcome::Ok, ['findings' => [$finding]], $vulnTokens, 10, $r->model)
            : new LlmResponse($r->payloadId, LlmOutcome::Ok, ['findings' => []], 100, 10, $r->model);
    }

    /** @return array<string, mixed> the finding the live model returned for this route */
    private static function finding(): array
    {
        $cassette = json_decode((string) file_get_contents(self::FIXTURES.'/live-idor-find-by-id.json'), true, 512, JSON_THROW_ON_ERROR);
        $message = json_decode($cassette['interactions'][0]['response']['body'], true, 512, JSON_THROW_ON_ERROR);
        $data = JsonOutput::decode($message['content'][0]['text']);
        self::assertIsArray($data);

        return $data['findings'][0];
    }
}
