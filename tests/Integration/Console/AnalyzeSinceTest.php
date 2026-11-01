<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Integration\Console;

use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Tester\CommandTester;
use TusharKhan\SemanticSec\Config\Config;
use TusharKhan\SemanticSec\Console\Commands\AnalyzeCommand;
use TusharKhan\SemanticSec\Llm\ClientInterface;
use TusharKhan\SemanticSec\Llm\LlmOutcome;
use TusharKhan\SemanticSec\Llm\LlmRequest;
use TusharKhan\SemanticSec\Llm\LlmResponse;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;
use TusharKhan\SemanticSec\Tests\Support\GitRepo;
use TusharKhan\SemanticSec\Tests\Support\NetworkTrap;

final class AnalyzeSinceTest extends TestCase
{
    private const VULN = '-get-vuln-invoices-id-1';

    private const CONTROLLER = 'app/Http/Controllers/Vuln/InvoiceController.php';

    private string $base;

    private string $root;

    /** @var list<LlmRequest> */
    private array $requests = [];

    protected function setUp(): void
    {
        $this->base = sys_get_temp_dir().'/semsec-since-'.bin2hex(random_bytes(4));
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

    public function testOnlyAffectedPayloadsSent(): void
    {
        $this->history(fn () => file_put_contents($this->root.'/'.self::CONTROLLER, "\n// touched\n", FILE_APPEND));

        [$code, $out, $err] = $this->analyze(['--since' => 'HEAD~1', '--format' => 'json']);

        self::assertSame(0, $code, $err);
        $summary = json_decode($out, true, 512, JSON_THROW_ON_ERROR)['summary'];
        self::assertSame(14, $summary['payloads']);
        self::assertSame(3, $summary['sent'], 'the three Vuln\InvoiceController routes');
        self::assertSame(11, $summary['unaffected']);
        self::assertSame($summary['payloads'], $summary['skipped'] + $summary['unaffected'] + $summary['unsent'] + $summary['cacheHits'] + $summary['sent']);
        self::assertCount(3, $this->requests);
        self::assertCount(1, array_filter($this->requests, static fn (LlmRequest $r): bool => str_ends_with($r->payloadId, self::VULN)));
        self::assertMatchesRegularExpression('~unaffected\s+11 \(--since\)~', $err);
    }

    public function testStatsIdentityWithUnaffected(): void
    {
        $this->history(fn () => file_put_contents($this->root.'/'.self::CONTROLLER, "\n// touched\n", FILE_APPEND));

        [$code, $out, $err] = $this->analyze(['--since' => 'HEAD~1', '--format' => 'sarif']);

        self::assertSame(0, $code, $err);
        $s = json_decode($out, true, 512, JSON_THROW_ON_ERROR)['runs'][0]['properties']['summary'];
        self::assertSame(11, $s['unaffected']);
        self::assertSame($s['payloads'], $s['skipped'] + $s['unaffected'] + $s['unsent'] + $s['cacheHits'] + $s['sent']);
    }

    public function testUnrelatedChangeSendsNothingExitZero(): void
    {
        $this->history(function (): void {
            file_put_contents($this->root.'/README.md', "notes\n");
            GitRepo::write($this->root, 'app/Support/Unused.php', "<?php\nnamespace App\\Support;\n\nclass Unused\n{\n}\n");
            GitRepo::write($this->root, 'config/app.php', "<?php\n\nreturn ['name' => 'x'];\n");
        });

        [$code, $out, $err] = $this->analyze(['--since' => 'HEAD~1']);

        self::assertSame(0, $code, $err);
        self::assertSame([], $this->requests);
        self::assertMatchesRegularExpression('~unaffected\s+14 \(--since\)~', $out);
        self::assertMatchesRegularExpression('~sent\s+0\b~', $out);
    }

    public function testGlobalFileWidensToAll(): void
    {
        $this->history(fn () => file_put_contents($this->root.'/bootstrap/app.php', "\n// touched\n", FILE_APPEND));

        [$code, $out, $err] = $this->analyze(['--since' => 'HEAD~1']);

        self::assertSame(0, $code, $err);
        self::assertCount(14, $this->requests);
        self::assertMatchesRegularExpression('~unaffected\s+0 \(--since\)~', $out);
    }

    public function testBadRefExitTwo(): void
    {
        $this->history(static fn () => null);

        [$code, , $err] = $this->analyze(['--since' => 'no-such-branch']);

        self::assertSame(2, $code);
        self::assertSame("Error: unknown git ref: no-such-branch\n", $err);
        self::assertSame([], $this->requests);
    }

    public function testRefStartingWithDashRejected(): void
    {
        // No repository: the ref is refused before git, or the project, is touched.
        [$code, , $err] = $this->analyze(['--since' => '--output=/tmp/x']);

        self::assertSame(2, $code);
        self::assertStringStartsWith('Error: --since must be a git ref', $err);
        self::assertSame([], $this->requests);
        self::assertDirectoryDoesNotExist($this->root.'/.semantic-sec');
    }

    public function testNotARepoExitTwo(): void
    {
        [$code, , $err] = $this->analyze(['--since' => 'HEAD~1']);

        self::assertSame(2, $code);
        self::assertStringContainsString('is not a git repository', $err);
        self::assertSame([], $this->requests);
    }

    public function testSinceWithGenerateBaselineExitTwo(): void
    {
        $this->history(static fn () => null);

        [$code, , $err] = $this->analyze(['--since' => 'HEAD~1', '--generate-baseline' => true]);

        self::assertSame(2, $code);
        self::assertSame("Error: --since cannot be combined with --generate-baseline; a baseline must cover every finding\n", $err);
        self::assertFileDoesNotExist($this->root.'/semantic-sec-baseline.json');
    }

    public function testDryRunWritesOnlyAffectedPayloads(): void
    {
        $this->history(fn () => file_put_contents($this->root.'/'.self::CONTROLLER, "\n// touched\n", FILE_APPEND));

        $t = new CommandTester(new AnalyzeCommand());
        $code = $t->execute(['--project-root' => $this->root, '--dry-run' => true, '--since' => 'HEAD~1', '--format' => 'json'], ['capture_stderr_separately' => true]);

        self::assertSame(0, $code, $t->getErrorOutput());
        $files = array_values(array_diff(scandir($this->root.'/'.AnalyzeCommand::DRY_RUN_DIR) ?: [], ['.', '..']));
        self::assertCount(4, $files, 'the system prompt and three payloads');
        self::assertSame(AnalyzeCommand::SYSTEM_FILE, $files[0]);
        self::assertCount(1, array_filter($files, static fn (string $f): bool => str_ends_with($f, self::VULN.'.txt')));
        $doc = json_decode($t->getDisplay(), true, 512, JSON_THROW_ON_ERROR);
        // Counted like the engine summary: every candidate and payload, the left-out ones as unaffected.
        self::assertSame([14, 14, 11], [$doc['summary']['candidates'], $doc['summary']['payloads'], $doc['summary']['unaffected']]);
        self::assertCount(3, $doc['candidates'], 'only the affected candidates are listed');
    }

    public function testDryRunConsoleNamesUnaffected(): void
    {
        $this->history(fn () => file_put_contents($this->root.'/'.self::CONTROLLER, "\n// touched\n", FILE_APPEND));

        $t = new CommandTester(new AnalyzeCommand());
        $code = $t->execute(['--project-root' => $this->root, '--dry-run' => true, '--since' => 'HEAD~1'], ['capture_stderr_separately' => true]);

        self::assertSame(0, $code, $t->getErrorOutput());
        self::assertStringContainsString('3 of 14 candidates affected since HEAD~1; 11 unaffected payloads not written', $t->getDisplay());
    }

    // Commits the app, applies $change, commits again.
    private function history(\Closure $change): void
    {
        GitRepo::init($this->root);
        GitRepo::commitAll($this->root, 'base');
        $change();
        GitRepo::commitAll($this->root, 'change');
    }

    /**
     * @param  array<string, string|bool>  $args
     * @return array{int, string, string}
     */
    private function analyze(array $args): array
    {
        $record = function (LlmRequest $request): void {
            $this->requests[] = $request;
        };
        $client = new class ($record) implements ClientInterface {
            /** @param \Closure(LlmRequest): void $record */
            public function __construct(private readonly \Closure $record)
            {
            }

            public function analyze(LlmRequest $request): PromiseInterface
            {
                ($this->record)($request);

                return Create::promiseFor(new LlmResponse($request->payloadId, LlmOutcome::Ok, ['findings' => []], 100, 10, $request->model));
            }
        };

        NetworkTrap::install();
        try {
            $t = new CommandTester(new AnalyzeCommand(static fn (Config $c): ClientInterface => $client));
            $code = $t->execute(['--project-root' => $this->root, '--no-cache' => true, ...$args], ['capture_stderr_separately' => true]);
        } finally {
            self::assertSame([], NetworkTrap::uninstall(), 'no network');
        }

        return [$code, $t->getDisplay(), $t->getErrorOutput()];
    }
}
