<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Console\Commands;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use TusharKhan\SemanticSec\Analysis\Category;
use TusharKhan\SemanticSec\Candidates\Candidate;
use TusharKhan\SemanticSec\Config\Config;
use TusharKhan\SemanticSec\Config\ConfigException;
use TusharKhan\SemanticSec\Config\ConfigLoader;
use TusharKhan\SemanticSec\Config\Defaults;
use TusharKhan\SemanticSec\Console\AnalysisPipeline;
use TusharKhan\SemanticSec\Console\Application;
use TusharKhan\SemanticSec\Console\ExitCode;
use TusharKhan\SemanticSec\Console\OutputDir;
use TusharKhan\SemanticSec\Console\PipelineResult;
use TusharKhan\SemanticSec\Console\Terminal;
use TusharKhan\SemanticSec\Engine\AnalysisResult;
use TusharKhan\SemanticSec\Engine\Baseline;
use TusharKhan\SemanticSec\Engine\Engine;
use TusharKhan\SemanticSec\Engine\Fingerprinter;
use TusharKhan\SemanticSec\Engine\ResultCache;
use TusharKhan\SemanticSec\Framework\FrameworkNotDetected;
use TusharKhan\SemanticSec\Llm\ClientFactory;
use TusharKhan\SemanticSec\Llm\ClientInterface;
use TusharKhan\SemanticSec\Llm\GroundingChecker;
use TusharKhan\SemanticSec\Llm\ValidatingClient;
use TusharKhan\SemanticSec\Output\BaselineFile;
use TusharKhan\SemanticSec\Output\ConsoleFormatter;
use TusharKhan\SemanticSec\Output\JsonFormatter;
use TusharKhan\SemanticSec\Output\SafeWriter;
use TusharKhan\SemanticSec\Output\SarifFormatter;
use TusharKhan\SemanticSec\Payload\Payload;
use TusharKhan\SemanticSec\Payload\Redactor;
use TusharKhan\SemanticSec\Since\ChangedFiles;
use TusharKhan\SemanticSec\Since\ImpactAnalyzer;

#[AsCommand(name: 'analyze', description: 'Find authorization flaws: map, select candidates, build payloads, then ask the LLM')]
class AnalyzeCommand extends Command
{
    use ProjectOptions;

    // CLI option => Config::with() key.
    private const OVERRIDES = ['level' => 'level', 'min-confidence' => 'min_confidence', 'provider' => 'provider', 'model' => 'model', 'concurrency' => 'concurrency', 'budget' => 'budget_tokens'];

    public const DRY_RUN_DIR = '.semantic-sec/dry-run';

    // Sorts before every payload file, whose ids start at 001.
    public const SYSTEM_FILE = '000-system.txt';

    /**
     * @param  (\Closure(Config): ClientInterface)|null  $providerClient  test seam: replaces the provider client under ValidatingClient
     * @param  (\Closure(Engine, list<Payload>, int, int): AnalysisResult)|null  $runEngine  test seam: replaces Engine::run
     */
    public function __construct(
        private readonly ?\Closure $providerClient = null,
        private readonly ?AnalysisPipeline $pipeline = null,
        private readonly ?\Closure $runEngine = null,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addArgument('paths', InputArgument::IS_ARRAY | InputArgument::OPTIONAL, 'Limit which candidates are reported (default: whole project)')
            ->addOption('project-root', null, InputOption::VALUE_REQUIRED, 'Project root (default: current directory)')
            ->addOption('config', null, InputOption::VALUE_REQUIRED, 'Path to semantic-sec.yaml')
            ->addOption('framework', null, InputOption::VALUE_REQUIRED, 'Force the framework (laravel)')
            ->addOption('deep', null, InputOption::VALUE_NONE, 'Do not exclude routes that have an authorization check')
            ->addOption('dry-run', null, InputOption::VALUE_NONE, 'Write the system prompt and every payload to .semantic-sec/dry-run; no network, no API key')
            ->addOption('level', null, InputOption::VALUE_REQUIRED, 'Minimum severity to report and fail on: low, medium, high, critical (config: level, default high)')
            ->addOption('min-confidence', null, InputOption::VALUE_REQUIRED, 'Below this confidence a finding is reported but never fails: low, medium, high (config: min_confidence, default medium)')
            ->addOption('provider', null, InputOption::VALUE_REQUIRED, 'anthropic, openai or ollama (config: provider)')
            ->addOption('model', null, InputOption::VALUE_REQUIRED, 'Model id (config: model)')
            ->addOption('concurrency', null, InputOption::VALUE_REQUIRED, 'Parallel requests (config: concurrency, default 5)')
            ->addOption('budget', null, InputOption::VALUE_REQUIRED, 'Hard cap on provider tokens; below one request\'s reservation (~35k at the default max_tokens) nothing is sent (config: budget_tokens)')
            ->addOption('no-cache', null, InputOption::VALUE_NONE, 'Ignore cached answers (new answers are still cached)')
            ->addOption('strict', null, InputOption::VALUE_NONE, 'Exit 2 if any request failed, was refused, invalid or truncated, or any payload went unsent (ignored with --dry-run)')
            ->addOption('format', null, InputOption::VALUE_REQUIRED, 'console, json or sarif', 'console')
            ->addOption('output', null, InputOption::VALUE_REQUIRED, 'Write the report to this file (never through a symlink); the summary and warnings go to stderr')
            ->addOption('baseline', null, InputOption::VALUE_REQUIRED, 'Baseline file: findings whose fingerprint is in it are baselined, not reported (default: semantic-sec-baseline.json in the project root, if present)')
            ->addOption('generate-baseline', null, InputOption::VALUE_NONE, 'Write every current finding\'s fingerprint to the baseline file and exit 0')
            ->addOption('since', null, InputOption::VALUE_REQUIRED, 'Send only candidates that committed changes since this git ref (<ref>...HEAD) can affect')
            ->setHelp(<<<'HELP'
                Maps the project, selects candidate routes, builds their payloads and sends each one to the LLM.
                Findings are grounded in the payload, fingerprinted, then filtered by suppressions, --level and --min-confidence.

                Exit codes: 0 clean, 1 a failing finding, 2 tool error (config, no framework, missing API key,
                every request failed), 3 token budget exceeded with no failing finding. 1 beats 3.
                --strict also exits 2 when any request failed, was refused, invalid or truncated, or any payload
                went unsent. Precedence: 1 > strict 2 > 3 > all-failed 2 > 0.

                --budget is a hard cap: before each request the pool reserves twice the prompt plus max_tokens,
                so a budget below one reservation (~35k tokens at the default max_tokens) sends nothing and exits 3.

                --dry-run writes the system prompt and every payload to .semantic-sec/dry-run and needs no API key.

                --since=<ref> sends only the candidates that files committed since <ref> (git diff <ref>...HEAD) can affect;
                uncommitted changes are ignored. It cannot be combined with --generate-baseline.

                --baseline reads fingerprints to accept (default semantic-sec-baseline.json in the project root, if present).
                --generate-baseline writes every reported, non-failing and below-level finding's fingerprint there instead
                and exits 0 unless every request failed (or --strict trips); `semantic-sec baseline` is the same.
                HELP);
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $dryRun = $input->getOption('dry-run') === true;
        $format = (string) $input->getOption('format');
        $generate = $this->generatesBaseline($input);
        if ($dryRun && $generate) {
            return $this->fail($output, '--generate-baseline cannot be used with --dry-run');
        }
        $since = $input->getOption('since');
        if ($since !== null) {
            if ($generate) {
                return $this->fail($output, '--since cannot be combined with --generate-baseline; a baseline must cover every finding');
            }
            try {
                ChangedFiles::validate((string) $since);
            } catch (\RuntimeException $e) {
                return $this->fail($output, $e->getMessage());
            }
        }
        if ($dryRun && $input->getOption('output') !== null) {
            return $this->fail($output, '--output cannot be used with --dry-run');
        }
        if ($format !== 'console' && $format !== 'json' && $format !== 'sarif') {
            return $this->fail($output, '--format must be console, json or sarif');
        }
        if ($dryRun && $format === 'sarif') {
            return $this->fail($output, '--format sarif cannot be used with --dry-run');
        }
        $report = $this->stringOption($input, 'output');
        if ($report !== null) {
            try {
                SafeWriter::check($report);
            } catch (\RuntimeException $e) {
                return $this->fail($output, (new Redactor())->redact($e->getMessage()));
            }
        }
        $overrides = [];
        foreach (self::OVERRIDES as $option => $key) {
            $value = $input->getOption($option);
            if ($value !== null) {
                $overrides[$key] = $value;
            }
        }

        if ($input->getOption('project-root') === '') {
            return $this->fail($output, '--project-root must not be empty');
        }
        $root = $this->resolveRoot($input->getOption('project-root'));
        if ($root === null) {
            return $this->fail($output, 'Project root does not exist: '.(string) $input->getOption('project-root'));
        }
        $paths = $this->paths($root, $input->getArgument('paths'));
        $baselinePath = $this->stringOption($input, 'baseline') ?? $root.'/'.BaselineFile::DEFAULT;
        $baseline = Baseline::empty();
        if (! $dryRun) {
            try {
                if ($generate) {
                    SafeWriter::check($baselinePath);
                } else {
                    $baseline = BaselineFile::load($baselinePath, $this->stringOption($input, 'baseline') !== null);
                }
            } catch (\RuntimeException $e) {
                return $this->fail($output, (new Redactor())->redact($e->getMessage()));
            }
        }

        // Flags, config and key are checked before the project is parsed, so a mistake fails fast.
        try {
            $config = (new ConfigLoader())->load($root, $this->stringOption($input, 'config'))->with($overrides, self::flagNames());
            if (! $dryRun) {
                $client = $this->providerClient === null ? ClientFactory::validated($config) : new ValidatingClient(($this->providerClient)($config));

                return $this->analyze($input, $output, $root, $paths, $overrides, $config, $client, $baseline, $generate ? $baselinePath : null);
            }
        } catch (ConfigException $e) {
            return $this->fail($output, $e->getMessage());
        }
        $dir = $root.'/'.self::DRY_RUN_DIR;
        $redactor = new Redactor();
        try {
            OutputDir::check($root, self::DRY_RUN_DIR);
        } catch (\RuntimeException $e) {
            return $this->fail($output, $redactor->redact($e->getMessage()));
        }

        try {
            $run = ($this->pipeline ?? new AnalysisPipeline())->run(
                $root,
                $this->stringOption($input, 'config'),
                $this->stringOption($input, 'framework'),
                $input->getOption('deep') === true,
                $paths,
                $overrides,
                $config,
            );
        } catch (ConfigException|FrameworkNotDetected $e) {
            return $this->fail($output, $e->getMessage());
        }
        [$results, $warnings, $system] = [$run->results, $run->warnings, $run->system];
        $unaffected = 0;
        if ($since !== null) {
            try {
                [$results, $unaffected] = $this->since($root, (string) $since, $run);
            } catch (\RuntimeException $e) {
                return $this->fail($output, Terminal::clean($redactor->redact($e->getMessage())));
            }
        }

        try {
            $this->write($root, $results, $system);
        } catch (\RuntimeException $e) {
            return $this->fail($output, $redactor->redact($e->getMessage()));
        }

        $rows = $this->rows($results, $redactor);
        $warnings = array_map($redactor->redact(...), $warnings);
        $dir = $redactor->redact($dir);
        if ($format === 'json') {
            $output->writeln(json_encode([
                'summary' => [
                    'candidates' => count($rows),
                    'payloads' => array_sum(array_map(static fn (array $r): int => count($r['payloads']), $rows)),
                    'tokens' => array_sum(array_column($rows, 'tokens')),
                    'unaffected' => $unaffected,
                    'directory' => $dir,
                    'system' => self::SYSTEM_FILE,
                ],
                'candidates' => $rows,
                'warnings' => $warnings,
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR));
        } else {
            $this->renderConsole($output, $rows, $warnings, $dir, $since === null ? null : $unaffected);
        }

        return ExitCode::OK;
    }

    /**
     * The engine run: one pipeline parse, the validated client, the cache, then findings and the exit code.
     *
     * @param  list<string>|null  $paths
     * @param  array<string, mixed>  $overrides
     * @param  string|null  $generate  the baseline file to write, or null to only read $baseline
     */
    private function analyze(InputInterface $input, OutputInterface $output, string $root, ?array $paths, array $overrides, Config $config, ClientInterface $client, Baseline $baseline, ?string $generate): int
    {
        $redactor = new Redactor();
        try {
            OutputDir::check($root, ResultCache::DIR);
        } catch (\RuntimeException $e) {
            return $this->fail($output, $redactor->redact($e->getMessage()));
        }

        try {
            $run = ($this->pipeline ?? new AnalysisPipeline())->run(
                $root,
                $this->stringOption($input, 'config'),
                $this->stringOption($input, 'framework'),
                $input->getOption('deep') === true,
                $paths,
                $overrides,
                $config,
            );
            $config = $run->project->config;
        } catch (ConfigException|FrameworkNotDetected $e) {
            return $this->fail($output, $e->getMessage());
        }

        try {
            $cache = ResultCache::inProject($root, $config, $run->system, $input->getOption('no-cache') !== true);
        } catch (\RuntimeException $e) {
            return $this->fail($output, $redactor->redact($e->getMessage()));
        }

        $results = $run->results;
        $unaffected = 0;
        $since = $input->getOption('since');
        if ($since !== null) {
            try {
                [$results, $unaffected] = $this->since($root, (string) $since, $run);
            } catch (\RuntimeException $e) {
                return $this->fail($output, Terminal::clean($redactor->redact($e->getMessage())));
            }
        }
        $payloads = [];
        foreach ($results as $r) {
            array_push($payloads, ...$r['payloads']);
        }

        $project = $run->project;
        $engine = new Engine($client, $cache, new Fingerprinter($project->parsed, $project->symbols), new GroundingChecker($project->symbols), $project->parsed, $config, $baseline);
        try {
            $result = $this->runEngine === null ? $engine->run($payloads, count($run->results), $unaffected) : ($this->runEngine)($engine, $payloads, count($run->results), $unaffected);
        } catch (\Throwable $e) {
            return $this->fail($output, 'analysis failed: '.Terminal::clean($redactor->redact($e->getMessage())));
        }

        $strict = $input->getOption('strict') === true;
        $warnings = array_map($redactor->redact(...), [...$run->warnings, ...$result->warnings]);
        $report = new AnalysisResult($result->findings, $result->suppressed, $result->baselined, $warnings, $result->stats, $result->filtered);
        // A generating run exits 0 whatever the findings; only all-failed or --strict still exit 2, and then nothing is written.
        $decides = $generate === null ? $result : new AnalysisResult([], [], [], [], $result->stats);
        $exit = ExitCode::for($decides, $strict);
        $exit = $generate !== null && $exit === ExitCode::BUDGET ? ExitCode::OK : $exit;
        $wrote = null;
        if ($generate !== null && $exit === ExitCode::OK) {
            try {
                $wrote = sprintf('wrote %d fingerprints to %s', BaselineFile::write($generate, $result), Terminal::safe($generate));
            } catch (\RuntimeException $e) {
                return $this->fail($output, $redactor->redact($e->getMessage()));
            }
        }
        $meta = [
            'tool' => Application::NAME,
            'version' => Application::VERSION,
            'provider' => $config->provider,
            'model' => $config->model ?? Defaults::model($config->provider) ?? 'default',
            'strictReason' => ExitCode::strictReason($decides, $strict),
            'level' => $config->level->value,
            'budget' => $config->budgetTokens,
            'exitCode' => $exit,
        ];

        $file = $this->stringOption($input, 'output');
        $format = $input->getOption('format');
        $err = $output instanceof ConsoleOutputInterface ? $output->getErrorOutput() : $output;
        if ($file === null && $format === 'console') {
            $output->write((new ConsoleFormatter($output->isDecorated()))->format($report, $meta), false, OutputInterface::OUTPUT_RAW);
            $this->baselineLine($err, $generate, $wrote);

            return $exit;
        }
        $formatter = match ($format) {
            'json' => new JsonFormatter(),
            'sarif' => new SarifFormatter(),
            default => new ConsoleFormatter(),
        };
        $document = $formatter->format($report, $meta);
        if ($file === null) {
            $output->write($document, false, OutputInterface::OUTPUT_RAW);
        } else {
            try {
                SafeWriter::write($file, $document);
            } catch (\RuntimeException $e) {
                return $this->fail($output, $redactor->redact($e->getMessage()));
            }
        }
        $err->write((new ConsoleFormatter($err->isDecorated()))->summary($report, $meta), false, OutputInterface::OUTPUT_RAW);
        if ($file !== null) {
            $err->writeln('Report written to '.Terminal::safe($file));
        }
        $this->baselineLine($err, $generate, $wrote);

        return $exit;
    }

    /**
     * Keeps the candidates the files committed since $ref can affect; git runs after parsing, before any request.
     *
     * @return array{list<array{candidate: Candidate, payloads: list<Payload>}>, int} the kept results and how many payloads were left out
     */
    private function since(string $root, string $ref, PipelineResult $run): array
    {
        $changed = ChangedFiles::between($root, $ref);
        $project = $run->project;
        $affected = (new ImpactAnalyzer($project->parsed, $project->symbols, $project->config))->affected(array_column($run->results, 'candidate'), $changed);
        $kept = [];
        $unaffected = 0;
        foreach ($run->results as $result) {
            if (in_array($result['candidate'], $affected, true)) {
                $kept[] = $result;
            } else {
                $unaffected += count($result['payloads']);
            }
        }

        return [$kept, $unaffected];
    }

    // `semantic-sec baseline` overrides this; analyze generates only with --generate-baseline.
    protected function generatesBaseline(InputInterface $input): bool
    {
        return $input->getOption('generate-baseline') === true;
    }

    private function baselineLine(OutputInterface $err, ?string $generate, ?string $wrote): void
    {
        if ($generate !== null) {
            $err->writeln($wrote ?? 'Baseline not written: no request succeeded, or --strict failed the run');
        }
    }

    /** @return array<string, string> Config::with() key => the CLI flag its errors name */
    private static function flagNames(): array
    {
        $out = [];
        foreach (self::OVERRIDES as $option => $key) {
            $out[$key] = '--'.$option;
        }

        return $out;
    }

    /** @return list<string>|null project-relative paths, or null when none were given */
    private function paths(string $root, mixed $argument): ?array
    {
        if (! is_array($argument) || $argument === []) {
            return null;
        }
        $out = [];
        foreach ($argument as $path) {
            $path = (string) $path;
            if (! str_starts_with($path, '/')) {
                $cwd = getcwd();
                $absolute = realpath(($cwd === false ? '' : $cwd).'/'.$path);
                $path = $absolute !== false && str_starts_with($absolute.'/', $root.'/') ? $absolute : $path;
            }
            if ($path === $root || str_starts_with($path, $root.'/')) {
                $path = substr($path, strlen($root));
            }
            $out[] = trim((string) preg_replace('#^\./#', '', ltrim($path, '/')), '/');
        }

        return $out;
    }

    /** @param list<array{candidate: Candidate, payloads: list<Payload>}> $results */
    private function write(string $root, array $results, string $system): void
    {
        $dir = self::recreate($root);
        self::put($dir.'/'.self::SYSTEM_FILE, $system);
        foreach ($results as $result) {
            foreach ($result['payloads'] as $payload) {
                self::put($dir.'/'.$payload->id.'.txt', $payload->text()."\n");
            }
        }
    }

    // Creates the file, never overwriting one that appeared since the directory was emptied.
    private static function put(string $file, string $text): void
    {
        $handle = @fopen($file, 'x');
        if ($handle === false || @fwrite($handle, $text) === false) {
            throw new \RuntimeException('Cannot write '.$file);
        }
        fclose($handle);
    }

    // Empties dry-run by removing and recreating it, both behind the OutputDir guard.
    private static function recreate(string $root): string
    {
        OutputDir::check($root, self::DRY_RUN_DIR);
        if (file_exists($root.'/'.self::DRY_RUN_DIR)) {
            self::remove($root.'/'.self::DRY_RUN_DIR);
        }

        return OutputDir::prepare($root, self::DRY_RUN_DIR);
    }

    // Deletes the dry-run directory; a symlink is unlinked, never followed.
    private static function remove(string $path): void
    {
        if (is_link($path) || is_file($path)) {
            if (! @unlink($path)) {
                throw new \RuntimeException('Cannot remove '.$path);
            }

            return;
        }
        if (! is_dir($path)) {
            return;
        }
        foreach (scandir($path) ?: [] as $entry) {
            if ($entry !== '.' && $entry !== '..') {
                self::remove($path.'/'.$entry);
            }
        }
        if (! @rmdir($path)) {
            throw new \RuntimeException('Cannot remove '.$path);
        }
    }

    /**
     * @param  list<array{candidate: Candidate, payloads: list<Payload>}>  $results
     * @return list<array{number: int, route: string, categories: list<string>, tokens: int, payloads: list<array{id: string, file: string, part: int, parts: int, tokens: int, truncated: bool}>}>
     */
    private function rows(array $results, Redactor $redactor): array
    {
        $rows = [];
        foreach ($results as $i => $result) {
            $route = $result['candidate']->route;
            $payloads = [];
            foreach ($result['payloads'] as $payload) {
                $payloads[] = ['id' => $payload->id, 'file' => $payload->id.'.txt', 'part' => $payload->part, 'parts' => $payload->parts, 'tokens' => $payload->tokens(), 'truncated' => $payload->truncated];
            }
            $rows[] = [
                'number' => $i + 1,
                'route' => $redactor->redact(implode('|', $route->methods).' '.$route->uri),
                'categories' => array_map(static fn (Category $c): string => $c->value, $result['candidate']->categories),
                'tokens' => array_sum(array_column($payloads, 'tokens')),
                'payloads' => $payloads,
            ];
        }

        return $rows;
    }

    /**
     * @param  list<array{number: int, route: string, categories: list<string>, tokens: int, payloads: list<array<string, mixed>>}>  $rows
     * @param  list<string>  $warnings
     */
    private function renderConsole(OutputInterface $output, array $rows, array $warnings, string $dir, ?int $unaffected): void
    {
        $table = new Table($output);
        $table->setHeaders(['#', 'Route', 'Categories', 'Parts', 'Tokens']);
        $payloads = $tokens = 0;
        foreach ($rows as $row) {
            $table->addRow([sprintf('%03d', $row['number']), Terminal::safe($row['route']), implode(', ', $row['categories']), count($row['payloads']), $row['tokens']]);
            $payloads += count($row['payloads']);
            $tokens += $row['tokens'];
        }
        $table->render();

        $output->writeln(sprintf('%d candidates, %d payloads, ~%d tokens; written to %s', count($rows), $payloads, $tokens, Terminal::safe($dir)));
        if ($unaffected !== null) {
            $output->writeln(sprintf('%d payloads not written: unaffected since the --since ref', $unaffected));
        }

        if ($warnings !== []) {
            $output->writeln('');
            $output->writeln('Warnings');
            foreach ($warnings as $warning) {
                $output->writeln('  '.Terminal::safe($warning));
            }
        }
    }
}
