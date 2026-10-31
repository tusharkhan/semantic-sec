<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Console\Commands;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use TusharKhan\SemanticSec\Analysis\Category;
use TusharKhan\SemanticSec\Candidates\Candidate;
use TusharKhan\SemanticSec\Config\ConfigException;
use TusharKhan\SemanticSec\Console\AnalysisPipeline;
use TusharKhan\SemanticSec\Console\ExitCode;
use TusharKhan\SemanticSec\Framework\FrameworkNotDetected;
use TusharKhan\SemanticSec\Payload\Payload;
use TusharKhan\SemanticSec\Payload\Redactor;

#[AsCommand(name: 'analyze', description: 'Select candidate routes and build their LLM payloads (M4: --dry-run only)')]
final class AnalyzeCommand extends Command
{
    use ProjectOptions;

    public const DRY_RUN_DIR = '.semantic-sec/dry-run';

    protected function configure(): void
    {
        $this
            ->addArgument('paths', InputArgument::IS_ARRAY | InputArgument::OPTIONAL, 'Limit which candidates are reported (default: whole project)')
            ->addOption('project-root', null, InputOption::VALUE_REQUIRED, 'Project root (default: current directory)')
            ->addOption('config', null, InputOption::VALUE_REQUIRED, 'Path to semantic-sec.yaml')
            ->addOption('framework', null, InputOption::VALUE_REQUIRED, 'Force the framework (laravel)')
            ->addOption('deep', null, InputOption::VALUE_NONE, 'Do not exclude routes that have an authorization check')
            ->addOption('dry-run', null, InputOption::VALUE_NONE, 'Write every payload to .semantic-sec/dry-run; no network, no API key')
            ->addOption('format', null, InputOption::VALUE_REQUIRED, 'console or json (the summary)', 'console');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $format = (string) $input->getOption('format');
        if (! in_array($format, ['console', 'json'], true)) {
            return $this->fail($output, '--format must be console or json');
        }
        if ($input->getOption('dry-run') !== true) {
            return $this->fail($output, 'analysis needs the LLM layer (M5); use --dry-run');
        }

        $root = $this->resolveRoot($input->getOption('project-root'));
        if ($root === null) {
            return $this->fail($output, 'Project root does not exist: '.(string) $input->getOption('project-root'));
        }
        $paths = $this->paths($root, $input->getArgument('paths'));

        try {
            [$results, $warnings] = (new AnalysisPipeline())->run(
                $root,
                $this->stringOption($input, 'config'),
                $this->stringOption($input, 'framework'),
                $input->getOption('deep') === true,
                $paths,
            );
        } catch (ConfigException|FrameworkNotDetected $e) {
            return $this->fail($output, $e->getMessage());
        }

        $dir = $root.'/'.self::DRY_RUN_DIR;
        try {
            $this->write($dir, $results);
        } catch (\RuntimeException $e) {
            return $this->fail($output, $e->getMessage());
        }

        $rows = $this->rows($results);
        if ($format === 'json') {
            $output->writeln(json_encode([
                'summary' => [
                    'candidates' => count($rows),
                    'payloads' => array_sum(array_map(static fn (array $r): int => count($r['payloads']), $rows)),
                    'tokens' => array_sum(array_column($rows, 'tokens')),
                    'directory' => $dir,
                ],
                'candidates' => $rows,
                'warnings' => $warnings,
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR));
        } else {
            $this->renderConsole($output, $rows, $warnings, $dir);
        }

        return ExitCode::OK;
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
    private function write(string $dir, array $results): void
    {
        self::remove($dir);
        if (! @mkdir($dir, 0777, true) && ! is_dir($dir)) {
            throw new \RuntimeException('Cannot create '.$dir);
        }
        foreach ($results as $result) {
            foreach ($result['payloads'] as $payload) {
                $file = $dir.'/'.$payload->id.'.txt';
                if (@file_put_contents($file, $payload->text()."\n") === false) {
                    throw new \RuntimeException('Cannot write '.$file);
                }
            }
        }
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
    private function rows(array $results): array
    {
        $redactor = new Redactor();
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
    private function renderConsole(OutputInterface $output, array $rows, array $warnings, string $dir): void
    {
        $table = new Table($output);
        $table->setHeaders(['#', 'Route', 'Categories', 'Parts', 'Tokens']);
        $payloads = $tokens = 0;
        foreach ($rows as $row) {
            $table->addRow([sprintf('%03d', $row['number']), $row['route'], implode(', ', $row['categories']), count($row['payloads']), $row['tokens']]);
            $payloads += count($row['payloads']);
            $tokens += $row['tokens'];
        }
        $table->render();

        $output->writeln(sprintf('%d candidates, %d payloads, ~%d tokens; written to %s', count($rows), $payloads, $tokens, $dir));

        if ($warnings !== []) {
            $output->writeln('');
            $output->writeln('Warnings');
            foreach ($warnings as $warning) {
                $output->writeln('  '.$warning);
            }
        }
    }
}
