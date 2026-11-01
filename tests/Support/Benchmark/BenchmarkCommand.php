<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support\Benchmark;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use TusharKhan\SemanticSec\Llm\SecurityPrompt;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;

/** bin/benchmark: score semantic-sec on the benchmark corpus against the SPEC §15 gate (M8 Task 2). Dev only. */
#[AsCommand(name: 'benchmark', description: 'Score semantic-sec on benchmark/ against the SPEC §15 accuracy gate')]
final class BenchmarkCommand extends Command
{
    public const REPLAY_KEY = 'replay-key';

    public const LIVE_BUDGET = '300000';

    private const SETS = ['all', 'existing', 'blind'];

    // A live run always has a token cap per app: --budget, or LIVE_BUDGET.
    public static function budget(?string $option, bool $live): ?string
    {
        return $option ?? ($live ? self::LIVE_BUDGET : null);
    }

    protected function configure(): void
    {
        $this
            ->addOption('live', null, InputOption::VALUE_NONE, 'Call Anthropic with the key from .env.live and record the cassettes (controller only; costs money)')
            ->addOption('app', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Benchmark app to run (repeatable; default: every app with cases in --set)')
            ->addOption('set', null, InputOption::VALUE_REQUIRED, 'all, existing or blind', 'all')
            ->addOption('competitor', null, InputOption::VALUE_REQUIRED, 'Competitor eval_results.json to score as well (M8 Task 5)')
            ->addOption('out', null, InputOption::VALUE_REQUIRED, 'Report path, relative to the repository root', 'docs/benchmark-results.md')
            ->addOption('budget', null, InputOption::VALUE_REQUIRED, 'Passed to analyze --budget for each app (with --live, default '.self::LIVE_BUDGET.')')
            ->addOption('cassettes', null, InputOption::VALUE_REQUIRED, 'Cassette directory', 'tests/Fixtures/cassettes/anthropic');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $repo = dirname(BenchmarkCorpus::root());
        $set = (string) $input->getOption('set');
        if (! in_array($set, self::SETS, true)) {
            return $this->fail($output, '--set must be all, existing or blind');
        }
        if ($input->getOption('competitor') !== null) {
            return $this->fail($output, '--competitor is not wired yet; M8 Task 5 adds the converter');
        }
        $yaml = (string) file_get_contents(BenchmarkCorpus::root().'/expected.yaml');
        $cases = array_values(array_filter(ExpectedCases::load($yaml), static fn (BenchmarkCase $c): bool => $set === 'all' || $c->set === $set));
        $publics = array_values(array_filter(ExpectedCases::publicRoutes($yaml), static fn (PublicRoute $p): bool => $set === 'all' || $p->set === $set));
        $inScope = array_unique([...array_map(static fn (BenchmarkCase $c): string => $c->app, $cases), ...array_map(static fn (PublicRoute $p): string => $p->app, $publics)]);
        /** @var list<string> $requested */
        $requested = $input->getOption('app');
        foreach ($requested as $app) {
            if (! in_array($app, BenchmarkCorpus::APPS, true)) {
                return $this->fail($output, "unknown app {$app}; expected one of ".implode(', ', BenchmarkCorpus::APPS));
            }
        }
        $apps = array_values(array_filter(BenchmarkCorpus::APPS, static fn (string $a): bool => in_array($a, $inScope, true) && ($requested === [] || in_array($a, $requested, true))));
        if ($apps === []) {
            return $this->fail($output, 'no cases in scope for that --app and --set');
        }
        $cases = array_values(array_filter($cases, static fn (BenchmarkCase $c): bool => in_array($c->app, $apps, true)));
        $publics = array_values(array_filter($publics, static fn (PublicRoute $p): bool => in_array($p->app, $apps, true)));

        $dir = (string) $input->getOption('cassettes');
        $runner = new Runner(str_starts_with($dir, '/') ? $dir : $repo.'/'.$dir);
        $live = $input->getOption('live') === true;
        $missing = array_filter($apps, static fn (string $a): bool => ! is_file($runner->cassette($a)));
        if (! $live && $missing !== []) {
            return $this->fail($output, "replay cassettes missing:\n  ".implode("\n  ", array_map($runner->cassette(...), $missing))."\nThe controller records them with bin/benchmark --live.");
        }

        $saved = getenv(Runner::KEY_ENV);
        if ($live) {
            require_once $repo.'/tests/Live/bootstrap-env.php';
            $key = getenv(Runner::KEY_ENV);
            if (! is_string($key) || trim($key) === '') {
                return $this->fail($output, Runner::KEY_ENV.' is not set (env or .env.live)');
            }
        } else {
            $key = self::REPLAY_KEY;
            putenv(Runner::KEY_ENV.'='.$key);
        }

        $option = $input->getOption('budget');
        $budget = self::budget(is_string($option) ? $option : null, $live);
        if ($live) {
            $output->writeln(sprintf('live run: token budget cap %s per app (analyze --budget)', $budget));
        }
        $runs = [];
        try {
            foreach ($apps as $app) {
                $output->writeln(sprintf('<info>%s</info> %s', $live ? 'recording' : 'replaying', $app), OutputInterface::VERBOSITY_VERBOSE);
                $runs[$app] = $runner->run($app, $live ? 'record' : 'replay', null, trim($key), $budget);
            }
        } catch (\RuntimeException $e) {
            return $this->fail($output, $e->getMessage());
        } finally {
            if (! $live) {
                putenv($saved === false ? Runner::KEY_ENV : Runner::KEY_ENV.'='.$saved);
            }
        }

        $score = Scorer::score(
            $cases,
            array_map(static fn (AppRun $r): array => $r->analyze, $runs),
            array_map(static fn (AppRun $r): array => $r->map, $runs),
            $publics,
            array_map(static fn (AppRun $r): array => $r->dryRun, $runs),
        );
        $usage = ['input' => 0, 'output' => 0, 'cacheRead' => 0, 'cacheWrite' => 0];
        $models = [];
        $requests = 0;
        foreach ($runs as $run) {
            foreach ($usage as $k => $v) {
                $usage[$k] = $v + $run->usage[$k];
            }
            array_push($models, ...$run->models);
            $requests += $run->requests;
        }
        $models = array_values(array_unique($models));
        sort($models);
        $markdown = Report::markdown($score, [
            'mode' => $live ? 'live' : 'replay',
            'date' => gmdate('Y-m-d'),
            'models' => $models,
            'promptVersion' => SecurityPrompt::VERSION,
            'requests' => $requests,
            'usage' => $usage,
        ]);
        $out = (string) $input->getOption('out');
        $path = str_starts_with($out, '/') ? $out : $repo.'/'.$out;
        if (! is_dir(dirname($path)) || file_put_contents($path, $markdown) === false) {
            return $this->fail($output, "cannot write {$path}");
        }

        // Exit 0 needs at least one measured slice and no failing one; n/a never counts as a pass.
        $verdicts = [];
        foreach ([...$score->sets(), 'all'] as $column) {
            $criteria = Gate::evaluate($score->counts($column === 'all' ? null : $column));
            $verdicts[] = Gate::verdict($criteria);
            $counts = $score->counts($column === 'all' ? null : $column);
            $strict = $score->hasPosthoc() ? sprintf('  (found strict %d/%d)', $counts->foundStrict, $counts->cases) : '';
            $output->writeln(sprintf('%-8s %s  %s%s', $column, Report::verdict(Gate::verdict($criteria)), implode('  ', array_map(
                static fn (array $c): string => $c['criterion'].' '.$c['numerator'].'/'.$c['denominator'].' '.match ($c['pass']) {
                    true => 'ok',
                    false => 'FAIL',
                    null => 'n/a',
                },
                $criteria,
            )), $strict));
        }
        $output->writeln(sprintf('%d requests, $%.2f estimated; report written to %s', $requests, Report::cost($usage), $out));

        return in_array(true, $verdicts, true) && ! in_array(false, $verdicts, true) ? Command::SUCCESS : Command::FAILURE;
    }

    private function fail(OutputInterface $output, string $message): int
    {
        $output->writeln('<error>'.$message.'</error>');

        return 2;
    }
}
