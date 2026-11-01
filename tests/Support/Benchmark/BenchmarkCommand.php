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
            ->addOption('competitor', null, InputOption::VALUE_REQUIRED, 'claude-code-security-review eval_results.json to score as well (M8 Task 5)')
            ->addOption('source', null, InputOption::VALUE_REQUIRED, 'Run on the disguised copy in this directory (needs --disguise-map); cassettes benchmark-disguised-<app>.json')
            ->addOption('disguise-map', null, InputOption::VALUE_REQUIRED, 'disguise-map.json from tools/benchmark-disguise.php; its copy is where the competitor ran')
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
        $competitorPath = $input->getOption('competitor');
        $disguisePath = $input->getOption('disguise-map');
        if (is_string($competitorPath) && ! is_string($disguisePath)) {
            return $this->fail($output, '--competitor needs --disguise-map to map their files back to ours');
        }
        $source = $input->getOption('source');
        if (is_string($source) && ! is_string($disguisePath)) {
            return $this->fail($output, '--source needs --disguise-map to map our findings back to the original names');
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
        $dir = str_starts_with($dir, '/') ? $dir : $repo.'/'.$dir;
        $disguise = null;
        if (is_string($source)) {
            try {
                $disguise = DisguiseMap::load($disguisePath);
            } catch (\RuntimeException $e) {
                return $this->fail($output, $e->getMessage());
            }
            $source = str_starts_with($source, '/') ? $source : $repo.'/'.$source;
            foreach ($apps as $app) {
                if (! is_dir($source.'/'.$app) || ! in_array($app, $disguise->apps(), true)) {
                    return $this->fail($output, "{$app} is missing from {$source} or from the disguise map");
                }
            }
        }
        $runner = $disguise === null ? new Runner($dir) : new Runner($dir, (string) $source, Runner::DISGUISED_PREFIX);
        $undisguisedRunner = $disguise === null ? null : new Runner($dir);
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
        $undisguisedRuns = [];
        try {
            foreach ($apps as $app) {
                $output->writeln(sprintf('<info>%s</info> %s', $live ? 'recording' : 'replaying', $app), OutputInterface::VERBOSITY_VERBOSE);
                $run = $runner->run($app, $live ? 'record' : 'replay', null, trim($key), $budget);
                $runs[$app] = $disguise === null ? $run : self::undisguise($disguise, $run);
            }
            // The undisguised recordings are only ever replayed here, as the secondary table.
            if ($undisguisedRunner !== null && array_filter($apps, static fn (string $a): bool => ! is_file($undisguisedRunner->cassette($a))) === []) {
                foreach ($apps as $app) {
                    $undisguisedRuns[$app] = $undisguisedRunner->run($app, 'replay', null, trim($key), $budget);
                }
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
        $undisguised = $undisguisedRuns === [] ? null : Scorer::score(
            $cases,
            array_map(static fn (AppRun $r): array => $r->analyze, $undisguisedRuns),
            array_map(static fn (AppRun $r): array => $r->map, $undisguisedRuns),
            $publics,
            array_map(static fn (AppRun $r): array => $r->dryRun, $undisguisedRuns),
        );
        $competitor = null;
        if (is_string($competitorPath) && is_string($disguisePath)) {
            try {
                $competitor = self::competitor($competitorPath, $disguisePath, $cases, $publics, $runs);
            } catch (\RuntimeException $e) {
                return $this->fail($output, $e->getMessage());
            }
        }
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
        ], $competitor, $disguise === null ? null : ($undisguised ?? false));
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
        if ($competitor !== null) {
            foreach ([...$competitor->score->sets(), 'all'] as $column) {
                $c = $competitor->score->counts($column === 'all' ? null : $column);
                $output->writeln(sprintf('competitor %-8s  recall %d/%d  safe flagged %d/%d  public %d/%d  unattributed %d', $column, $c->found, $c->cases, $c->flagged, $c->cases, $c->publicViolations, $c->publicRoutes, $c->unattributed));
            }
        }
        $output->writeln(sprintf('%d requests, $%.2f estimated; report written to %s', $requests, Report::cost($usage), $out));

        return in_array(true, $verdicts, true) && ! in_array(false, $verdicts, true) ? Command::SUCCESS : Command::FAILURE;
    }

    // Our run on the disguised copy, rewritten to original names so the same cases score it.
    private static function undisguise(DisguiseMap $map, AppRun $run): AppRun
    {
        return new AppRun(
            $run->app,
            Undisguise::analyze($map, $run->app, $run->analyze),
            Undisguise::map($map, $run->app, $run->map),
            Undisguise::dryRun($map, $run->app, $run->dryRun),
            $run->usage,
            $run->models,
            $run->requests,
        );
    }

    /**
     * Converts and scores their results with the same cases, public routes and Scorer as ours.
     *
     * @param list<BenchmarkCase> $cases
     * @param list<PublicRoute> $publics
     * @param array<string, AppRun> $runs
     */
    private static function competitor(string $resultsPath, string $mapPath, array $cases, array $publics, array $runs): CompetitorResult
    {
        $text = is_file($resultsPath) ? file_get_contents($resultsPath) : false;
        $results = $text === false ? null : json_decode($text, true);
        if (! is_array($results)) {
            throw new \RuntimeException("cannot read competitor results {$resultsPath}");
        }
        $map = DisguiseMap::load($mapPath);
        $missing = array_diff(array_keys($runs), $map->apps());
        if ($missing !== []) {
            throw new \RuntimeException('the disguise map has no entry for '.implode(', ', $missing));
        }
        $run = CompetitorConverter::fromMap($map)->convert($results);
        $analyze = [];
        foreach (array_keys($runs) as $app) {
            $analyze[$app] = $run->analyze[$app] ?? ['findings' => []];
        }
        $score = Scorer::score($cases, $analyze, array_map(static fn (AppRun $r): array => $r->map, $runs), $publics);

        return new CompetitorResult($score, $run, CompetitorResult::readMeta(dirname($resultsPath)));
    }

    private function fail(OutputInterface $output, string $message): int
    {
        $output->writeln('<error>'.$message.'</error>');

        return 2;
    }
}
