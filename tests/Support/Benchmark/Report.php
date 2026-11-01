<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support\Benchmark;

/**
 * Renders docs/benchmark-results.md; output depends only on the score and meta, never on the clock.
 *
 * @phpstan-import-type Finding from CaseVerdict
 * @phpstan-import-type MapCheck from CaseVerdict
 * @phpstan-import-type Criterion from Gate
 *
 * @phpstan-type Usage array{input: int, output: int, cacheRead: int, cacheWrite: int}
 */
final class Report
{
    // claude-opus-5-5, $ per million tokens; cache writes at Anthropic's 1.25x input rate.
    public const PRICE_INPUT = 4.0;

    public const PRICE_OUTPUT = 20.0;

    public const PRICE_CACHE_READ = 0.20;

    public const PRICE_CACHE_WRITE = 5.0;

    /**
     * @param array<string, mixed> $meta mode, date, models (list), promptVersion, requests, usage (Usage)
     */
    public static function markdown(Score $s, array $meta): string
    {
        $columns = [...$s->sets(), 'all'];
        $out = ['# Benchmark results', ''];
        $out[] = sprintf(
            'Mode: %s · Model: %s · Prompt v%s · Date: %s',
            self::meta($meta, 'mode') === 'live' ? 'live run, recorded to cassettes' : 'replay of recorded cassettes',
            self::cell(implode(', ', self::models($meta)) ?: 'unknown'),
            self::meta($meta, 'promptVersion'),
            self::meta($meta, 'date'),
        );
        $out[] = '';
        $out[] = 'Apps: '.implode(', ', $s->apps()).'. Scored at `--level low` with every confidence; "failing" means confidence medium or high.';
        $out[] = '';

        $out[] = '## Gate';
        $out[] = '';
        array_push($out, ...self::gateTable($s, $columns, false));
        $out[] = '## Gate, failing findings only';
        $out[] = '';
        array_push($out, ...self::gateTable($s, $columns, true));

        array_push($out, ...self::selection($s));

        $out[] = '## Per app';
        $out[] = '';
        foreach ($s->apps() as $app) {
            $out[] = "### {$app}";
            $out[] = '';
            $out[] = '| Set | Cases | Found | Found (failing) | Safe flagged | Safe flagged (failing) | Public violations | Map mismatches |';
            $out[] = '|---|---|---|---|---|---|---|---|';
            foreach ($columns as $set) {
                $c = $s->counts($set === 'all' ? null : $set, $app);
                if ($c->cases === 0 && $c->publicRoutes === 0) {
                    continue;
                }
                $f = $s->counts($set === 'all' ? null : $set, $app, true);
                $out[] = sprintf('| %s | %d | %d | %d | %d | %d | %d/%d | %d/%d |', $set, $c->cases, $c->found, $f->found, $c->flagged, $f->flagged, $c->publicViolations, $c->publicRoutes, $c->mapMismatches, $c->mapVariants);
            }
            $out[] = '';
        }

        array_push($out, ...self::cases($s));
        array_push($out, ...self::publics($s));
        array_push($out, ...self::costSection($meta));

        $out[] = '## Competitive check';
        $out[] = '';
        $out[] = '_Not run yet._ M8 Task 5 scores Anthropic\'s `claude-code-security-review` on the same code with this scorer and records its numbers and every asymmetry here.';

        return implode("\n", $out)."\n";
    }

    /** @param Usage $usage */
    public static function cost(array $usage): float
    {
        return ($usage['input'] * self::PRICE_INPUT + $usage['output'] * self::PRICE_OUTPUT + $usage['cacheRead'] * self::PRICE_CACHE_READ + $usage['cacheWrite'] * self::PRICE_CACHE_WRITE) / 1_000_000;
    }

    /**
     * @param list<string> $columns
     *
     * @return list<string>
     */
    private static function gateTable(Score $s, array $columns, bool $failingOnly): array
    {
        $byColumn = [];
        foreach ($columns as $set) {
            $byColumn[$set] = Gate::evaluate($s->counts($set === 'all' ? null : $set, failingOnly: $failingOnly));
        }
        $rows = ['| Criterion | Threshold | '.implode(' | ', $columns).' |', '|---|---|'.str_repeat('---|', count($columns))];
        foreach (array_keys($byColumn['all']) as $i) {
            $first = $byColumn['all'][$i];
            $cells = array_map(static fn (string $set): string => self::criterion($byColumn[$set][$i]), $columns);
            $rows[] = "| {$first['label']} | {$first['threshold']} | ".implode(' | ', $cells).' |';
        }
        $rows[] = '| **Gate** | | '.implode(' | ', array_map(static fn (string $set): string => Gate::passes($byColumn[$set]) ? '**PASS**' : '**FAIL**', $columns)).' |';
        $rows[] = '';

        return $rows;
    }

    /** @param Criterion $c */
    private static function criterion(array $c): string
    {
        $verdict = match ($c['pass']) {
            true => 'PASS',
            false => 'FAIL',
            null => 'n/a',
        };
        if ($c['criterion'] === 'public') {
            return sprintf('%d/%d routes hit %s', $c['numerator'], $c['denominator'], $verdict);
        }
        if ($c['denominator'] === 0) {
            return $verdict;
        }

        return sprintf('%s (%d/%d) %s', self::percent($c['numerator'] / $c['denominator']), $c['numerator'], $c['denominator'], $verdict);
    }

    /** @return list<string> */
    private static function selection(Score $s): array
    {
        $out = ['## Selection stage', ''];
        if (! $s->selectionMeasured()) {
            return [...$out, 'Not measured: no dry-run output was given.', ''];
        }
        $out[] = 'Whether each route reached the LLM for the case\'s category. A missed vulnerable case whose route was not selected was never sent to the LLM; one that was selected is an LLM miss.';
        $out[] = '';
        $misses = $s->selectionMisses();
        if ($misses === []) {
            return [...$out, 'Every vulnerable route was selected for its category, and no `candidate: false` safe route was selected.', ''];
        }
        $out[] = '| Case | Set | Variant | Route | Expected | Actual |';
        $out[] = '|---|---|---|---|---|---|';
        foreach ($misses as $m) {
            $route = $m['variant'] === 'vulnerable' ? $m['case']->vulnerable->route : $m['case']->safe->route;
            $out[] = sprintf('| %s | %s | %s | `%s` | %s | %s |', $m['case']->id, $m['case']->set, $m['variant'], self::cell($route), $m['expected'], $m['actual']);
        }
        $out[] = '';

        return $out;
    }

    /** @return list<string> */
    private static function cases(Score $s): array
    {
        $out = ['## Cases', '', '| Case | Set | App | Category | Vulnerable | Deciding finding | Safe | Deciding finding | Map | Selected |', '|---|---|---|---|---|---|---|---|---|---|'];
        foreach ($s->cases as $v) {
            $vulnerable = match (true) {
                $v->found && ! $v->foundFailing => 'found (low confidence)',
                $v->found && $v->foundBy !== null && $v->foundBy['list'] === 'suppressed' => 'found (suppressed)',
                $v->found => 'found',
                $v->selectedVulnerable === false => 'missed: never sent to the LLM',
                $v->selectedVulnerable === true => 'missed: LLM missed it',
                default => 'missed',
            };
            $safe = match (true) {
                $v->flagged && ! $v->flaggedFailing => 'flagged (low confidence)',
                $v->flagged => 'flagged',
                default => 'clean',
            };
            $selected = $v->selectedVulnerable === null ? 'n/a' : sprintf('vulnerable: %s; safe: %s', Score::selection($v->vulnerableCategories), Score::selection($v->safeCategories));
            $out[] = sprintf(
                '| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |',
                $v->case->id,
                $v->case->set,
                $v->case->app,
                $v->case->category,
                $vulnerable,
                self::finding($v->foundBy),
                $safe,
                self::finding($v->flaggedBy),
                self::map($v->mapVulnerable, $v->mapSafe),
                $selected,
            );
        }
        $out[] = '';

        return $out;
    }

    /** @return list<string> */
    private static function publics(Score $s): array
    {
        $out = ['## Public routes', ''];
        if ($s->publics === []) {
            return [...$out, 'None in scope.', ''];
        }
        $out[] = '| App | Set | Route | Symbol | Result | Deciding finding |';
        $out[] = '|---|---|---|---|---|---|';
        foreach ($s->publics as $p) {
            $result = match (true) {
                $p->byFailing !== null => 'violation',
                $p->by !== null => 'violation (low confidence)',
                default => 'clean',
            };
            $out[] = sprintf('| %s | %s | `%s` | `%s` | %s | %s |', $p->route->app, $p->route->set, self::cell($p->route->route), self::cell($p->route->symbol), $result, self::finding($p->by));
        }
        $out[] = '';

        return $out;
    }

    /**
     * @param array<string, mixed> $meta
     *
     * @return list<string>
     */
    private static function costSection(array $meta): array
    {
        $raw = is_array($meta['usage'] ?? null) ? $meta['usage'] : [];
        $usage = [];
        foreach (['input', 'output', 'cacheRead', 'cacheWrite'] as $key) {
            $usage[$key] = is_int($raw[$key] ?? null) ? $raw[$key] : 0;
        }
        $requests = is_int($meta['requests'] ?? null) ? $meta['requests'] : 0;

        return [
            '## Run cost',
            '',
            'Tokens as the provider reported them in the recorded responses. A replay re-reads the recording, so these are the cost of the live run that made it.',
            '',
            '| Requests | Input | Cache write | Cache read | Output | Estimated $ |',
            '|---|---|---|---|---|---|',
            sprintf('| %d | %s | %s | %s | %s | $%s |', $requests, number_format($usage['input']), number_format($usage['cacheWrite']), number_format($usage['cacheRead']), number_format($usage['output']), number_format(self::cost($usage), 2)),
            '',
            sprintf('Priced as claude-opus-5-5: $%.2f/M input, $%.2f/M output, $%.2f/M cache read, $%.2f/M cache write (1.25x input).', self::PRICE_INPUT, self::PRICE_OUTPUT, self::PRICE_CACHE_READ, self::PRICE_CACHE_WRITE),
            '',
        ];
    }

    /** @param Finding|null $f */
    private static function finding(?array $f): string
    {
        if ($f === null) {
            return '';
        }
        $list = $f['list'] === 'findings' ? '' : " ({$f['list']})";

        return sprintf('%s %s · `%s:%d` · `%s` · %s%s', $f['category'], $f['confidence'], self::cell($f['file']), $f['line'], self::cell($f['symbol']), self::cell($f['title']), $list);
    }

    /**
     * @param MapCheck $vulnerable
     * @param MapCheck $safe
     */
    private static function map(array $vulnerable, array $safe): string
    {
        $parts = [];
        foreach (['vulnerable' => $vulnerable, 'safe' => $safe] as $name => $check) {
            if (! $check['ok']) {
                $actual = $check['actual'] === null ? 'route not in map' : '['.implode(', ', $check['actual']).']';
                $parts[] = sprintf('%s: expected [%s], got %s', $name, implode(', ', $check['expected']), $actual);
            }
        }

        return $parts === [] ? 'ok' : implode('; ', $parts);
    }

    private static function percent(float $rate): string
    {
        return sprintf('%.0f%%', round($rate * 100));
    }

    // Model text and paths go into table cells: no pipes, no newlines, no backticks.
    private static function cell(string $text): string
    {
        $flat = (string) preg_replace('/\s+/', ' ', trim($text));

        return str_replace(['|', '`'], ['\|', "'"], $flat);
    }

    /** @param array<string, mixed> $meta */
    private static function meta(array $meta, string $key): string
    {
        return is_scalar($meta[$key] ?? null) ? self::cell((string) $meta[$key]) : 'unknown';
    }

    /**
     * @param array<string, mixed> $meta
     *
     * @return list<string>
     */
    private static function models(array $meta): array
    {
        return array_values(array_filter(is_array($meta['models'] ?? null) ? $meta['models'] : [], is_string(...)));
    }
}
