<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support\Benchmark;

/** The "Competitive check" report section: both tools under the same scorer, and every way the comparison is uneven. */
final class CompetitiveSection
{
    public const TOOL = 'claude-code-security-review';

    /**
     * @param list<string> $ourModels
     *
     * @return list<string>
     */
    public static function lines(Score $ours, CompetitorResult $c, array $ourModels): array
    {
        $theirs = $c->score;
        $run = $c->run;
        $model = self::meta($c->meta, 'model', 'unknown');
        $inApps = count($run->traces) - $run->unmapped();
        $out = ['## Competitive check', ''];
        $out[] = sprintf(
            'Anthropic\'s `%s` at commit `%s` ran with model `%s` on %s, a pull request that adds the disguised copy of the three apps. Its findings were mapped to symbols with our `SymbolTable` and scored by the same scorer as above: %d findings, %d inside a benchmark app, %d outside. Runtime %.0f s.',
            self::TOOL,
            self::meta($c->meta, 'sha', 'unknown'),
            $model,
            self::meta($c->meta, 'pr', 'an unrecorded PR'),
            count($run->traces),
            $inApps,
            $run->unmapped(),
            $run->meta['runtime'],
        );
        $out[] = '';
        array_push($out, ...self::cost($c->meta));
        $out[] = 'Recall is the share of vulnerable variants found at the right symbol with a matching category. Precision is found / (found + safe variants flagged + public routes hit + unattributed safe-code findings). Each term is a case-level verdict, so repeated findings on one symbol count once. Findings at every confidence count for both tools.';
        $out[] = '';
        $out[] = '| Set | Metric | semantic-sec | '.self::TOOL.' |';
        $out[] = '|---|---|---|---|';
        foreach ([...$ours->sets(), 'all'] as $set) {
            $a = $ours->counts($set === 'all' ? null : $set);
            $b = $theirs->counts($set === 'all' ? null : $set);
            $out[] = sprintf('| %s | Recall (found) | %s | %s |', $set, self::rate($a->found, $a->cases), self::rate($b->found, $b->cases));
            $out[] = sprintf('| %s | Precision | %s | %s |', $set, self::rate($a->found, self::asserted($a)), self::rate($b->found, self::asserted($b)));
            $out[] = sprintf('| %s | Safe variants flagged | %s | %s |', $set, self::rate($a->flagged, $a->cases), self::rate($b->flagged, $b->cases));
            $out[] = sprintf('| %s | Public routes hit | %d/%d | %d/%d |', $set, $a->publicViolations, $a->publicRoutes, $b->publicViolations, $b->publicRoutes);
            $out[] = sprintf('| %s | Unattributed safe-code findings | %d | %d |', $set, $a->unattributed, $b->unattributed);
        }
        $out[] = '';

        $out[] = '### Verdicts per case';
        $out[] = '';
        $out[] = '| Case | Set | Category | semantic-sec | '.self::TOOL.' | Their deciding finding |';
        $out[] = '|---|---|---|---|---|---|';
        foreach ($theirs->cases as $v) {
            $mine = $ours->verdict($v->case->id);
            $out[] = sprintf('| %s | %s | %s | %s | %s | %s |', $v->case->id, $v->case->set, $v->case->category, self::verdict($mine), self::verdict($v), Report::finding($v->foundBy ?? $v->flaggedBy));
        }
        $out[] = '';

        $out[] = '### Their findings and how each was mapped';
        $out[] = '';
        if ($run->traces === []) {
            $out[] = 'None.';
        } else {
            $out[] = '| # | Reported at (original path) | Their category | Scored as | Rule | Symbol | Located by |';
            $out[] = '|---|---|---|---|---|---|---|';
            foreach ($run->traces as $i => $t) {
                $at = ($t['app'] === null ? '' : $t['app'].'/').$t['file'].':'.$t['line'];
                $out[] = sprintf('| %d | `%s` | %s | %s | %s | %s | %s |', $i + 1, Report::cell($at), Report::cell($t['rawCategory']), Report::cell($t['category']), $t['rule'], $t['symbol'] === '' ? '' : '`'.Report::cell($t['symbol']).'`', $t['location']);
            }
        }
        $out[] = '';

        $out[] = '### Category inference';
        $out[] = '';
        $out[] = 'Their findings carry a free-text `category` and no CWE field, while our scorer needs one of five categories. The first rule that matches decides: a CWE id anywhere in the finding, then our own category name as theirs, then keywords in category and description (`keyword:`), then keywords in the exploit scenario (`exploit:`). Generic authorization wording scores as either `idor` or `missing_authorization` (`access-control`). A finding with nothing to go on (`none`) scores as **any category** for the found check, so they are not penalised for vocabulary. Our findings must match the case category exactly, so this favours them.';
        $out[] = '';
        $out[] = '| Rule | Findings |';
        $out[] = '|---|---|';
        foreach ($run->rules() as $rule => $count) {
            $out[] = sprintf('| %s | %d |', $rule, $count);
        }
        $out[] = '';

        $out[] = '### Asymmetries';
        $out[] = '';
        foreach (self::asymmetries($model, $ourModels, $c->meta) as $line) {
            $out[] = '- '.$line;
        }
        $out[] = '';

        return $out;
    }

    // Case-level verdicts a tool asserted: true positives plus every kind of false positive the gate counts.
    private static function asserted(Counts $c): int
    {
        return $c->found + $c->flagged + $c->publicViolations + $c->unattributed;
    }

    private static function rate(int $numerator, int $denominator): string
    {
        return $denominator === 0 ? 'n/a' : sprintf('%s (%d/%d)', Report::percent($numerator / $denominator), $numerator, $denominator);
    }

    private static function verdict(CaseVerdict $v): string
    {
        return ($v->found ? 'found' : 'missed').'; safe '.($v->flagged ? 'flagged' : 'clean');
    }

    /**
     * @param array<string, mixed> $meta
     *
     * @return list<string>
     */
    private static function cost(array $meta): array
    {
        $usage = is_array($meta['usage'] ?? null) ? $meta['usage'] : null;
        if ($usage === null) {
            return ['Cost: not recorded (no claude-call-*.json beside the results).', ''];
        }
        $u = [];
        foreach (['input', 'output', 'cacheRead', 'cacheWrite'] as $key) {
            $u[$key] = is_int($usage[$key] ?? null) ? $usage[$key] : 0;
        }
        $line = sprintf(
            'Cost: %s input, %s cache write, %s cache read, %s output tokens over %s agent turns; $%s at the prices above%s.',
            number_format($u['input']),
            number_format($u['cacheWrite']),
            number_format($u['cacheRead']),
            number_format($u['output']),
            is_int($meta['turns'] ?? null) ? (string) $meta['turns'] : '?',
            number_format(Report::cost($u), 2),
            is_numeric($meta['cost'] ?? null) ? sprintf(' ($%.2f as the Claude Code CLI reported it)', (float) $meta['cost']) : '',
        );
        $lines = [$line, ''];
        if (($meta['capped'] ?? false) === true) {
            $lines[] = '**A Claude Code call hit the cost guard (max turns or max budget) or ended in an error, so the findings may be incomplete.**';
            $lines[] = '';
        }

        return $lines;
    }

    /**
     * @param list<string> $ourModels
     * @param array<string, mixed> $meta
     *
     * @return list<string>
     */
    private static function asymmetries(string $model, array $ourModels, array $meta): array
    {
        $ours = $ourModels === [] ? 'unknown' : implode(', ', $ourModels);

        return [
            'Input. They review a PR diff of the three apps plus whatever the agent chooses to open in the checkout; we analyze each app as a whole project, with routes, middleware and policies resolved before the LLM sees a candidate. Their prompt lists only the first 100 changed files (one GitHub API page), although the diff itself is complete.',
            'Disguise. They ran on the disguised copy (`Vuln`/`Safe` renamed to `Alpha`/`Beta` at random per class pair, routes regrouped to match, line numbers kept outside route files). Our numbers above come from the recordings of the original corpus; the code is otherwise identical, and `semantic-sec map` gives the same checks on both copies.',
            'Category. Their category is inferred (see above) and may be "any category"; ours must match exactly.',
            'Location. A finding counts only at the case symbol or an accepted one. Their file and line become the enclosing method through our `SymbolTable`; a line in a route file becomes that route\'s controller action. Findings on models, form requests or class bodies land on no case, for both tools.',
            sprintf('Model and method. Theirs: `%s` in one agentic Claude Code session with file tools; ours: `%s`, one structured call per selected route and category.', $model, $ours),
            'Suppression. They do not honour `@semantic-sec-ignore`; we report the annotated case as suppressed, and both count as found for `suppressed-idor`.',
            'Filtering. Their eval mode applies only the hard-coded exclusion rules; the GitHub Action also runs a second Claude false-positive filter, which this run did not use.',
            sprintf('Confidence. Their 0 to 1 confidence maps to high (0.9 and up), medium (0.7 and up) or low; their prompt drops findings under 0.7. Cost guard: %s.', self::meta($meta, 'limits', 'not recorded')),
        ];
    }

    /** @param array<string, mixed> $meta */
    private static function meta(array $meta, string $key, string $default): string
    {
        return is_scalar($meta[$key] ?? null) && (string) $meta[$key] !== '' ? Report::cell((string) $meta[$key]) : $default;
    }
}
