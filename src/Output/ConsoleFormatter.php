<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Output;

use Symfony\Component\Console\Formatter\OutputFormatter;
use TusharKhan\SemanticSec\Analysis\Severity;
use TusharKhan\SemanticSec\Console\Terminal;
use TusharKhan\SemanticSec\Engine\AnalysisResult;
use TusharKhan\SemanticSec\Engine\Vulnerability;

/**
 * SPEC §14 console report: findings grouped by file, suppressed and baselined lists, the summary, warnings.
 *
 * @phpstan-import-type Meta from Formatter
 */
final class ConsoleFormatter implements Formatter
{
    private const FIELD = '      %-15s%s';

    private const PATCH_INDENT = '        ';

    // Continuation lines of a multi-line field line up under its value.
    private const VALUE_INDENT = '                     ';

    public function __construct(private readonly bool $decorated = false)
    {
    }

    /** @param Meta $meta */
    public function format(AnalysisResult $r, array $meta): string
    {
        $lines = [Terminal::safe(sprintf('%s %s — %s %s', $meta['tool'], $meta['version'], $meta['provider'], $meta['model'])), ''];

        $findings = $r->findings;
        usort($findings, static fn (array $a, array $b): int => self::compare($a['vulnerability'], $b['vulnerability']));
        $file = null;
        foreach ($findings as $finding) {
            $v = $finding['vulnerability'];
            if ($v->file !== $file) {
                $file = $v->file;
                array_push($lines, '<options=bold>'.Terminal::safe($v->file).'</>', '');
            }
            array_push($lines, ...$this->finding($v, $finding['failing']));
            $lines[] = '';
        }
        if ($findings === []) {
            array_push($lines, 'No findings.', '');
        }

        $suppressed = array_map(static fn (array $s): array => [$s['vulnerability'], $s['suppression']->reason ?? 'no reason given'], $r->suppressed);
        $baselined = array_map(static fn (Vulnerability $v): array => [$v, 'in baseline'], $r->baselined);
        foreach (['Suppressed' => $suppressed, 'Baselined' => $baselined] as $heading => $entries) {
            if ($entries !== []) {
                array_push($lines, ...self::shortList($heading, $entries));
                $lines[] = '';
            }
        }

        return $this->render($lines).$this->summary($r, $meta);
    }

    /**
     * The summary block, the strict reason and the warnings; --output sends this to stderr.
     *
     * @param  Meta  $meta
     */
    public function summary(AnalysisResult $r, array $meta): string
    {
        $s = $r->stats;
        $failing = count(array_filter($r->findings, static fn (array $f): bool => $f['failing']));
        $budget = $meta['budget'] ?? null;
        $level = $meta['level'] ?? null;
        $rows = [
            'candidates' => $s['candidates'],
            'payloads' => $s['payloads'],
            'skipped' => $s['skipped'].' (no source code)',
            'unsent' => $s['unsent'].' (token budget)',
            'cache hits' => $s['cacheHits'],
            'sent' => $s['sent'],
            'ok' => $s['ok'],
            'refused' => $s['refused'],
            'truncated' => $s['truncated'],
            'invalid' => $s['invalid'],
            'failed' => $s['failed'],
            'dropped' => $s['dropped'].' (not grounded)',
            'findings' => count($r->findings).' ('.$failing.' failing)',
            'filtered' => $s['filtered'].($level === null ? '' : ' (below level '.Terminal::safe($level).')'),
            'suppressed' => count($r->suppressed),
            'baselined' => count($r->baselined),
            'tokens' => $s['tokens'],
            'budget' => ($budget === null ? 'unlimited' : (string) $budget).($s['budgetExceeded'] ? ' (exceeded)' : ''),
        ];
        $lines = ['<options=bold>Summary</>'];
        foreach ($rows as $label => $value) {
            $lines[] = sprintf('  %-11s %s', $label, $value);
        }
        $strict = $meta['strictReason'] ?? null;
        if ($strict !== null) {
            array_push($lines, '', '<fg=red>'.Terminal::safe($strict).'</>');
        }
        if ($r->warnings !== []) {
            array_push($lines, '', '<fg=yellow>Warnings</>');
            foreach ($r->warnings as $warning) {
                $lines[] = '  '.Terminal::safe($warning);
            }
        }

        return $this->render($lines);
    }

    /** @return list<string> */
    private function finding(Vulnerability $v, bool $failing): array
    {
        $colour = match ($v->severity) {
            Severity::Critical, Severity::High => 'fg=red;options=bold',
            Severity::Medium => 'fg=yellow;options=bold',
            Severity::Low => 'fg=cyan;options=bold',
        };
        $lines = [
            sprintf('  <%s>[!] %s Severity: %s</>', $colour, ucfirst($v->severity->value), Terminal::safe($v->title)),
            sprintf(self::FIELD, 'File:', Terminal::safe($v->file)),
            sprintf(self::FIELD, 'Line:', $v->line),
            sprintf(self::FIELD, 'Symbol:', Terminal::safe($v->symbol)),
            sprintf(self::FIELD, 'Category:', $v->category->label().' ('.$v->category->cweId().')'),
            sprintf(self::FIELD, 'Confidence:', $v->confidence->value.($failing ? '' : ' (not failing)')),
            sprintf(self::FIELD, 'Context:', self::prose($v->context)),
            sprintf(self::FIELD, 'Flaw:', self::prose($v->flaw)),
            sprintf(self::FIELD, 'Suggested Fix:', self::prose($v->fix)),
        ];
        $patch = rtrim($v->patch, "\r\n");
        if (trim($patch) !== '') {
            $lines[] = sprintf(self::FIELD, 'Patch:', '');
            foreach (preg_split('/\R/', $patch) ?: [] as $line) {
                $lines[] = rtrim(self::PATCH_INDENT.self::diffLine($line), ' ');
            }
        }

        return array_map(static fn (string $l): string => rtrim($l, ' '), $lines);
    }

    // Model prose keeps its line breaks, each line cleaned, escaped and indented under the value.
    private static function prose(string $text): string
    {
        $lines = array_map(Terminal::safe(...), preg_split('/\R/', trim($text)) ?: []);

        return implode("\n", array_map(static fn (string $l, int $i): string => $i === 0 || $l === '' ? $l : self::VALUE_INDENT.$l, $lines, array_keys($lines)));
    }

    private static function diffLine(string $line): string
    {
        $safe = Terminal::safeLine($line);
        $style = match (true) {
            str_starts_with($line, '+++'), str_starts_with($line, '---') => 'options=bold',
            str_starts_with($line, '@@') => 'fg=cyan',
            str_starts_with($line, '+') => 'fg=green',
            str_starts_with($line, '-') => 'fg=red',
            default => null,
        };

        return $style === null || $safe === '' ? $safe : '<'.$style.'>'.$safe.'</>';
    }

    /**
     * @param  list<array{Vulnerability, string}>  $entries
     * @return list<string>
     */
    private static function shortList(string $heading, array $entries): array
    {
        usort($entries, static fn (array $a, array $b): int => self::compare($a[0], $b[0]));
        $lines = ['<options=bold>'.$heading.' ('.count($entries).')</>'];
        foreach ($entries as [$v, $reason]) {
            $lines[] = sprintf('  - %s — %s:%d — %s', Terminal::safe($v->title), Terminal::safe($v->file), $v->line, Terminal::safe($reason));
        }

        return $lines;
    }

    // File, then line; the rest only makes the order deterministic.
    private static function compare(Vulnerability $a, Vulnerability $b): int
    {
        return [$a->file, $a->line, $a->category->value, $a->symbol, $a->title, $a->fingerprint]
            <=> [$b->file, $b->line, $b->category->value, $b->symbol, $b->title, $b->fingerprint];
    }

    /** @param list<string> $lines console markup, every interpolated value already escaped */
    private function render(array $lines): string
    {
        return (new OutputFormatter($this->decorated))->format(implode("\n", $lines)."\n") ?? '';
    }
}
