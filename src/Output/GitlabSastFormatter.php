<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Output;

use TusharKhan\SemanticSec\Analysis\Severity;
use TusharKhan\SemanticSec\Console\Terminal;
use TusharKhan\SemanticSec\Engine\AnalysisResult;
use TusharKhan\SemanticSec\Engine\Vulnerability;

/**
 * SPEC §14 GitLab SAST report (schema 15.2.5): reported findings only; suppressed, baselined and filtered ones are left out.
 *
 * @phpstan-import-type Meta from Formatter
 */
final class GitlabSastFormatter implements Formatter
{
    public const SCHEMA_VERSION = '15.2.5';

    // uuid5(NAMESPACE_URL, "https://github.com/tusharkhan/semantic-sec#gitlab-sast").
    public const NAMESPACE = '84d1fcaf-52cc-5cb0-a675-4b8a9ad45331';

    private const NAME_CAP = 255;

    private const DESCRIPTION_CAP = 4000;

    private const SOLUTION_CAP = 7000;

    private const FLAGS = JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR;

    /** @param Meta $meta */
    public function format(AnalysisResult $r, array $meta): string
    {
        $findings = $r->findings;
        usort($findings, static fn (array $a, array $b): int => self::compare($a['vulnerability'], $b['vulnerability']));
        $tool = [
            'id' => 'semantic_sec',
            'name' => 'semantic-sec',
            'url' => SarifFormatter::INFORMATION_URI,
            'version' => self::nonEmpty(Terminal::clean($meta['version'])),
            'vendor' => ['name' => 'semantic-sec'],
        ];
        $started = $meta['startedAt'] ?? time();

        $document = [
            'version' => self::SCHEMA_VERSION,
            'scan' => [
                'analyzer' => $tool,
                'scanner' => $tool,
                'type' => 'sast',
                'start_time' => gmdate('Y-m-d\TH:i:s', $started),
                'end_time' => gmdate('Y-m-d\TH:i:s', max($started, $meta['finishedAt'] ?? time())),
                'status' => ($meta['exitCode'] ?? 0) === 2 ? 'failure' : 'success',
            ],
            'vulnerabilities' => array_map(static fn (array $f): array => self::vulnerability($f['vulnerability'], $f['failing']), $findings),
        ];

        return json_encode($document, self::FLAGS)."\n";
    }

    // RFC 4122 version 5 (SHA-1, name-based) UUID of the fingerprint under NAMESPACE.
    public static function uuid(string $fingerprint): string
    {
        $hash = sha1((string) hex2bin(str_replace('-', '', self::NAMESPACE)).$fingerprint);
        $hex = substr($hash, 0, 12).'5'.substr($hash, 13, 3).dechex((hexdec($hash[16]) & 0x3) | 0x8).substr($hash, 17, 15);

        return implode('-', [substr($hex, 0, 8), substr($hex, 8, 4), substr($hex, 12, 4), substr($hex, 16, 4), substr($hex, 20, 12)]);
    }

    /** @return array<string, mixed> */
    private static function vulnerability(Vulnerability $v, bool $failing): array
    {
        $title = Terminal::clean($v->title);
        $flaw = trim(Terminal::block($v->flaw));
        $fix = trim(Terminal::block($v->fix));
        $cwe = $v->category->cweId();
        $n = substr($cwe, 4);
        $location = ['file' => Terminal::clean($v->file)];
        if ($v->line >= 1) {
            $location['start_line'] = $v->line;
        }

        $out = [
            'id' => self::uuid($v->fingerprint),
            'name' => self::cap(self::nonEmpty($title), self::NAME_CAP),
            'description' => self::cap($flaw === '' ? self::nonEmpty($title) : $flaw, self::DESCRIPTION_CAP),
            // A non-failing finding (below --min-confidence) is Info, as SARIF makes it a note.
            'severity' => $failing ? self::severity($v->severity) : 'Info',
        ];
        if ($fix !== '') {
            $out['solution'] = self::cap($fix, self::SOLUTION_CAP);
        }
        $out['location'] = $location;
        // The first identifier is GitLab's primary one, which it tracks by; the fingerprint survives line moves.
        $out['identifiers'] = [
            ['type' => 'semantic_sec_fingerprint', 'name' => 'semantic-sec '.self::nonEmpty(mb_substr(Terminal::clean($v->fingerprint), 0, 12, 'UTF-8')), 'value' => self::nonEmpty($v->fingerprint)],
            ['type' => 'cwe', 'name' => $cwe, 'value' => $n, 'url' => 'https://cwe.mitre.org/data/definitions/'.$n.'.html'],
        ];

        return $out;
    }

    private static function severity(Severity $s): string
    {
        return match ($s) {
            Severity::Critical => 'Critical',
            Severity::High => 'High',
            Severity::Medium => 'Medium',
            Severity::Low => 'Low',
        };
    }

    // The schema has minLength 1 on names and versions.
    private static function nonEmpty(string $text): string
    {
        return $text === '' ? 'unknown' : $text;
    }

    // Cuts to at most $max characters, ending in an ellipsis; expects valid UTF-8, so the cut is on a character boundary.
    private static function cap(string $text, int $max): string
    {
        return mb_strlen($text, 'UTF-8') <= $max ? $text : mb_substr($text, 0, $max - 1, 'UTF-8').'…';
    }

    // File, then line; the rest only makes the order deterministic.
    private static function compare(Vulnerability $a, Vulnerability $b): int
    {
        return [$a->file, $a->line, $a->category->value, $a->symbol, $a->title, $a->fingerprint]
            <=> [$b->file, $b->line, $b->category->value, $b->symbol, $b->title, $b->fingerprint];
    }
}
