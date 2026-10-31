<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Output;

use TusharKhan\SemanticSec\Console\Terminal;
use TusharKhan\SemanticSec\Engine\AnalysisResult;
use TusharKhan\SemanticSec\Engine\Vulnerability;

/**
 * SPEC §14 JSON document: fixed key order, findings sorted by file then line, model text stripped of control characters but never console-escaped.
 *
 * @phpstan-import-type Meta from Formatter
 */
final class JsonFormatter implements Formatter
{
    public const VERSION = 1;

    private const FLAGS = JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR;

    /** @param Meta $meta */
    public function format(AnalysisResult $r, array $meta): string
    {
        $findings = $r->findings;
        usort($findings, static fn (array $a, array $b): int => self::compare($a['vulnerability'], $b['vulnerability']));
        $suppressed = $r->suppressed;
        usort($suppressed, static fn (array $a, array $b): int => self::compare($a['vulnerability'], $b['vulnerability']));

        $document = [
            'version' => self::VERSION,
            'tool' => ['name' => Terminal::clean($meta['tool']), 'version' => Terminal::clean($meta['version'])],
            'summary' => [
                ...$r->stats,
                'exitCode' => $meta['exitCode'] ?? 0,
                'strictReason' => isset($meta['strictReason']) ? Terminal::clean($meta['strictReason']) : null,
            ],
            'findings' => array_map(fn (array $f): array => self::finding($f['vulnerability'], $f['failing']), $findings),
            'suppressed' => array_map(static fn (array $s): array => [
                ...self::finding($s['vulnerability'], false),
                'suppression' => [
                    'file' => Terminal::clean($s['suppression']->file),
                    'line' => $s['suppression']->commentLine,
                    'category' => $s['suppression']->category?->value,
                    'reason' => $s['suppression']->reason === null ? null : Terminal::clean($s['suppression']->reason),
                ],
            ], $suppressed),
            'baselined' => array_map(static fn (Vulnerability $v): array => self::finding($v, false), self::sorted($r->baselined)),
            'filtered' => array_map(static fn (Vulnerability $v): array => self::finding($v, false), self::sorted($r->filtered)),
            'warnings' => array_map(Terminal::clean(...), $r->warnings),
        ];

        return json_encode($document, self::FLAGS)."\n";
    }

    /** @return array<string, mixed> */
    private static function finding(Vulnerability $v, bool $failing): array
    {
        return [
            'title' => Terminal::clean($v->title),
            'category' => $v->category->value,
            'severity' => $v->severity->value,
            'confidence' => $v->confidence->value,
            'file' => Terminal::clean($v->file),
            'line' => $v->line,
            'symbol' => Terminal::clean($v->symbol),
            'context' => Terminal::block($v->context),
            'flaw' => Terminal::block($v->flaw),
            'fix' => Terminal::block($v->fix),
            'patch' => Terminal::block($v->patch),
            'path' => array_map(static fn (array $s): array => ['file' => Terminal::clean($s['file']), 'line' => $s['line'], 'symbol' => Terminal::clean($s['symbol'])], $v->path),
            'fingerprint' => $v->fingerprint,
            'failing' => $failing,
            'routeKey' => $v->routeKey,
            'model' => Terminal::clean($v->model),
        ];
    }

    /**
     * @param  list<Vulnerability>  $list
     * @return list<Vulnerability>
     */
    private static function sorted(array $list): array
    {
        usort($list, static fn (Vulnerability $a, Vulnerability $b): int => self::compare($a, $b));

        return $list;
    }

    // File, then line; the rest only makes the order deterministic.
    private static function compare(Vulnerability $a, Vulnerability $b): int
    {
        return [$a->file, $a->line, $a->category->value, $a->symbol, $a->title, $a->fingerprint]
            <=> [$b->file, $b->line, $b->category->value, $b->symbol, $b->title, $b->fingerprint];
    }
}
