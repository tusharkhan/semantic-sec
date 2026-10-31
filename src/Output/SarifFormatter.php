<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Output;

use TusharKhan\SemanticSec\Analysis\Category;
use TusharKhan\SemanticSec\Analysis\Severity;
use TusharKhan\SemanticSec\Console\Terminal;
use TusharKhan\SemanticSec\Engine\AnalysisResult;
use TusharKhan\SemanticSec\Engine\Vulnerability;
use TusharKhan\SemanticSec\Parsing\Suppression;

/**
 * SPEC §14 SARIF 2.1.0 log: one run, one rule per category, findings then suppressed then baselined as results.
 *
 * @phpstan-import-type Meta from Formatter
 */
final class SarifFormatter implements Formatter
{
    public const SCHEMA = 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json';

    public const INFORMATION_URI = 'https://github.com/tusharkhan/semantic-sec';

    public const FINGERPRINT_KEY = 'semanticSec/v1';

    private const SRCROOT = '%SRCROOT%';

    private const FLAGS = JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR;

    /** @param Meta $meta */
    public function format(AnalysisResult $r, array $meta): string
    {
        $findings = $r->findings;
        usort($findings, static fn (array $a, array $b): int => self::compare($a['vulnerability'], $b['vulnerability']));
        $suppressed = $r->suppressed;
        usort($suppressed, static fn (array $a, array $b): int => self::compare($a['vulnerability'], $b['vulnerability']));
        $baselined = $r->baselined;
        usort($baselined, self::compare(...));

        $results = [
            ...array_map(static fn (array $f): array => self::result($f['vulnerability'], $f['failing']), $findings),
            ...array_map(static fn (array $s): array => self::result($s['vulnerability'], false, $s['suppression']), $suppressed),
            ...array_map(static fn (Vulnerability $v): array => self::result($v, false, null, true), $baselined),
        ];

        $document = [
            '$schema' => self::SCHEMA,
            'version' => '2.1.0',
            'runs' => [[
                'tool' => ['driver' => [
                    'name' => Terminal::clean($meta['tool']),
                    'version' => Terminal::clean($meta['version']),
                    'informationUri' => self::INFORMATION_URI,
                    'rules' => array_map(self::rule(...), Category::cases()),
                ]],
                'originalUriBaseIds' => [self::SRCROOT => ['description' => ['text' => 'The project root that semantic-sec analyzed.']]],
                'results' => $results,
                'properties' => ['summary' => [
                    ...$r->stats,
                    'exitCode' => $meta['exitCode'] ?? 0,
                    'strictReason' => isset($meta['strictReason']) ? Terminal::clean($meta['strictReason']) : null,
                ]],
            ]],
        ];

        return json_encode($document, self::FLAGS)."\n";
    }

    /** @return array<string, mixed> */
    private static function rule(Category $c): array
    {
        return [
            'id' => $c->cweId(),
            'name' => match ($c) {
                Category::Idor => 'InsecureDirectObjectReference',
                Category::MissingAuthorization => 'MissingAuthorization',
                Category::MassAssignment => 'MassAssignment',
                Category::InsecureDeserialization => 'InsecureDeserialization',
                Category::WorkflowBypass => 'WorkflowBypass',
            },
            'shortDescription' => ['text' => $c->label()],
            'helpUri' => 'https://cwe.mitre.org/data/definitions/'.substr($c->cweId(), 4).'.html',
            'properties' => ['tags' => ['security']],
        ];
    }

    /** @return array<string, mixed> */
    private static function result(Vulnerability $v, bool $failing, ?Suppression $suppression = null, bool $baselined = false): array
    {
        $title = Terminal::clean($v->title);
        $flaw = Terminal::block($v->flaw);
        $out = [
            'ruleId' => $v->category->cweId(),
            'ruleIndex' => (int) array_search($v->category, Category::cases(), true),
            'level' => self::level($v->severity),
            'message' => ['text' => trim($flaw) === '' ? $title : $title."\n\n".$flaw],
            'locations' => [['physicalLocation' => self::physical($v->file, $v->line)]],
            'partialFingerprints' => [self::FINGERPRINT_KEY => $v->fingerprint],
        ];
        if ($v->path !== []) {
            $out['codeFlows'] = [['threadFlows' => [['locations' => array_map(static fn (array $s): array => ['location' => [
                'physicalLocation' => self::physical($s['file'], $s['line']),
                'message' => ['text' => Terminal::clean($s['symbol'])],
            ]], $v->path)]]]];
        }
        if ($suppression !== null) {
            $out['suppressions'] = [['kind' => 'inSource', 'justification' => Terminal::clean($suppression->reason ?? '')]];
        }
        if ($baselined) {
            $out['baselineState'] = 'unchanged';
        }
        $out['properties'] = [
            'severity' => $v->severity->value,
            'confidence' => $v->confidence->value,
            'failing' => $failing,
            'category' => $v->category->value,
            'symbol' => Terminal::clean($v->symbol),
            'routeKey' => Terminal::clean($v->routeKey),
            'fix' => Terminal::block($v->fix),
        ];
        // SARIF `fixes` require exact artifactChanges, which a model diff cannot give reliably.
        if ($v->patch !== '') {
            $out['properties']['patch'] = Terminal::block($v->patch);
        }

        return $out;
    }

    /** @return array<string, mixed> */
    private static function physical(string $file, int $line): array
    {
        $out = ['artifactLocation' => ['uri' => self::uri($file), 'uriBaseId' => self::SRCROOT]];
        if ($line >= 1) {
            $out['region'] = ['startLine' => $line];
        }

        return $out;
    }

    // Root-relative path, each segment percent-encoded so any byte stays a valid, inert URI reference.
    private static function uri(string $file): string
    {
        return implode('/', array_map(rawurlencode(...), explode('/', $file)));
    }

    private static function level(Severity $s): string
    {
        return match ($s) {
            Severity::Critical, Severity::High => 'error',
            Severity::Medium => 'warning',
            Severity::Low => 'note',
        };
    }

    // File, then line; the rest only makes the order deterministic.
    private static function compare(Vulnerability $a, Vulnerability $b): int
    {
        return [$a->file, $a->line, $a->category->value, $a->symbol, $a->title, $a->fingerprint]
            <=> [$b->file, $b->line, $b->category->value, $b->symbol, $b->title, $b->fingerprint];
    }
}
