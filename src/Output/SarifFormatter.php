<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Output;

use TusharKhan\SemanticSec\Analysis\Category;
use TusharKhan\SemanticSec\Analysis\Severity;
use TusharKhan\SemanticSec\Console\Terminal;
use TusharKhan\SemanticSec\Engine\AnalysisResult;
use TusharKhan\SemanticSec\Engine\Vulnerability;

/**
 * SPEC §14 SARIF 2.1.0 log: one run, one rule per category, reported findings only as results; suppressed and baselined ones are counts in run.properties.summary.
 *
 * @phpstan-import-type Meta from Formatter
 */
final class SarifFormatter implements Formatter
{
    public const SCHEMA = 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json';

    public const INFORMATION_URI = 'https://github.com/tusharkhan/semantic-sec';

    public const FINGERPRINT_KEY = 'semanticSec/v1';

    private const SRCROOT = '%SRCROOT%';

    private const MESSAGE_CAP = 4000;

    private const DESCRIPTION_CAP = 1024;

    private const PROPERTY_CAP = 8000;

    // GitHub's 0–10 score per category, as a string.
    private const SECURITY_SEVERITY = [
        'insecure_deserialization' => '9.1',
        'missing_authorization' => '8.5',
        'idor' => '8.1',
        'mass_assignment' => '7.5',
        'workflow_bypass' => '5.5',
    ];

    // Per category: the flaw class, the generic remedy, the Laravel remedy.
    private const RULES = [
        'idor' => [
            'A record is looked up by an identifier the client controls, and nothing checks that the current user may access that record, so changing the id exposes or modifies other users\' data.',
            'Check ownership or a permission for the specific record before reading or changing it.',
            'scope the lookup to the user (`$request->user()->invoices()->findOrFail($id)`), or call `$this->authorize(\'view\', $invoice)` / `Gate::authorize()` with a policy, or use scoped route model binding.',
        ],
        'missing_authorization' => [
            'An action that reads or changes protected data runs for any caller who reaches the route, because no authentication or permission check guards it.',
            'Require authentication and an explicit permission check for every sensitive action.',
            'put the route behind `auth` (or `auth:sanctum`) middleware and authorize the action with a policy, `can:` middleware, `$this->authorize()` or a FormRequest `authorize()` that does not just return true.',
        ],
        'mass_assignment' => [
            'Client input is written to a model in bulk, so the client can set attributes it should never control, such as an owner id, a role or a balance.',
            'Write only an explicit allow-list of fields.',
            'pass `$request->validated()` or `$request->only([...])` to `create()`/`update()`/`fill()` rather than `$request->all()`, and give the model a `$fillable` list instead of `$guarded = []`.',
        ],
        'insecure_deserialization' => [
            'Data an attacker can influence is deserialized into PHP objects, which can trigger gadget chains in magic methods and lead to code execution.',
            'Never deserialize untrusted input into objects; use a data-only format.',
            'replace `unserialize()` on request, cookie or cache data with `json_decode()`, pass `[\'allowed_classes\' => false]` when unserialize is unavoidable, and keep values encrypted and signed with `Crypt`.',
        ],
        'workflow_bypass' => [
            'A multi-step process can be skipped or replayed because an action does not check that the record is in the state the workflow requires.',
            'Check the current state, and the actor\'s right to make the transition, before every state change.',
            'check the model\'s status (or use a state machine) before the transition, authorize the transition in a policy, and update inside a transaction with a conditional `where(\'status\', ...)` so concurrent requests cannot both succeed.',
        ],
    ];

    private const FLAGS = JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR;

    /** @param Meta $meta */
    public function format(AnalysisResult $r, array $meta): string
    {
        $findings = $r->findings;
        usort($findings, static fn (array $a, array $b): int => self::compare($a['vulnerability'], $b['vulnerability']));
        // Suppressed and baselined findings are counts only: GitHub would open them as live alerts.
        $results = array_map(static fn (array $f): array => self::result($f['vulnerability'], $f['failing']), $findings);

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
                    'suppressed' => count($r->suppressed),
                    'baselined' => count($r->baselined),
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
        $n = substr($c->cweId(), 4);

        return [
            'id' => $c->cweId(),
            'name' => match ($c) {
                Category::Idor => 'InsecureDirectObjectReference',
                Category::MissingAuthorization => 'MissingAuthorization',
                Category::MassAssignment => 'MassAssignment',
                Category::InsecureDeserialization => 'InsecureDeserialization',
                Category::WorkflowBypass => 'WorkflowBypass',
            },
            'shortDescription' => ['text' => self::cap($c->label(), self::DESCRIPTION_CAP)],
            'fullDescription' => ['text' => self::cap(self::RULES[$c->value][0], self::DESCRIPTION_CAP)],
            'help' => [
                'text' => self::RULES[$c->value][0].' '.self::RULES[$c->value][1].' Fix in Laravel: '.self::RULES[$c->value][2],
                'markdown' => '**'.$c->label().'** ('.$c->cweId().')'."\n\n".self::RULES[$c->value][0].' '.self::RULES[$c->value][1]."\n\n".'**Fix in Laravel:** '.self::RULES[$c->value][2],
            ],
            'helpUri' => 'https://cwe.mitre.org/data/definitions/'.$n.'.html',
            'properties' => [
                'tags' => ['security', 'external/cwe/cwe-'.$n],
                'precision' => 'high',
                'security-severity' => self::SECURITY_SEVERITY[$c->value],
            ],
        ];
    }

    // Cuts to at most $max characters, ending in an ellipsis; expects valid UTF-8, so the cut is on a character boundary.
    private static function cap(string $text, int $max): string
    {
        return mb_strlen($text, 'UTF-8') <= $max ? $text : mb_substr($text, 0, $max - 1, 'UTF-8').'…';
    }

    /** @return array<string, mixed> */
    private static function result(Vulnerability $v, bool $failing): array
    {
        $title = Terminal::clean($v->title);
        $flaw = Terminal::block($v->flaw);
        $out = [
            'ruleId' => $v->category->cweId(),
            'ruleIndex' => (int) array_search($v->category, Category::cases(), true),
            // A non-failing finding (below --min-confidence) never shows as an error or warning.
            'level' => $failing ? self::level($v->severity) : 'note',
            'message' => ['text' => self::cap(trim($flaw) === '' ? $title : $title."\n\n".$flaw, self::MESSAGE_CAP)],
            'locations' => [['physicalLocation' => self::physical($v->file, $v->line)]],
            'partialFingerprints' => [self::FINGERPRINT_KEY => $v->fingerprint],
        ];
        if ($v->path !== []) {
            $out['codeFlows'] = [['threadFlows' => [['locations' => array_map(static fn (array $s): array => ['location' => [
                'physicalLocation' => self::physical($s['file'], $s['line']),
                'message' => ['text' => Terminal::clean($s['symbol'])],
            ]], $v->path)]]]];
        }
        $out['properties'] = [
            'severity' => $v->severity->value,
            'confidence' => $v->confidence->value,
            'failing' => $failing,
            'category' => $v->category->value,
            'symbol' => Terminal::clean($v->symbol),
            'routeKey' => Terminal::clean($v->routeKey),
            'fix' => self::cap(Terminal::block($v->fix), self::PROPERTY_CAP),
        ];
        // SARIF `fixes` require exact artifactChanges, which a model diff cannot give reliably.
        if ($v->patch !== '') {
            $out['properties']['patch'] = self::cap(Terminal::block($v->patch), self::PROPERTY_CAP);
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
