<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Output;

use Opis\JsonSchema\Errors\ErrorFormatter;
use Opis\JsonSchema\Validator;
use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Analysis\Category;
use TusharKhan\SemanticSec\Analysis\Confidence;
use TusharKhan\SemanticSec\Analysis\Severity;
use TusharKhan\SemanticSec\Engine\AnalysisResult;
use TusharKhan\SemanticSec\Engine\Vulnerability;
use TusharKhan\SemanticSec\Output\Formatter;
use TusharKhan\SemanticSec\Output\SarifFormatter;
use TusharKhan\SemanticSec\Parsing\Suppression;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkReplay;

final class SarifFormatterTest extends TestCase
{
    private const SCHEMA = __DIR__.'/../../Fixtures/sarif-schema-2.1.0.json';

    private const META = ['tool' => 'semantic-sec', 'version' => '0.7.0', 'provider' => 'anthropic', 'model' => 'claude-opus-5-5', 'level' => 'low', 'budget' => null, 'exitCode' => 1, 'strictReason' => null];

    // Keywords whose meaning is identical in draft-04 and draft-07, so the vendored schema can be validated as draft-07.
    private const SAME_IN_04_AND_07 = ['$schema', 'id', 'title', 'description', 'type', '$ref', 'default', 'items', 'uniqueItems', 'minItems', 'additionalProperties', 'properties', 'required', 'minimum', 'maximum', 'pattern', 'format', 'enum', 'anyOf', 'oneOf', 'definitions'];

    private const SECURITY_SEVERITY = ['CWE-502' => '9.1', 'CWE-862' => '8.5', 'CWE-639' => '8.1', 'CWE-915' => '7.5', 'CWE-841' => '5.5'];

    private static ?AnalysisResult $replayed = null;

    public function testIsAFormatter(): void
    {
        self::assertInstanceOf(Formatter::class, new SarifFormatter());
    }

    public function testSchemaIsTheVendoredOfficialOne(): void
    {
        $raw = json_decode((string) file_get_contents(self::SCHEMA), true, 512, JSON_THROW_ON_ERROR);
        self::assertSame('http://json-schema.org/draft-04/schema#', $raw['$schema']);
        self::assertSame('https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json', $raw['id']);
        self::assertSame([], array_values(array_diff(self::keywords($raw), self::SAME_IN_04_AND_07)), 'a draft-04-only keyword would change meaning under draft-07');
        self::assertStringContainsString('oasis-tcs/sarif-spec', (string) file_get_contents(self::SCHEMA.'.source'));
    }

    public function testValidatorIsStrict(): void
    {
        $doc = self::decode((new SarifFormatter())->format(self::analysis([[self::vuln(), true]]), self::META));
        self::assertSame([], self::schemaErrors($doc));

        $loc = '/runs/0/results/0/locations/0/physicalLocation';
        $badUri = $doc;
        $badUri['runs'][0]['results'][0]['locations'][0]['physicalLocation']['artifactLocation']['uri'] = 'a b';
        self::assertSchemaCause($loc.'/artifactLocation/uri: The data must match the \'uri-reference\' format', $badUri);
        $badLine = $doc;
        $badLine['runs'][0]['results'][0]['locations'][0]['physicalLocation']['region']['startLine'] = 0;
        self::assertSchemaCause($loc.'/region/startLine: Number must be greater than or equal to 1', $badLine);
        $badFix = $doc;
        $badFix['runs'][0]['results'][0]['fixes'] = [['description' => ['text' => 'x']]];
        self::assertSchemaCause('/runs/0/results/0/fixes/0: The required properties (artifactChanges) are missing', $badFix);
        $badLevel = $doc;
        $badLevel['runs'][0]['results'][0]['level'] = 'critical';
        self::assertSchemaCause('/runs/0/results/0/level: The data should match one item from enum', $badLevel);
    }

    public function testValidatesAgainstOfficialSchema(): void
    {
        $sup = self::vuln(['title' => 'quiet', 'fingerprint' => str_repeat('b', 64)]);
        $base = self::vuln(['title' => 'known', 'fingerprint' => str_repeat('c', 64), 'patch' => "@@ -1 +1 @@\n-a\n+b"]);
        $mixed = new AnalysisResult(
            [['vulnerability' => self::vuln(['path' => [['file' => 'routes/api.php', 'line' => 4, 'symbol' => 'route'], ['file' => 'app/A.php', 'line' => 0, 'symbol' => 'App\A::show']]]), 'failing' => true]],
            [['vulnerability' => $sup, 'suppression' => new Suppression('app/S.php', Category::Idor, 1, 9, 1, 'ok')], ['vulnerability' => $sup, 'suppression' => new Suppression('app/S.php', null, 1, 9, 1, null)]],
            [$base],
            ['warn'],
            self::stats(),
            [self::vuln(['severity' => 'low'])],
        );

        foreach (['replayed benchmark' => self::replay(), 'empty run' => new AnalysisResult([], [], [], [], self::stats()), 'suppressed and baselined' => $mixed] as $name => $result) {
            $doc = self::decode((new SarifFormatter())->format($result, self::META));
            self::assertSame([], self::schemaErrors($doc), $name);
            self::assertSame('2.1.0', $doc['version']);
            self::assertCount(1, $doc['runs']);
        }
        self::assertCount(1, self::decode((new SarifFormatter())->format($mixed, self::META))['runs'][0]['results'], 'only the live finding');
        $empty = self::decode((new SarifFormatter())->format(new AnalysisResult([], [], [], [], self::stats()), self::META));
        self::assertSame([], $empty['runs'][0]['results']);
        self::assertCount(5, $empty['runs'][0]['tool']['driver']['rules']);
    }

    public function testDriverAndRules(): void
    {
        $doc = self::decode((new SarifFormatter())->format(self::analysis([]), self::META));
        $driver = $doc['runs'][0]['tool']['driver'];

        self::assertStringContainsString('sarif-schema-2.1.0.json', $doc['$schema']);
        self::assertSame('semantic-sec', $driver['name']);
        self::assertSame('0.7.0', $driver['version']);
        self::assertSame('https://github.com/tusharkhan/semantic-sec', $driver['informationUri']);
        self::assertSame(['CWE-639', 'CWE-862', 'CWE-915', 'CWE-502', 'CWE-841'], array_column($driver['rules'], 'id'));
        foreach ($driver['rules'] as $i => $rule) {
            $category = Category::cases()[$i];
            $n = substr($category->cweId(), 4);
            self::assertSame(['id', 'name', 'shortDescription', 'fullDescription', 'help', 'helpUri', 'properties'], array_keys($rule));
            self::assertMatchesRegularExpression('~^[A-Z][A-Za-z]+$~', $rule['name']);
            self::assertSame($category->label(), $rule['shortDescription']['text']);
            self::assertGreaterThan(40, mb_strlen($rule['fullDescription']['text']));
            self::assertSame(['text', 'markdown'], array_keys($rule['help']));
            self::assertStringContainsString('Laravel', $rule['help']['text']);
            self::assertStringContainsString('Laravel', $rule['help']['markdown']);
            self::assertSame('https://cwe.mitre.org/data/definitions/'.$n.'.html', $rule['helpUri']);
            self::assertSame(['tags' => ['security', 'external/cwe/cwe-'.$n], 'precision' => 'high', 'security-severity' => self::SECURITY_SEVERITY[$rule['id']]], $rule['properties']);
            foreach ([$rule['shortDescription']['text'], $rule['fullDescription']['text']] as $text) {
                self::assertLessThanOrEqual(1024, mb_strlen($text));
            }
        }
        self::assertArrayNotHasKey('uri', $doc['runs'][0]['originalUriBaseIds']['%SRCROOT%'], 'no absolute project path');
    }

    public function testResultShape(): void
    {
        $v = self::vuln(['category' => 'mass_assignment', 'title' => 'Mass assignment', 'flaw' => "line one\nline two", 'line' => 12]);
        $r = self::decode((new SarifFormatter())->format(self::analysis([[$v, true]]), self::META))['runs'][0]['results'][0];

        self::assertSame('CWE-915', $r['ruleId']);
        self::assertSame(2, $r['ruleIndex']);
        self::assertSame("Mass assignment\n\nline one\nline two", $r['message']['text']);
        self::assertSame(['uri' => 'app/A.php', 'uriBaseId' => '%SRCROOT%'], $r['locations'][0]['physicalLocation']['artifactLocation']);
        self::assertSame(['startLine' => 12], $r['locations'][0]['physicalLocation']['region']);
        self::assertSame(['severity' => 'high', 'confidence' => 'high', 'failing' => true, 'category' => 'mass_assignment', 'symbol' => 'App\A::show', 'routeKey' => 'GET /a/{id}', 'fix' => 'fix'], $r['properties']);
        self::assertArrayNotHasKey('suppressions', $r);
        self::assertArrayNotHasKey('baselineState', $r);
    }

    public function testLevelsMapping(): void
    {
        $findings = [];
        foreach (['critical', 'high', 'medium', 'low'] as $i => $s) {
            $findings[] = [self::vuln(['severity' => $s, 'line' => $i + 1]), true];
        }
        $results = self::decode((new SarifFormatter())->format(self::analysis($findings), self::META))['runs'][0]['results'];

        self::assertSame(['error', 'error', 'warning', 'note'], array_column($results, 'level'));
        self::assertSame(['critical', 'high', 'medium', 'low'], array_map(static fn (array $r): string => $r['properties']['severity'], $results));
    }

    public function testPartialFingerprintStable(): void
    {
        $result = self::replay();
        $first = (new SarifFormatter())->format($result, self::META);
        $doc = self::decode($first);

        self::assertSame($first, (new SarifFormatter())->format($result, self::META));
        $expected = array_map(static fn (array $f): string => $f['vulnerability']->fingerprint, $result->findings);
        $actual = array_map(static fn (array $r): string => $r['partialFingerprints']['semanticSec/v1'], $doc['runs'][0]['results']);
        self::assertCount(13, $actual);
        self::assertCount(1, $result->suppressed);
        self::assertSame(1, $doc['runs'][0]['properties']['summary']['suppressed']);
        sort($expected);
        sort($actual);
        self::assertSame($expected, $actual);
        foreach ($doc['runs'][0]['results'] as $r) {
            self::assertSame(['semanticSec/v1'], array_keys($r['partialFingerprints']));
        }

        $fp = 'sk-ant-api03-'.str_repeat('a', 51);
        $r = self::decode((new SarifFormatter())->format(self::analysis([[self::vuln(['fingerprint' => $fp, 'file' => 'app/AKIAIOSFODNN7EXAMPLE.php']), true]]), self::META))['runs'][0]['results'][0];
        self::assertSame($fp, $r['partialFingerprints']['semanticSec/v1'], 'never redacted');
        self::assertSame('app/AKIAIOSFODNN7EXAMPLE.php', $r['locations'][0]['physicalLocation']['artifactLocation']['uri']);
    }

    public function testFixesOnlyWithPatch(): void
    {
        $with = self::vuln(['fix' => 'Scope the query.', 'patch' => "@@ -1,2 +1,2 @@\n-\$a = A::find(\$id);\n+\$a = \$user->as()->findOrFail(\$id);"]);
        $without = self::vuln(['line' => 2, 'fix' => 'Scope the query.']);
        $results = self::decode((new SarifFormatter())->format(self::analysis([[$with, true], [$without, true]]), self::META))['runs'][0]['results'];

        foreach ($results as $r) {
            self::assertArrayNotHasKey('fixes', $r, 'SARIF fixes require artifactChanges, which a model diff cannot give reliably');
            self::assertSame('Scope the query.', $r['properties']['fix']);
        }
        self::assertSame("@@ -1,2 +1,2 @@\n-\$a = A::find(\$id);\n+\$a = \$user->as()->findOrFail(\$id);", $results[0]['properties']['patch']);
        self::assertArrayNotHasKey('patch', $results[1]['properties']);
    }

    public function testCodeFlowFromPath(): void
    {
        $path = [['file' => 'routes/api.php', 'line' => 7, 'symbol' => 'GET /a/{id}'], ['file' => 'app/Http/A.php', 'line' => 0, 'symbol' => 'App\A::show']];
        $results = self::decode((new SarifFormatter())->format(self::analysis([[self::vuln(['path' => $path]), true], [self::vuln(['line' => 2]), true]]), self::META))['runs'][0]['results'];

        $locations = $results[0]['codeFlows'][0]['threadFlows'][0]['locations'];
        self::assertCount(2, $locations);
        self::assertSame(['physicalLocation' => ['artifactLocation' => ['uri' => 'routes/api.php', 'uriBaseId' => '%SRCROOT%'], 'region' => ['startLine' => 7]], 'message' => ['text' => 'GET /a/{id}']], $locations[0]['location']);
        self::assertArrayNotHasKey('region', $locations[1]['location']['physicalLocation'], 'line 0 has no region rather than an invalid one');
        self::assertArrayNotHasKey('codeFlows', $results[1]);
    }

    public function testSuppressedAndBaselinedAreCountsNotResults(): void
    {
        $sup = self::vuln(['title' => 'quiet', 'fingerprint' => str_repeat('b', 64)]);
        $live = self::vuln(['title' => 'live', 'line' => 5]);
        $result = new AnalysisResult([['vulnerability' => $live, 'failing' => true]], [['vulnerability' => $sup, 'suppression' => new Suppression('app/S.php', Category::Idor, 1, 9, 1, 'reviewed')], ['vulnerability' => $sup, 'suppression' => new Suppression('app/S.php', null, 1, 9, 1, null)]], [self::vuln(['title' => 'known', 'fingerprint' => str_repeat('c', 64)])], [], [...self::stats(), 'filtered' => 1], [self::vuln(['title' => 'below'])]);
        $out = (new SarifFormatter())->format($result, self::META);
        $run = self::decode($out)['runs'][0];

        self::assertSame(['live'], array_map(static fn (array $r): string => $r['message']['text'], $run['results']), 'GitHub would open suppressed and baselined results as live alerts');
        self::assertStringNotContainsString('suppressions', $out);
        self::assertStringNotContainsString('baselineState', $out);
        self::assertStringNotContainsString(str_repeat('b', 64), $out);
        self::assertSame(2, $run['properties']['summary']['suppressed']);
        self::assertSame(1, $run['properties']['summary']['baselined']);
        self::assertSame(1, $run['properties']['summary']['filtered']);
    }

    public function testLengthCaps(): void
    {
        $title = str_repeat("a\u{00E9}", 200_000);
        $long = str_repeat("\u{1F600}x", 10_000);
        $v = self::vuln(['title' => $title, 'flaw' => $long, 'fix' => $long, 'patch' => $long]);
        $out = (new SarifFormatter())->format(self::analysis([[$v, true]]), self::META);
        $doc = self::decode($out);
        $r = $doc['runs'][0]['results'][0];

        self::assertLessThan(64_000, strlen($out));
        self::assertSame([], self::schemaErrors($doc));
        self::assertSame(4000, mb_strlen($r['message']['text']));
        self::assertStringEndsWith("a\u{00E9}a\u{00E9}a…", $r['message']['text']);
        self::assertSame(8000, mb_strlen($r['properties']['fix']));
        self::assertSame(8000, mb_strlen($r['properties']['patch']));
        self::assertStringEndsWith("\u{1F600}x\u{1F600}…", $r['properties']['patch'], 'cut on a character boundary');
        foreach ([$r['message']['text'], $r['properties']['fix'], $r['properties']['patch']] as $text) {
            self::assertSame(1, preg_match('//u', $text));
        }

        $short = self::decode((new SarifFormatter())->format(self::analysis([[self::vuln(['title' => str_repeat('t', 10), 'flaw' => str_repeat('f', 3988)]), true]]), self::META));
        self::assertSame(str_repeat('t', 10)."\n\n".str_repeat('f', 3988), $short['runs'][0]['results'][0]['message']['text'], 'exactly 4000 is not cut');
    }

    public function testRelativeUris(): void
    {
        $base = sys_get_temp_dir();
        $out = (new SarifFormatter())->format(self::replay(), self::META);
        $doc = self::decode($out);

        self::assertStringNotContainsString($base.'/', $out);
        self::assertStringNotContainsString('semsec-', $out);
        foreach ($doc['runs'][0]['results'] as $r) {
            $loc = $r['locations'][0]['physicalLocation'];
            self::assertSame('%SRCROOT%', $loc['artifactLocation']['uriBaseId']);
            self::assertMatchesRegularExpression('~^(app|routes)/[A-Za-z0-9/_.-]+\.php$~', $loc['artifactLocation']['uri']);
            self::assertGreaterThanOrEqual(1, $loc['region']['startLine']);
            foreach ($r['codeFlows'][0]['threadFlows'][0]['locations'] ?? [] as $step) {
                self::assertStringStartsNotWith('/', $step['location']['physicalLocation']['artifactLocation']['uri']);
            }
        }
        $odd = self::decode((new SarifFormatter())->format(self::analysis([[self::vuln(['file' => 'app/My Ctrl:x#1?.php']), true]]), self::META));
        self::assertSame('app/My%20Ctrl%3Ax%231%3F.php', $odd['runs'][0]['results'][0]['locations'][0]['physicalLocation']['artifactLocation']['uri']);
        self::assertSame([], self::schemaErrors($odd));
    }

    public function testHostileTextStillValid(): void
    {
        $evil = "Evil \e[2J\e]0;pwned\x07 <error>x</error>\nInjected: line </script> \"q\" \\ \u{202E}rtl \xC3\x28 \0 end";
        $v = self::vuln(['title' => $evil, 'file' => "app/\e[31mEvil \xC3\x28.php", 'symbol' => $evil, 'context' => $evil, 'flaw' => $evil, 'fix' => $evil, 'patch' => "+ \e[2J<error>p</error>\n-\tok\\", 'model' => $evil, 'routeKey' => "GET /\e[2J", 'path' => [['file' => "app/\e.php", 'line' => 3, 'symbol' => $evil]]]);
        $s = new Suppression('app/S.php', Category::Idor, 1, 9, 1, "r\e[2J\0");
        $result = new AnalysisResult([['vulnerability' => $v, 'failing' => true]], [['vulnerability' => $v, 'suppression' => $s]], [$v], ["warn \e[2J"], self::stats(), [$v]);
        $out = (new SarifFormatter())->format($result, [...self::META, 'tool' => "t\e[2J", 'version' => "1\x07"]);
        $doc = self::decode($out);

        self::assertSame([], self::schemaErrors($doc));
        foreach (["\e", "\x07", "\0", "\u{202E}"] as $bad) {
            self::assertStringNotContainsString($bad, $out);
            self::assertStringNotContainsString(substr((string) json_encode($bad), 1, -1), $out);
        }
        $r = $doc['runs'][0]['results'][0];
        self::assertStringContainsString('<error>x</error>', $r['message']['text'], 'no console-tag escaping');
        self::assertStringContainsString('</script> "q" \\', $r['message']['text']);
        self::assertStringContainsString("\u{FFFD}", $r['message']['text']);
        self::assertStringNotContainsString("\n", $r['properties']['symbol']);
        self::assertSame('app/%1B%5B31mEvil%20%C3%28.php', $r['locations'][0]['physicalLocation']['artifactLocation']['uri'], 'paths are percent-encoded, not altered');
        self::assertSame("+  [2J<error>p</error>\n-    ok\\", $r['properties']['patch']);
    }

    // The leaf error is the cause; opis also reports each ancestor's additionalProperties as failed.
    /** @param array<mixed> $doc */
    private static function assertSchemaCause(string $expected, array $doc): void
    {
        $errors = self::schemaErrors($doc);
        self::assertSame($expected, $errors[0] ?? null);
        foreach (array_slice($errors, 1) as $e) {
            self::assertMatchesRegularExpression('~^/[^:]*: Additional object properties are not allowed: ~', $e);
        }
    }

    /**
     * @param  array<mixed>  $schema
     * @return list<string>
     */
    private static function keywords(array $schema, bool $named = false): array
    {
        $out = [];
        foreach ($schema as $k => $v) {
            if (! $named) {
                $out[] = (string) $k;
            }
            if (is_array($v)) {
                $out = [...$out, ...self::keywords($v, ! $named && in_array($k, ['properties', 'definitions'], true))];
            }
        }

        return array_values(array_unique(array_filter($out, static fn (string $k): bool => ! is_numeric($k))));
    }

    /**
     * Validates with opis, which has no draft-04 support; the schema only uses keywords that mean the same in draft-07.
     *
     * @param  array<mixed>  $doc
     * @return list<string>
     */
    private static function schemaErrors(array $doc): array
    {
        $schema = json_decode((string) file_get_contents(self::SCHEMA), false, 512, JSON_THROW_ON_ERROR);
        $schema->{'$schema'} = 'http://json-schema.org/draft-07/schema#';
        $schema->{'$id'} = $schema->id;
        unset($schema->id);
        $data = json_decode((string) json_encode($doc, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), false, 512, JSON_THROW_ON_ERROR);
        $result = (new Validator())->setStopAtFirstError(false)->validate($data, $schema);
        $error = $result->error();
        if ($error === null) {
            return [];
        }
        $errors = [];
        foreach ((new ErrorFormatter())->format($error, true) as $path => $messages) {
            foreach ($messages as $m) {
                $errors[] = $path.': '.$m;
            }
        }

        return $errors === [] ? ['invalid'] : $errors;
    }

    private static function replay(): AnalysisResult
    {
        if (self::$replayed !== null) {
            return self::$replayed;
        }
        $base = sys_get_temp_dir().'/semsec-sarif-'.bin2hex(random_bytes(4));
        mkdir($base, 0777, true);
        try {
            exec('cp -R '.escapeshellarg(BenchmarkCorpus::root().'/laravel11-app').' '.escapeshellarg($base.'/app'), $out, $code);
            self::assertSame(0, $code);

            return self::$replayed = BenchmarkReplay::run($base.'/app');
        } finally {
            exec('rm -rf '.escapeshellarg($base));
        }
    }

    /** @return array<string, mixed> */
    private static function decode(string $json): array
    {
        self::assertStringEndsWith("}\n", $json);
        $doc = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($doc);

        return $doc;
    }

    /** @param list<array{Vulnerability, bool}> $findings */
    private static function analysis(array $findings): AnalysisResult
    {
        return new AnalysisResult(array_map(static fn (array $f): array => ['vulnerability' => $f[0], 'failing' => $f[1]], $findings), [], [], [], self::stats());
    }

    /** @return array{candidates:int, payloads:int, skipped:int, unaffected:int, unsent:int, sent:int, cacheHits:int, ok:int, refused:int, truncated:int, invalid:int, failed:int, dropped:int, filtered:int, tokens:int, budgetExceeded:bool} */
    private static function stats(): array
    {
        return ['candidates' => 1, 'payloads' => 1, 'skipped' => 0, 'unaffected' => 0, 'unsent' => 0, 'sent' => 1, 'cacheHits' => 0, 'ok' => 1, 'refused' => 0, 'truncated' => 0, 'invalid' => 0, 'failed' => 0, 'dropped' => 0, 'filtered' => 0, 'tokens' => 110, 'budgetExceeded' => false];
    }

    /** @param array<string, mixed> $o */
    private static function vuln(array $o = []): Vulnerability
    {
        /** @var list<array{file:string,line:int,symbol:string}> $path */
        $path = $o['path'] ?? [];

        return new Vulnerability(
            Category::from((string) ($o['category'] ?? 'idor')),
            Severity::from((string) ($o['severity'] ?? 'high')),
            Confidence::from((string) ($o['confidence'] ?? 'high')),
            (string) ($o['title'] ?? 'IDOR'),
            (string) ($o['file'] ?? 'app/A.php'),
            (int) ($o['line'] ?? 1),
            (string) ($o['symbol'] ?? 'App\A::show'),
            (string) ($o['context'] ?? 'context'),
            (string) ($o['flaw'] ?? ''),
            (string) ($o['fix'] ?? 'fix'),
            (string) ($o['patch'] ?? ''),
            $path,
            (string) ($o['routeKey'] ?? 'GET /a/{id}'),
            '001-get-a-id-1',
            (string) ($o['model'] ?? 'm'),
            (string) ($o['fingerprint'] ?? str_repeat('a', 64)),
        );
    }
}
