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
use TusharKhan\SemanticSec\Output\GitlabSastFormatter;
use TusharKhan\SemanticSec\Parsing\Suppression;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkReplay;

final class GitlabSastFormatterTest extends TestCase
{
    private const SCHEMA = __DIR__.'/../../Fixtures/gitlab-sast-report-format.json';

    private const SNAPSHOT = __DIR__.'/../../Fixtures/snapshots/gitlab-sast-benchmark.json';

    // 2026-11-01T10:00:00Z and 2026-11-01T10:02:05Z.
    private const META = ['tool' => 'semantic-sec', 'version' => '0.7.0', 'provider' => 'anthropic', 'model' => 'claude-opus-5-5', 'level' => 'low', 'budget' => null, 'exitCode' => 1, 'strictReason' => null, 'startedAt' => 1793527200, 'finishedAt' => 1793527325];

    private static ?AnalysisResult $replayed = null;

    public function testIsAFormatter(): void
    {
        self::assertInstanceOf(Formatter::class, new GitlabSastFormatter());
    }

    public function testSchemaIsTheVendoredOfficialOne(): void
    {
        $raw = json_decode((string) file_get_contents(self::SCHEMA), true, 512, JSON_THROW_ON_ERROR);
        self::assertSame('http://json-schema.org/draft-07/schema#', $raw['$schema']);
        self::assertSame(['version' => '15.2.5'], $raw['self']);
        self::assertSame(GitlabSastFormatter::SCHEMA_VERSION, $raw['self']['version']);
        self::assertSame('1d2d2717fe7bd7bc5f3428bcfc4c3f2b7d60dbe27482602f99041da57afc33d8', hash_file('sha256', self::SCHEMA));
        self::assertStringContainsString('SHA-256: 1d2d2717fe7bd7bc5f3428bcfc4c3f2b7d60dbe27482602f99041da57afc33d8', (string) file_get_contents(self::SCHEMA.'.source'));
        self::assertStringContainsString('security-report-schemas/-/raw/v15.2.5/dist/sast-report-format.json', (string) file_get_contents(self::SCHEMA.'.source'));
    }

    public function testValidatorIsStrict(): void
    {
        $doc = self::decode((new GitlabSastFormatter())->format(self::analysis([[self::vuln(), true]]), self::META));
        self::assertSame([], self::schemaErrors($doc));

        $badSeverity = $doc;
        $badSeverity['vulnerabilities'][0]['severity'] = 'high';
        self::assertContains('/vulnerabilities/0/severity: The data should match one item from enum', self::schemaErrors($badSeverity));
        $badTime = $doc;
        $badTime['scan']['start_time'] = '2026-11-01T10:00:00Z';
        self::assertContains('/scan/start_time: The string should match pattern: ^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$', self::schemaErrors($badTime));
        $noIdentifiers = $doc;
        $noIdentifiers['vulnerabilities'][0]['identifiers'] = [];
        self::assertNotSame([], self::schemaErrors($noIdentifiers));
        $longName = $doc;
        $longName['vulnerabilities'][0]['name'] = str_repeat('é', 256);
        self::assertNotSame([], self::schemaErrors($longName), 'maxLength counts characters');
        $badLine = $doc;
        $badLine['vulnerabilities'][0]['location']['start_line'] = '12';
        self::assertContains('/vulnerabilities/0/location/start_line: The data (string) must match the type: number', self::schemaErrors($badLine));
    }

    public function testValidatesAgainstOfficialSchema(): void
    {
        $sup = self::vuln(['title' => 'quiet', 'fingerprint' => str_repeat('b', 64)]);
        $base = self::vuln(['title' => 'known', 'fingerprint' => str_repeat('c', 64)]);
        $mixed = new AnalysisResult(
            [['vulnerability' => self::vuln(['title' => 'live']), 'failing' => true]],
            [['vulnerability' => $sup, 'suppression' => new Suppression('app/S.php', Category::Idor, 1, 9, 1, 'ok')]],
            [$base],
            ['warn'],
            self::stats(),
            [self::vuln(['severity' => 'low', 'fingerprint' => str_repeat('d', 64)])],
        );
        $evil = "Evil \e[2J\e]0;pwned\x07 <b>x</b>\n\u{202E}rtl \u{2066}iso\u{2069} \xC3\x28 \0 \u{2028} end";
        $hostile = self::analysis([[self::vuln(['title' => $evil.str_repeat('t', 300_000), 'flaw' => $evil.str_repeat("\u{1F600}", 200_000), 'fix' => $evil.str_repeat('f', 20_000), 'symbol' => $evil, 'file' => "app/\e[31mEvil \xC3\x28.php"]), true]]);

        $cases = ['replayed benchmark' => self::replay(), 'empty run' => new AnalysisResult([], [], [], [], self::stats()), 'suppressed and baselined' => $mixed, 'hostile text' => $hostile];
        foreach ($cases as $name => $result) {
            $doc = self::decode((new GitlabSastFormatter())->format($result, self::META));
            self::assertSame([], self::schemaErrors($doc), $name);
            self::assertSame('15.2.5', $doc['version'], $name);
        }
        $mixedDoc = self::decode((new GitlabSastFormatter())->format($mixed, self::META));
        self::assertSame(['live'], array_column($mixedDoc['vulnerabilities'], 'name'), 'suppressed, baselined and filtered findings are left out');
        self::assertSame([], self::decode((new GitlabSastFormatter())->format($cases['empty run'], self::META))['vulnerabilities']);
    }

    public function testScanBlock(): void
    {
        $doc = self::decode((new GitlabSastFormatter())->format(self::analysis([]), self::META));
        $tool = ['id' => 'semantic_sec', 'name' => 'semantic-sec', 'url' => 'https://github.com/tusharkhan/semantic-sec', 'version' => '0.7.0', 'vendor' => ['name' => 'semantic-sec']];

        self::assertSame(['version', 'scan', 'vulnerabilities'], array_keys($doc));
        self::assertSame(['analyzer' => $tool, 'scanner' => $tool, 'type' => 'sast', 'start_time' => '2026-11-01T10:00:00', 'end_time' => '2026-11-01T10:02:05', 'status' => 'success'], $doc['scan']);

        foreach ([0 => 'success', 1 => 'success', 3 => 'success', 2 => 'failure'] as $exit => $status) {
            $scan = self::decode((new GitlabSastFormatter())->format(self::analysis([]), [...self::META, 'exitCode' => $exit]))['scan'];
            self::assertSame($status, $scan['status'], 'exit '.$exit);
        }

        $before = gmdate('Y-m-d\TH:i:s', time() - 1);
        $meta = self::META;
        unset($meta['startedAt'], $meta['finishedAt']);
        $now = self::decode((new GitlabSastFormatter())->format(self::analysis([]), $meta))['scan'];
        self::assertGreaterThanOrEqual($before, $now['start_time'], 'defaults to now, in UTC');
        self::assertSame([], self::schemaErrors(self::decode((new GitlabSastFormatter())->format(self::analysis([]), [...$meta, 'tool' => "\e", 'version' => "\x07"]))), 'empty tool strings still validate');
    }

    public function testVulnerabilityShape(): void
    {
        $v = self::vuln(['category' => 'mass_assignment', 'title' => 'Mass assignment', 'flaw' => "line one\nline two", 'fix' => "Use validated().\nOnly.", 'line' => 12]);
        $out = self::decode((new GitlabSastFormatter())->format(self::analysis([[$v, true]]), self::META))['vulnerabilities'][0];

        self::assertSame([
            'id' => '918ae4f7-81fe-55f2-95d0-13ad748130e3',
            'name' => 'Mass assignment',
            'description' => "line one\nline two",
            'severity' => 'High',
            'solution' => "Use validated().\nOnly.",
            'location' => ['file' => 'app/A.php', 'start_line' => 12],
            'identifiers' => [
                ['type' => 'semantic_sec_fingerprint', 'name' => 'semantic-sec aaaaaaaaaaaa', 'value' => str_repeat('a', 64)],
                ['type' => 'cwe', 'name' => 'CWE-915', 'value' => '915', 'url' => 'https://cwe.mitre.org/data/definitions/915.html'],
            ],
        ], $out);

        $bare = self::decode((new GitlabSastFormatter())->format(self::analysis([[self::vuln(['flaw' => '', 'fix' => '', 'line' => 0]), true]]), self::META))['vulnerabilities'][0];
        self::assertSame('IDOR', $bare['description'], 'falls back to the title');
        self::assertArrayNotHasKey('solution', $bare);
        self::assertSame(['file' => 'app/A.php'], $bare['location'], 'line 0 has no start_line');
    }

    public function testSeverityMapping(): void
    {
        $findings = [];
        foreach (['critical', 'high', 'medium', 'low'] as $i => $s) {
            $findings[] = [self::vuln(['severity' => $s, 'line' => $i + 1, 'fingerprint' => str_repeat((string) $i, 64)]), true];
        }
        $findings[] = [self::vuln(['severity' => 'critical', 'confidence' => 'low', 'line' => 9, 'fingerprint' => str_repeat('9', 64)]), false];
        $vulns = self::decode((new GitlabSastFormatter())->format(self::analysis($findings), self::META))['vulnerabilities'];

        self::assertSame(['Critical', 'High', 'Medium', 'Low', 'Info'], array_column($vulns, 'severity'), 'a non-failing finding is Info, like a SARIF note');
    }

    public function testStableIdsFromFingerprint(): void
    {
        $f = new GitlabSastFormatter();
        $a = self::decode($f->format(self::analysis([[self::vuln(), true]]), self::META))['vulnerabilities'][0]['id'];
        $moved = self::decode($f->format(self::analysis([[self::vuln(['line' => 40, 'title' => 'renamed', 'file' => 'app/B.php']), true]]), self::META))['vulnerabilities'][0]['id'];
        $b = self::decode($f->format(self::analysis([[self::vuln(['fingerprint' => str_repeat('b', 64)]), true]]), self::META))['vulnerabilities'][0]['id'];

        // Python: uuid5(uuid5(NAMESPACE_URL, "https://github.com/tusharkhan/semantic-sec#gitlab-sast"), fingerprint).
        self::assertSame('918ae4f7-81fe-55f2-95d0-13ad748130e3', $a);
        self::assertSame('871fc689-9a5f-529b-a19d-2e1539e633df', $b);
        self::assertSame($a, $moved, 'only the fingerprint decides the id');
        self::assertSame('84d1fcaf-52cc-5cb0-a675-4b8a9ad45331', GitlabSastFormatter::NAMESPACE);

        $result = self::replay();
        $doc = self::decode($f->format($result, self::META));
        self::assertSame($f->format($result, self::META), $f->format($result, self::META));
        $ids = array_column($doc['vulnerabilities'], 'id');
        self::assertCount(13, $ids);
        self::assertSame($ids, array_values(array_unique($ids)));
        foreach ($doc['vulnerabilities'] as $v) {
            self::assertMatchesRegularExpression('~^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$~', $v['id']);
            self::assertSame(GitlabSastFormatter::uuid($v['identifiers'][0]['value']), $v['id']);
        }
        $expected = array_map(static fn (array $x): string => $x['vulnerability']->fingerprint, $result->findings);
        $actual = array_map(static fn (array $v): string => $v['identifiers'][0]['value'], $doc['vulnerabilities']);
        sort($expected);
        sort($actual);
        self::assertSame($expected, $actual);

        $fp = 'sk-ant-api03-'.str_repeat('a', 51);
        $v = self::decode($f->format(self::analysis([[self::vuln(['fingerprint' => $fp, 'file' => 'app/AKIAIOSFODNN7EXAMPLE.php']), true]]), self::META))['vulnerabilities'][0];
        self::assertSame($fp, $v['identifiers'][0]['value'], 'never redacted');
        self::assertSame('app/AKIAIOSFODNN7EXAMPLE.php', $v['location']['file']);
    }

    public function testFingerprintIsThePrimaryIdentifier(): void
    {
        $two = self::analysis([[self::vuln(['line' => 3]), true], [self::vuln(['line' => 9, 'fingerprint' => str_repeat('b', 64)]), true]]);
        $vulns = self::decode((new GitlabSastFormatter())->format($two, self::META))['vulnerabilities'];

        foreach ($vulns as $v) {
            self::assertSame(['semantic_sec_fingerprint', 'cwe'], array_column($v['identifiers'], 'type'), 'GitLab tracks by the first identifier');
        }
        self::assertSame([str_repeat('a', 64), str_repeat('b', 64)], array_map(static fn (array $v): string => $v['identifiers'][0]['value'], $vulns), 'same CWE and file, still told apart');
        self::assertSame('semantic-sec bbbbbbbbbbbb', $vulns[1]['identifiers'][0]['name']);
        foreach (self::decode((new GitlabSastFormatter())->format(self::replay(), self::META))['vulnerabilities'] as $v) {
            self::assertSame('semantic_sec_fingerprint', $v['identifiers'][0]['type']);
        }
    }

    public function testFilePathsRootRelative(): void
    {
        $out = (new GitlabSastFormatter())->format(self::replay(), self::META);
        $doc = self::decode($out);

        self::assertStringNotContainsString(sys_get_temp_dir().'/', $out);
        self::assertStringNotContainsString('semsec-', $out);
        self::assertNotSame([], $doc['vulnerabilities']);
        foreach ($doc['vulnerabilities'] as $v) {
            self::assertMatchesRegularExpression('~^(app|routes)/[A-Za-z0-9/_.-]+\.php$~', $v['location']['file']);
            self::assertGreaterThanOrEqual(1, $v['location']['start_line']);
        }
        $odd = self::decode((new GitlabSastFormatter())->format(self::analysis([[self::vuln(['file' => 'app/My Ctrl:x#1?.php']), true]]), self::META));
        self::assertSame('app/My Ctrl:x#1?.php', $odd['vulnerabilities'][0]['location']['file'], 'a plain path, not a URI');
    }

    public function testHostileTextIsCleanedAndCapped(): void
    {
        $evil = "Evil \e[2J\e]0;pwned\x07 <error>x</error>\nInjected </script> \"q\" \\ \u{202E}rtl \u{200F}m \xC3\x28 \0 end";
        $v = self::vuln(['title' => $evil, 'file' => "app/\e[31mEvil \xC3\x28.php", 'flaw' => $evil, 'fix' => $evil]);
        $out = (new GitlabSastFormatter())->format(self::analysis([[$v, true]]), [...self::META, 'tool' => "t\e[2J", 'version' => "1\x07"]);
        $doc = self::decode($out);
        $r = $doc['vulnerabilities'][0];

        self::assertSame([], self::schemaErrors($doc));
        foreach (["\e", "\x07", "\0", "\u{202E}", "\u{200F}"] as $bad) {
            self::assertStringNotContainsString($bad, $out);
            self::assertStringNotContainsString(substr((string) json_encode($bad), 1, -1), $out);
        }
        self::assertStringNotContainsString("\n", $r['name']);
        self::assertStringContainsString("<error>x</error>\nInjected </script> \"q\" \\", $r['description'], 'no console escaping; line breaks kept');
        self::assertStringContainsString("\u{FFFD}", $r['description']);
        self::assertSame("app/ [31mEvil \u{FFFD}(.php", $r['location']['file'], 'controls become spaces; never redacted');

        $title = str_repeat("a\u{00E9}", 200_000);
        $long = str_repeat("\u{1F600}x", 10_000);
        $capped = self::decode((new GitlabSastFormatter())->format(self::analysis([[self::vuln(['title' => $title, 'flaw' => $long, 'fix' => $long]), true]]), self::META));
        $c = $capped['vulnerabilities'][0];
        self::assertSame([], self::schemaErrors($capped));
        self::assertSame(255, mb_strlen($c['name']));
        self::assertStringEndsWith('…', $c['name']);
        self::assertSame(4000, mb_strlen($c['description']));
        self::assertSame(7000, mb_strlen($c['solution']));
        self::assertStringEndsWith("\u{1F600}x\u{1F600}…", $c['solution'], 'cut on a character boundary');
        $exact = self::decode((new GitlabSastFormatter())->format(self::analysis([[self::vuln(['title' => str_repeat('t', 255), 'fix' => str_repeat('f', 7000)]), true]]), self::META))['vulnerabilities'][0];
        self::assertSame(str_repeat('t', 255), $exact['name'], 'exactly at the cap is not cut');
        self::assertSame(str_repeat('f', 7000), $exact['solution']);
    }

    public function testSnapshot(): void
    {
        $actual = (new GitlabSastFormatter())->format(self::replay(), self::META);

        if (getenv('UPDATE_SNAPSHOTS') === '1') {
            file_put_contents(self::SNAPSHOT, $actual);
        }
        self::assertFileExists(self::SNAPSHOT, 'run with UPDATE_SNAPSHOTS=1 to create it');
        self::assertSame(file_get_contents(self::SNAPSHOT), $actual);
    }

    /**
     * @param  array<mixed>  $doc
     * @return list<string>
     */
    private static function schemaErrors(array $doc): array
    {
        $schema = json_decode((string) file_get_contents(self::SCHEMA), false, 512, JSON_THROW_ON_ERROR);
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
        $base = sys_get_temp_dir().'/semsec-gitlab-'.bin2hex(random_bytes(4));
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
            [],
            (string) ($o['routeKey'] ?? 'GET /a/{id}'),
            '001-get-a-id-1',
            (string) ($o['model'] ?? 'm'),
            (string) ($o['fingerprint'] ?? str_repeat('a', 64)),
        );
    }
}
