<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Output;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Analysis\Category;
use TusharKhan\SemanticSec\Analysis\Confidence;
use TusharKhan\SemanticSec\Analysis\Severity;
use TusharKhan\SemanticSec\Engine\AnalysisResult;
use TusharKhan\SemanticSec\Engine\Vulnerability;
use TusharKhan\SemanticSec\Output\Formatter;
use TusharKhan\SemanticSec\Output\JsonFormatter;
use TusharKhan\SemanticSec\Parsing\Suppression;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkReplay;

final class JsonFormatterTest extends TestCase
{
    private const SNAPSHOT = __DIR__.'/../../Fixtures/snapshots/json-benchmark.json';

    private const META = ['tool' => 'semantic-sec', 'version' => 'snapshot', 'provider' => 'anthropic', 'model' => 'claude-opus-5-5', 'level' => 'low', 'budget' => null, 'exitCode' => 1, 'strictReason' => null];

    public function testIsAFormatter(): void
    {
        self::assertInstanceOf(Formatter::class, new JsonFormatter());
    }

    public function testSnapshotOverReplayedBenchmark(): void
    {
        $actual = (new JsonFormatter())->format(self::replay(), self::META);

        if (getenv('UPDATE_SNAPSHOTS') === '1') {
            file_put_contents(self::SNAPSHOT, $actual);
        }
        self::assertFileExists(self::SNAPSHOT, 'run with UPDATE_SNAPSHOTS=1 to create it');
        self::assertSame(file_get_contents(self::SNAPSHOT), $actual);
        self::assertStringNotContainsString(sys_get_temp_dir().'/', $actual);
        self::assertStringNotContainsString('semsec-', $actual);
    }

    public function testParsesAndHasEveryFindingWithFingerprint(): void
    {
        $result = self::replay();
        $doc = self::decode((new JsonFormatter())->format($result, self::META));

        self::assertSame(['version', 'tool', 'summary', 'findings', 'suppressed', 'baselined', 'filtered', 'warnings'], array_keys($doc));
        self::assertSame(1, $doc['version']);
        self::assertSame(['name' => 'semantic-sec', 'version' => 'snapshot'], $doc['tool']);
        self::assertCount(count($result->findings), $doc['findings']);
        self::assertCount(13, $doc['findings']);
        $keys = ['title', 'category', 'severity', 'confidence', 'file', 'line', 'symbol', 'context', 'flaw', 'fix', 'patch', 'path', 'fingerprint', 'failing', 'routeKey', 'model'];
        $expected = array_map(static fn (array $f): string => $f['vulnerability']->fingerprint, $result->findings);
        $actual = [];
        foreach ($doc['findings'] as $f) {
            self::assertSame($keys, array_keys($f));
            self::assertMatchesRegularExpression('~^[0-9a-f]{64}$~', $f['fingerprint']);
            $actual[] = $f['fingerprint'];
        }
        sort($expected);
        sort($actual);
        self::assertSame($expected, $actual);
        foreach (['candidates', 'payloads', 'sent', 'ok', 'findings', 'filtered', 'tokens', 'budgetExceeded', 'exitCode', 'strictReason'] as $k) {
            self::assertArrayHasKey($k, $doc['summary'] + ['findings' => 0], $k);
        }
        self::assertSame(1, $doc['summary']['exitCode']);
        self::assertNull($doc['summary']['strictReason']);
    }

    public function testSuppressedBaselinedFilteredAndStrictReason(): void
    {
        $sup = self::vuln(['title' => 'quiet']);
        $base = self::vuln(['title' => 'known']);
        $low = self::vuln(['title' => 'below', 'severity' => 'low']);
        $s = new Suppression('app/S.php', Category::Idor, 10, 20, 9, 'because');
        $n = new Suppression('app/S.php', null, 30, 40, 29, null);
        $result = new AnalysisResult([], [['vulnerability' => $sup, 'suppression' => $s], ['vulnerability' => $sup, 'suppression' => $n]], [$base], [], [...self::stats(), 'filtered' => 1], [$low]);
        $doc = self::decode((new JsonFormatter())->format($result, [...self::META, 'exitCode' => 2, 'strictReason' => 'strict: 1 failed']));

        self::assertSame(['file' => 'app/S.php', 'line' => 9, 'category' => 'idor', 'reason' => 'because'], $doc['suppressed'][0]['suppression']);
        self::assertSame(['file' => 'app/S.php', 'line' => 29, 'category' => null, 'reason' => null], $doc['suppressed'][1]['suppression']);
        self::assertSame('quiet', $doc['suppressed'][0]['title']);
        self::assertSame('known', $doc['baselined'][0]['title']);
        self::assertSame('below', $doc['filtered'][0]['title']);
        self::assertFalse($doc['filtered'][0]['failing']);
        self::assertSame(2, $doc['summary']['exitCode']);
        self::assertSame('strict: 1 failed', $doc['summary']['strictReason']);
    }

    public function testFingerprintsNotRedacted(): void
    {
        $fp = 'sk-ant-api03-'.str_repeat('a', 40).str_repeat('b', 11);
        $v = self::vuln(['fingerprint' => $fp, 'file' => 'app/secret_key_AKIAIOSFODNN7EXAMPLE.php', 'routeKey' => 'GET /tokens/{ghp_'.str_repeat('c', 36).'}']);
        $doc = self::decode((new JsonFormatter())->format(self::analysis([[$v, true]]), self::META));

        self::assertSame($fp, $doc['findings'][0]['fingerprint']);
        self::assertSame('app/secret_key_AKIAIOSFODNN7EXAMPLE.php', $doc['findings'][0]['file']);
        self::assertSame('GET /tokens/{ghp_'.str_repeat('c', 36).'}', $doc['findings'][0]['routeKey']);
        self::assertStringNotContainsString('REDACTED', json_encode($doc, JSON_THROW_ON_ERROR));
    }

    public function testHostileTextStillValidJson(): void
    {
        $evil = "Evil \e[2J\e]0;pwned\x07 <error>x</error>\nInjected: line </script> \"q\" \\ \u{202E}rtl \xC3\x28 \0 end";
        $v = self::vuln(['title' => $evil, 'file' => "app/\e[31mEvil.php", 'symbol' => $evil, 'context' => $evil, 'flaw' => $evil, 'fix' => $evil, 'patch' => "+ \e[2J<error>p</error>\n-\tok\\", 'model' => $evil]);
        $s = new Suppression("app/\e[2J.php", Category::Idor, 1, 9, 1, "r\e[2J\0");
        $result = new AnalysisResult([['vulnerability' => $v, 'failing' => true]], [['vulnerability' => $v, 'suppression' => $s]], [$v], ["warn \e[2J \xC3\x28 <b>w</b>"], self::stats(), [$v]);
        $out = (new JsonFormatter())->format($result, [...self::META, 'tool' => "t\e[2J", 'strictReason' => "strict\x07"]);
        $doc = self::decode($out);

        foreach (["\e", "\x07", "\0", "\u{202E}"] as $bad) {
            self::assertStringNotContainsString($bad, $out);
            self::assertStringNotContainsString(substr((string) json_encode($bad), 1, -1), $out);
        }
        self::assertStringContainsString('<error>x</error>', $doc['findings'][0]['title'], 'no console-tag escaping');
        self::assertStringContainsString('</script> "q" \\', $doc['findings'][0]['flaw']);
        self::assertStringContainsString("\u{FFFD}", $doc['findings'][0]['flaw'], 'invalid bytes become U+FFFD');
        self::assertStringNotContainsString("\n", $doc['findings'][0]['title'], 'single-line fields stay one line');
        self::assertStringContainsString("\n", $doc['findings'][0]['flaw'], 'prose keeps its line breaks');
        self::assertStringContainsString("+  [2J<error>p</error>\n-    ok\\", $doc['findings'][0]['patch']);
        self::assertSame('app/ [31mEvil.php', $doc['findings'][0]['file']);
    }

    public function testDeterministicOrder(): void
    {
        $result = self::analysis([[self::vuln(['file' => 'app/B.php', 'line' => 3]), true], [self::vuln(['file' => 'app/A.php', 'line' => 9]), true], [self::vuln(['file' => 'app/A.php', 'line' => 2]), false]]);
        $out = (new JsonFormatter())->format($result, self::META);
        $doc = self::decode($out);

        self::assertSame([['app/A.php', 2], ['app/A.php', 9], ['app/B.php', 3]], array_map(static fn (array $f): array => [$f['file'], $f['line']], $doc['findings']));
        self::assertSame($out, (new JsonFormatter())->format($result, self::META));
        self::assertStringEndsWith("}\n", $out);
        self::assertStringContainsString('app/A.php', $out);
        self::assertStringNotContainsString('\/', $out, 'slashes stay literal');
    }

    private static function replay(): AnalysisResult
    {
        $base = sys_get_temp_dir().'/semsec-json-snap-'.bin2hex(random_bytes(4));
        mkdir($base, 0777, true);
        try {
            exec('cp -R '.escapeshellarg(BenchmarkCorpus::root().'/laravel11-app').' '.escapeshellarg($base.'/app'), $out, $code);
            self::assertSame(0, $code);

            return BenchmarkReplay::run($base.'/app');
        } finally {
            exec('rm -rf '.escapeshellarg($base));
        }
    }

    /** @return array<string, mixed> */
    private static function decode(string $json): array
    {
        $doc = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($doc);

        return $doc;
    }

    /** @param list<array{Vulnerability, bool}> $findings */
    private static function analysis(array $findings): AnalysisResult
    {
        return new AnalysisResult(array_map(static fn (array $f): array => ['vulnerability' => $f[0], 'failing' => $f[1]], $findings), [], [], [], self::stats());
    }

    /** @return array{candidates:int, payloads:int, skipped:int, unsent:int, sent:int, cacheHits:int, ok:int, refused:int, truncated:int, invalid:int, failed:int, dropped:int, filtered:int, tokens:int, budgetExceeded:bool} */
    private static function stats(): array
    {
        return ['candidates' => 1, 'payloads' => 1, 'skipped' => 0, 'unsent' => 0, 'sent' => 1, 'cacheHits' => 0, 'ok' => 1, 'refused' => 0, 'truncated' => 0, 'invalid' => 0, 'failed' => 0, 'dropped' => 0, 'filtered' => 0, 'tokens' => 110, 'budgetExceeded' => false];
    }

    /** @param array<string, string|int> $o */
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
            (string) ($o['flaw'] ?? 'flaw'),
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
