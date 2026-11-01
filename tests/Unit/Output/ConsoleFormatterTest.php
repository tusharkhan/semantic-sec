<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Output;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Analysis\Category;
use TusharKhan\SemanticSec\Analysis\Confidence;
use TusharKhan\SemanticSec\Analysis\Severity;
use TusharKhan\SemanticSec\Engine\AnalysisResult;
use TusharKhan\SemanticSec\Engine\Vulnerability;
use TusharKhan\SemanticSec\Output\ConsoleFormatter;
use TusharKhan\SemanticSec\Output\Formatter;
use TusharKhan\SemanticSec\Parsing\Suppression;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkReplay;

final class ConsoleFormatterTest extends TestCase
{
    private const SNAPSHOT = __DIR__.'/../../Fixtures/snapshots/console-benchmark.txt';

    private const META = ['tool' => 'semantic-sec', 'version' => 'snapshot', 'provider' => 'anthropic', 'model' => 'claude-opus-5-5', 'level' => 'low', 'budget' => null];

    private const PATCH = "--- a/app/X.php\n+++ b/app/X.php\n@@ -1,2 +1,2 @@\n     \$a = 1;\n-    return \$a;\n+    return \$b;";

    public function testIsAFormatter(): void
    {
        self::assertInstanceOf(Formatter::class, new ConsoleFormatter());
    }

    public function testSnapshotOverReplayedBenchmark(): void
    {
        $base = sys_get_temp_dir().'/semsec-console-snap-'.bin2hex(random_bytes(4));
        mkdir($base, 0777, true);
        try {
            exec('cp -R '.escapeshellarg(BenchmarkCorpus::root().'/laravel11-app').' '.escapeshellarg($base.'/app'), $out, $code);
            self::assertSame(0, $code);
            $result = BenchmarkReplay::run($base.'/app');
        } finally {
            exec('rm -rf '.escapeshellarg($base));
        }
        $actual = (new ConsoleFormatter())->format($result, self::META);

        if (getenv('UPDATE_SNAPSHOTS') === '1') {
            file_put_contents(self::SNAPSHOT, $actual);
        }
        self::assertFileExists(self::SNAPSHOT, 'run with UPDATE_SNAPSHOTS=1 to create it');
        self::assertSame(file_get_contents(self::SNAPSHOT), $actual);
        self::assertStringNotContainsString($base, $actual);
        self::assertStringNotContainsString(sys_get_temp_dir().'/', $actual);
        self::assertSame(13, substr_count($actual, '[!] '), 'every reported finding is rendered');
    }

    public function testGroupsByFileAndLine(): void
    {
        $result = self::analysis([
            [self::vuln(['file' => 'app/B.php', 'line' => 30, 'title' => 'b30']), true],
            [self::vuln(['file' => 'app/A.php', 'line' => 20, 'title' => 'a20']), true],
            [self::vuln(['file' => 'app/B.php', 'line' => 4, 'title' => 'b4']), true],
            [self::vuln(['file' => 'app/A.php', 'line' => 7, 'title' => 'a7']), false],
        ]);
        $out = (new ConsoleFormatter())->format($result, self::META);

        $positions = array_map(static fn (string $needle): int|false => strpos($out, $needle), ['app/A.php', 'Severity: a7', 'Severity: a20', 'app/B.php', 'Severity: b4', 'Severity: b30']);
        self::assertNotContains(false, $positions);
        $sorted = $positions;
        sort($sorted);
        self::assertSame($sorted, $positions);
        self::assertSame(1, preg_match_all('~^app/A\.php$~m', $out), 'one group header per file');
        self::assertStringContainsString('Confidence:    high (not failing)', $out);
        self::assertStringContainsString('Category:      Insecure Direct Object Reference (IDOR) (CWE-639)', $out);
        self::assertStringContainsString('[!] High Severity: a7', $out);
    }

    public function testHostileTextInert(): void
    {
        $evil = "Evil \e[2J\e]0;pwned\x07 <error>x</error>\nInjected: line </script> \"q\" \\";
        $v = self::vuln(['title' => $evil, 'file' => "app/\e[31mEvil<info>.php", 'symbol' => $evil, 'context' => $evil, 'flaw' => $evil, 'fix' => $evil, 'patch' => "+ \e[2J<error>p</error>\n- ok\\"]);
        $s = new Suppression('app/S.php', Category::Idor, 1, 9, 1, "<error>r</error>\e[2J");
        $result = new AnalysisResult([['vulnerability' => $v, 'failing' => true]], [['vulnerability' => $v, 'suppression' => $s]], [$v], ["warn \e[2J <error>w</error>"], self::stats());

        foreach ([false, true] as $decorated) {
            $f = new ConsoleFormatter($decorated);
            $out = $f->format($result, [...self::META, 'model' => "m\e[2J<error>", 'strictReason' => 'strict: 1 failed']);
            $out .= $f->summary($result, self::META);
            self::assertStringNotContainsString("\e[2J", $out);
            self::assertStringNotContainsString("\e]0", $out);
            self::assertStringNotContainsString("\x07", $out);
            self::assertStringNotContainsString("\0", $out);
            self::assertStringContainsString('<error>x</error>', $out, 'tags print literally');
            self::assertStringContainsString('<error>r</error>', $out);
            self::assertStringContainsString('<error>w</error>', $out);
            self::assertDoesNotMatchRegularExpression('~^Injected:~m', $out, 'model newlines never start a fake line');
            self::assertStringContainsString('[!] High Severity: Evil', $out);
        }
        $plain = (new ConsoleFormatter())->format($result, self::META);
        self::assertStringContainsString('</script> "q" \\', $plain);
        self::assertStringContainsString('app/ [31mEvil<info>.php', $plain);
    }

    public function testUtf8StaysIntact(): void
    {
        $text = 'Å Ӆ naïve অ';
        $v = self::vuln(['title' => $text, 'flaw' => $text, 'patch' => "-    \$a = '{$text}';\n+    \$b = '{$text}';"]);
        foreach ([false, true] as $decorated) {
            $out = (new ConsoleFormatter($decorated))->format(self::analysis([[$v, true]]), self::META);

            self::assertTrue(mb_check_encoding($out, 'UTF-8'));
            self::assertStringNotContainsString("\u{FFFD}", $out);
            self::assertMatchesRegularExpression('~Flaw:\s+'.preg_quote($text, '~').'$~mu', $out);
            self::assertMatchesRegularExpression('~-    \$a = \''.preg_quote($text, '~').'\';~u', $out);
            self::assertMatchesRegularExpression('~\+    \$b = \''.preg_quote($text, '~').'\';~u', $out);
        }
    }

    public function testPatchShownOnlyWhenPresent(): void
    {
        $with = self::vuln(['title' => 'with', 'line' => 1, 'patch' => self::PATCH]);
        $without = self::vuln(['title' => 'without', 'line' => 2, 'patch' => '']);
        $out = (new ConsoleFormatter())->format(self::analysis([[$with, true], [$without, true]]), self::META);

        self::assertSame(1, substr_count($out, 'Patch:'));
        self::assertStringContainsString("        -    return \$a;\n        +    return \$b;", $out, 'patch lines keep their indentation');
        self::assertStringContainsString('             $a = 1;', $out);
        self::assertGreaterThan(strpos($out, 'Patch:'), strpos($out, 'Severity: without'));

        $ansi = (new ConsoleFormatter(true))->format(self::analysis([[$with, true]]), self::META);
        self::assertStringContainsString("\e[32m+    return \$b;", $ansi);
        self::assertStringContainsString("\e[31m-    return \$a;", $ansi);
    }

    public function testSuppressedAndBaselinedListedFilteredOnlyCounted(): void
    {
        $sup = self::vuln(['title' => 'quiet', 'file' => 'app/S.php', 'line' => 15]);
        $base = self::vuln(['title' => 'known', 'file' => 'app/K.php', 'line' => 8]);
        $low = self::vuln(['title' => 'below level', 'severity' => 'low']);
        $result = new AnalysisResult([], [['vulnerability' => $sup, 'suppression' => new Suppression('app/S.php', null, 10, 20, 9, null)]], [$base], [], [...self::stats(), 'filtered' => 1], [$low]);
        $out = (new ConsoleFormatter())->format($result, self::META);

        self::assertStringContainsString('No findings.', $out);
        self::assertStringContainsString("Suppressed (1)\n  - quiet — app/S.php:15 — no reason given", $out);
        self::assertStringContainsString("Baselined (1)\n  - known — app/K.php:8 — in baseline", $out);
        self::assertStringNotContainsString('below level —', $out);
        self::assertMatchesRegularExpression('~filtered\s+1 \(below level low\)~', $out);
        self::assertStringNotContainsString('[!]', $out);
    }

    public function testSummaryHasEveryStatStrictAndWarnings(): void
    {
        $result = new AnalysisResult([], [], [], ['careful'], [...self::stats(), 'unsent' => 2, 'budgetExceeded' => true]);
        $summary = (new ConsoleFormatter())->summary($result, [...self::META, 'budget' => 500, 'strictReason' => 'strict: 2 unsent']);

        foreach (['candidates', 'payloads', 'skipped', 'unsent', 'cache hits', 'sent', 'ok', 'refused', 'truncated', 'invalid', 'failed', 'dropped', 'findings', 'filtered', 'suppressed', 'baselined', 'tokens', 'budget'] as $label) {
            self::assertMatchesRegularExpression('~^  '.preg_quote($label, '~').'\s+\S~m', $summary, $label);
        }
        self::assertMatchesRegularExpression('~budget\s+500 \(exceeded\)~', $summary);
        self::assertStringContainsString("\nstrict: 2 unsent\n", $summary);
        self::assertStringContainsString("Warnings\n  careful\n", $summary);
        self::assertStringContainsString($summary, (new ConsoleFormatter())->format($result, [...self::META, 'budget' => 500, 'strictReason' => 'strict: 2 unsent']));
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
            'GET /a/{id}',
            '001-get-a-id-1',
            'm',
            str_repeat('a', 64),
        );
    }
}
