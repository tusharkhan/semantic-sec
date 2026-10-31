<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Output;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Analysis\Category;
use TusharKhan\SemanticSec\Analysis\Confidence;
use TusharKhan\SemanticSec\Analysis\Severity;
use TusharKhan\SemanticSec\Engine\AnalysisResult;
use TusharKhan\SemanticSec\Engine\Vulnerability;
use TusharKhan\SemanticSec\Output\BaselineFile;
use TusharKhan\SemanticSec\Parsing\Suppression;

final class BaselineFileTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir().'/semsec-baseline-'.bin2hex(random_bytes(4));
        mkdir($this->dir, 0777, true);
    }

    protected function tearDown(): void
    {
        exec('rm -rf '.escapeshellarg($this->dir));
    }

    public function testIncludesFilteredAndNonFailing(): void
    {
        $result = new AnalysisResult(
            [['vulnerability' => self::vuln(['fingerprint' => self::fp('1')]), 'failing' => true], ['vulnerability' => self::vuln(['fingerprint' => self::fp('2'), 'confidence' => 'low']), 'failing' => false]],
            [],
            [self::vuln(['fingerprint' => self::fp('3')])],
            [],
            self::stats(),
            [self::vuln(['fingerprint' => self::fp('4'), 'severity' => 'low'])],
        );

        $n = BaselineFile::write($this->dir.'/b.json', $result);

        self::assertSame(4, $n);
        $baseline = BaselineFile::load($this->dir.'/b.json', true);
        foreach (['1', '2', '3', '4'] as $c) {
            self::assertTrue($baseline->contains(self::fp($c)), $c);
        }
    }

    public function testExcludesSuppressed(): void
    {
        $result = new AnalysisResult(
            [['vulnerability' => self::vuln(['fingerprint' => self::fp('1')]), 'failing' => true]],
            [['vulnerability' => self::vuln(['fingerprint' => self::fp('9')]), 'suppression' => new Suppression('app/A.php', Category::Idor, 1, 9, 1, 'ok')]],
            [],
            [],
            self::stats(),
        );

        self::assertSame(1, BaselineFile::write($this->dir.'/b.json', $result));
        $baseline = BaselineFile::load($this->dir.'/b.json', true);
        self::assertTrue($baseline->contains(self::fp('1')));
        self::assertFalse($baseline->contains(self::fp('9')));
    }

    public function testSortedStableFile(): void
    {
        $a = self::vuln(['fingerprint' => self::fp('b'), 'title' => "IDOR \e[2J</script>", 'file' => 'app/B.php', 'symbol' => 'App\B::show']);
        $b = self::vuln(['fingerprint' => self::fp('a'), 'category' => 'mass_assignment', 'title' => 'Mass', 'file' => 'app/A.php', 'symbol' => 'App\A::store']);
        $one = new AnalysisResult([['vulnerability' => $a, 'failing' => true]], [], [], [], self::stats(), [$b]);
        $two = new AnalysisResult([['vulnerability' => $b, 'failing' => true]], [], [$a], [], self::stats());

        BaselineFile::write($this->dir.'/one.json', $one);
        BaselineFile::write($this->dir.'/two.json', $two);
        $text = (string) file_get_contents($this->dir.'/one.json');

        self::assertSame($text, file_get_contents($this->dir.'/two.json'), 'same fingerprints, same bytes');
        $expected = json_encode([
            'version' => 1,
            'tool' => 'semantic-sec',
            'fingerprints' => [
                ['fingerprint' => self::fp('a'), 'category' => 'mass_assignment', 'file' => 'app/A.php', 'symbol' => 'App\A::store', 'title' => 'Mass'],
                ['fingerprint' => self::fp('b'), 'category' => 'idor', 'file' => 'app/B.php', 'symbol' => 'App\B::show', 'title' => 'IDOR  [2J</script>'],
            ],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)."\n";
        self::assertSame($expected, $text);
    }

    public function testDuplicateFingerprintWrittenOnce(): void
    {
        $result = new AnalysisResult([['vulnerability' => self::vuln(['fingerprint' => self::fp('1')]), 'failing' => true]], [], [self::vuln(['fingerprint' => self::fp('1')])], [], self::stats());

        self::assertSame(1, BaselineFile::write($this->dir.'/b.json', $result));
    }

    public function testWriteRefusesASymlink(): void
    {
        file_put_contents($this->dir.'/real.json', 'x');
        symlink($this->dir.'/real.json', $this->dir.'/b.json');

        try {
            BaselineFile::write($this->dir.'/b.json', new AnalysisResult([], [], [], [], self::stats()));
            self::fail('expected a refusal');
        } catch (\RuntimeException $e) {
            self::assertStringContainsString('symlink', $e->getMessage());
        }
        self::assertSame('x', file_get_contents($this->dir.'/real.json'));
    }

    public function testMissingDefaultIsEmpty(): void
    {
        $baseline = BaselineFile::load($this->dir.'/semantic-sec-baseline.json', false);

        self::assertFalse($baseline->contains(self::fp('1')));
    }

    public function testMissingExplicitIsExitTwo(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage($this->dir.'/nope.json');

        BaselineFile::load($this->dir.'/nope.json', true);
    }

    public function testBadJsonOrVersionIsExitTwo(): void
    {
        $cases = [
            'bad json' => '{"version": 1,',
            'not an object' => '[]',
            'wrong version' => '{"version": 2, "fingerprints": []}',
            'string version' => '{"version": "1", "fingerprints": []}',
            'no list' => '{"version": 1}',
            'entry not an object' => '{"version": 1, "fingerprints": ["'.self::fp('1').'"]}',
            'short fingerprint' => '{"version": 1, "fingerprints": [{"fingerprint": "abc"}]}',
            'upper-case fingerprint' => '{"version": 1, "fingerprints": [{"fingerprint": "'.strtoupper(self::fp('a')).'"}]}',
            'missing fingerprint' => '{"version": 1, "fingerprints": [{"file": "a"}]}',
        ];
        foreach ($cases as $name => $json) {
            $path = $this->dir.'/'.str_replace(' ', '-', $name).'.json';
            file_put_contents($path, $json);
            foreach ([true, false] as $required) {
                try {
                    BaselineFile::load($path, $required);
                    self::fail("{$name}: expected a RuntimeException");
                } catch (\RuntimeException $e) {
                    self::assertStringContainsString($path, $e->getMessage(), $name);
                }
            }
        }
    }

    public function testOversizedFileRefused(): void
    {
        $path = $this->dir.'/big.json';
        $handle = fopen($path, 'w');
        self::assertNotFalse($handle);
        ftruncate($handle, BaselineFile::MAX_BYTES + 1);
        fclose($handle);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('larger than');

        BaselineFile::load($path, false);
    }

    public function testDirectoryRefused(): void
    {
        mkdir($this->dir.'/d.json');

        $this->expectException(\RuntimeException::class);

        BaselineFile::load($this->dir.'/d.json', false);
    }

    private static function fp(string $c): string
    {
        return str_repeat($c, 64);
    }

    /** @return array{candidates:int, payloads:int, skipped:int, unsent:int, sent:int, cacheHits:int, ok:int, refused:int, truncated:int, invalid:int, failed:int, dropped:int, filtered:int, tokens:int, budgetExceeded:bool} */
    private static function stats(): array
    {
        return ['candidates' => 1, 'payloads' => 1, 'skipped' => 0, 'unsent' => 0, 'sent' => 1, 'cacheHits' => 0, 'ok' => 1, 'refused' => 0, 'truncated' => 0, 'invalid' => 0, 'failed' => 0, 'dropped' => 0, 'filtered' => 0, 'tokens' => 110, 'budgetExceeded' => false];
    }

    /** @param array<string, string> $o */
    private static function vuln(array $o = []): Vulnerability
    {
        return new Vulnerability(
            Category::from($o['category'] ?? 'idor'),
            Severity::from($o['severity'] ?? 'high'),
            Confidence::from($o['confidence'] ?? 'high'),
            $o['title'] ?? 'IDOR',
            $o['file'] ?? 'app/A.php',
            1,
            $o['symbol'] ?? 'App\A::show',
            'context',
            'flaw',
            'fix',
            '',
            [],
            'GET /a/{id}',
            '001-get-a-id-1',
            'm',
            $o['fingerprint'] ?? self::fp('a'),
        );
    }
}
