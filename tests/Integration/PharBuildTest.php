<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Integration;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Process\Process;
use TusharKhan\SemanticSec\Console\Application;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;

// Slow and needs network for Box and Composer: runs only with SEMANTIC_SEC_PHAR=1.
final class PharBuildTest extends TestCase
{
    private static string $tmp = '';

    private static string $phar = '';

    public static function setUpBeforeClass(): void
    {
        if (getenv('SEMANTIC_SEC_PHAR') !== '1') {
            return;
        }
        $root = dirname(__DIR__, 2);
        $build = new Process(['sh', $root.'/tools/build-phar.sh'], $root, null, null, 600);
        $build->run();
        self::assertSame(0, $build->getExitCode(), $build->getOutput().$build->getErrorOutput());

        // The PHAR runs from a temp dir, away from the repo and its vendor/.
        self::$tmp = sys_get_temp_dir().'/semsec-phar-'.bin2hex(random_bytes(4));
        mkdir(self::$tmp, 0777, true);
        self::$phar = self::$tmp.'/semantic-sec.phar';
        copy($root.'/build/semantic-sec.phar', self::$phar);
    }

    public static function tearDownAfterClass(): void
    {
        if (self::$tmp !== '') {
            exec('rm -rf '.escapeshellarg(self::$tmp));
        }
    }

    protected function setUp(): void
    {
        if (getenv('SEMANTIC_SEC_PHAR') !== '1') {
            self::markTestSkipped('Set SEMANTIC_SEC_PHAR=1 to build and check the PHAR.');
        }
    }

    /** @param list<string> $args */
    private static function exec(string $script, array $args): Process
    {
        $p = new Process([PHP_BINARY, $script, ...$args], self::$tmp, null, null, 300);
        $p->run();

        return $p;
    }

    private static function appCopy(string $name): string
    {
        $dir = self::$tmp.'/'.$name;
        exec('cp -R '.escapeshellarg(BenchmarkCorpus::root().'/laravel11-app').' '.escapeshellarg($dir), $out, $code);
        self::assertSame(0, $code);

        return $dir;
    }

    public function testVersion(): void
    {
        $p = self::exec(self::$phar, ['--version']);

        self::assertSame(0, $p->getExitCode(), $p->getErrorOutput());
        self::assertSame(Application::NAME.' '.Application::VERSION, trim($p->getOutput()));
    }

    public function testMapMatchesBinByteForByte(): void
    {
        $app = self::appCopy('map-app');
        $args = ['map', '--format=json', '--project-root='.$app];
        $phar = self::exec(self::$phar, $args);
        $bin = self::exec(dirname(__DIR__, 2).'/bin/semantic-sec', $args);

        self::assertSame(0, $phar->getExitCode(), $phar->getErrorOutput());
        self::assertSame(0, $bin->getExitCode(), $bin->getErrorOutput());
        self::assertNotSame('', $phar->getOutput());
        self::assertSame($bin->getOutput(), $phar->getOutput());
    }

    public function testDryRunWritesPayloads(): void
    {
        $app = self::appCopy('dry-app');
        $p = self::exec(self::$phar, ['analyze', '--dry-run', '--format=json', '--project-root='.$app]);

        self::assertSame(0, $p->getExitCode(), $p->getErrorOutput());
        $data = json_decode($p->getOutput(), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($data);
        self::assertGreaterThan(0, $data['summary']['payloads']);
        $files = glob($app.'/.semantic-sec/dry-run/*.txt') ?: [];
        self::assertCount($data['summary']['payloads'] + 1, $files);
    }

    public function testContentsHoldNothingExcluded(): void
    {
        $prefix = 'phar://'.self::$phar.'/';
        $top = [];
        $count = 0;
        foreach (new \RecursiveIteratorIterator(new \Phar(self::$phar)) as $file) {
            self::assertInstanceOf(\SplFileInfo::class, $file);
            $path = substr($file->getPathname(), strlen($prefix));
            $top[explode('/', $path)[0]] = true;
            $count++;
            self::assertDoesNotMatchRegularExpression('~(^|/)(\.env|cassettes/|tests/Fixtures/)|docs/plans|\.superpowers|\.claude/~', $path);
            self::assertStringNotContainsString('sk-ant-', (string) file_get_contents($file->getPathname()), $path);
        }

        self::assertGreaterThan(100, $count);
        $top = array_keys($top);
        sort($top);
        self::assertSame(['.box', 'LICENSE', 'bin', 'config', 'src', 'vendor'], $top);
    }
}
