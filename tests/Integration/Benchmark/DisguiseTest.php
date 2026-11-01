<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Integration\Benchmark;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Console\MapBuilder;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\Disguise;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\DisguiseMap;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\ExpectedCases;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;

/** The competitor's copy of the corpus: same code, no names that give the answer away (M8 Task 5). */
final class DisguiseTest extends TestCase
{
    private static string $dir = '';

    /** @var array<string, mixed> */
    private static array $map = [];

    public static function setUpBeforeClass(): void
    {
        self::$dir = sys_get_temp_dir().'/semsec-disguise-'.bin2hex(random_bytes(4));
        self::$map = Disguise::run(BenchmarkCorpus::root(), self::$dir.'/bench');
        Disguise::writeMap(self::$map, self::$dir.'/disguise-map.json');
    }

    public static function tearDownAfterClass(): void
    {
        exec('rm -rf '.escapeshellarg(self::$dir));
    }

    public function testCopiesSourceOnly(): void
    {
        self::assertSame(BenchmarkCorpus::APPS, array_values(array_diff((array) scandir(self::$dir.'/bench'), ['.', '..'])));
        self::assertFileExists(self::$dir.'/bench/laravel11-app/routes/web.php');
        self::assertFileDoesNotExist(self::$dir.'/bench/expected.yaml');
        self::assertFileDoesNotExist(self::$dir.'/bench/README.md');
        self::assertDirectoryDoesNotExist(self::$dir.'/bench/verify');
    }

    public function testNothingNamesTheAnswer(): void
    {
        $leaks = [];
        foreach (self::files(self::$dir.'/bench') as $path) {
            foreach ((array) file($path) as $n => $line) {
                if (preg_match(Disguise::LEAK, (string) $line) === 1 && ! str_contains((string) $line, '@semantic-sec-ignore')) {
                    $leaks[] = substr($path, strlen(self::$dir)).':'.($n + 1).': '.trim((string) $line);
                }
            }
        }

        self::assertSame([], $leaks);
        self::assertStringContainsString('@semantic-sec-ignore idor', (string) file_get_contents(self::$dir.'/bench/laravel11-app/'.self::disguisedFile('laravel11-app', 'app/Http/Controllers/Vuln/SharedInvoiceController.php')));
    }

    public function testDeterministic(): void
    {
        $again = Disguise::run(BenchmarkCorpus::root(), self::$dir.'/again');

        self::assertSame(self::$map['apps'], $again['apps']);
        self::assertSame(self::tree(self::$dir.'/bench'), self::tree(self::$dir.'/again'));
    }

    public function testRoutesSurviveAndMapBack(): void
    {
        foreach (BenchmarkCorpus::APPS as $app) {
            $original = (new MapBuilder())->project(BenchmarkCorpus::root().'/'.$app, null, null);
            $disguised = (new MapBuilder())->project(self::$dir.'/bench/'.$app, null, null);

            self::assertCount(count($original->map->routes), $disguised->map->routes, $app);
            self::assertSame([], $disguised->parsed->failures, $app);
            self::assertCount(array_sum(array_map(static fn ($r): int => count($r->methods), $original->map->routes)), self::$map['apps'][$app]['routes'], $app);
        }
    }

    public function testEveryCaseSymbolRoundTrips(): void
    {
        $map = DisguiseMap::load(self::$dir.'/disguise-map.json');
        $letters = [];
        foreach (ExpectedCases::load((string) file_get_contents(BenchmarkCorpus::root().'/expected.yaml')) as $case) {
            foreach ([$case->vulnerable, $case->safe] as $i => $variant) {
                $disguised = $map->disguisedSymbol($case->app, $variant->symbol);
                self::assertSame($variant->symbol, $map->originalSymbol($case->app, $disguised), $case->id);
                self::assertFileExists(self::$dir.'/bench/'.$case->app.'/'.ExpectedCases::fileOf($disguised), $case->id);
                self::assertContains($variant->route, self::$map['apps'][$case->app]['routes'], $case->id);
                if ($i === 0 && preg_match('/\\\\(Alpha|Beta)\\\\/', $disguised, $m) === 1) {
                    $letters[$m[1]] = true;
                }
            }
        }

        self::assertSame(['Alpha', 'Beta'], array_keys(array_intersect_key(['Alpha' => 1, 'Beta' => 1], $letters)));
    }

    public function testLinesOutsideRoutesDoNotMove(): void
    {
        foreach (self::$map['apps']['laravel11-app']['files'] as $disguised => $original) {
            self::assertSame(
                substr_count((string) file_get_contents(BenchmarkCorpus::root().'/laravel11-app/'.$original), "\n"),
                substr_count((string) file_get_contents(self::$dir.'/bench/laravel11-app/'.$disguised), "\n"),
                $original,
            );
        }
    }

    private static function disguisedFile(string $app, string $original): string
    {
        return (string) array_search($original, self::$map['apps'][$app]['files'], true);
    }

    /** @return list<string> */
    private static function files(string $dir): array
    {
        $out = [];
        foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS)) as $file) {
            $out[] = (string) $file;
        }
        sort($out);

        return $out;
    }

    /** @return array<string, string> */
    private static function tree(string $dir): array
    {
        $out = [];
        foreach (self::files($dir) as $path) {
            $out[substr($path, strlen($dir))] = (string) md5_file($path);
        }

        return $out;
    }
}
