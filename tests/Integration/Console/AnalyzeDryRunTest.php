<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Integration\Console;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Tester\CommandTester;
use TusharKhan\SemanticSec\Console\Application;
use TusharKhan\SemanticSec\Payload\PayloadBuilder;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkMaps;
use TusharKhan\SemanticSec\Tests\Support\NetworkTrap;

final class AnalyzeDryRunTest extends TestCase
{
    private const APPS = ['laravel11-app', 'laravel10-app'];

    /** @var list<string> */
    private static array $httpClients = [
        'GuzzleHttp\Client',
        'GuzzleHttp\Pool',
        'Symfony\Component\HttpClient\HttpClient',
        'Symfony\Component\HttpClient\CurlHttpClient',
        'Symfony\Component\HttpClient\NativeHttpClient',
        'Psr\Http\Client\ClientInterface',
    ];

    /** @var array<string, string> app => copied project root */
    private static array $copies = [];

    /** @var array<string, array<string, mixed>> app|deep => decoded JSON summary */
    private static array $runs = [];

    public static function tearDownAfterClass(): void
    {
        foreach (self::$copies as $dir) {
            exec('rm -rf '.escapeshellarg(dirname($dir)));
        }
        self::$copies = self::$runs = [];
    }

    // The benchmark is never written to: each app is copied to a temp dir first.
    private static function copy(string $app, string $tag = ''): string
    {
        $key = $app.$tag;
        if (! isset(self::$copies[$key])) {
            $base = sys_get_temp_dir().'/semsec-analyze-'.bin2hex(random_bytes(4));
            mkdir($base, 0777, true);
            exec('cp -R '.escapeshellarg(BenchmarkCorpus::root().'/'.$app).' '.escapeshellarg($base.'/'.$app), $out, $code);
            self::assertSame(0, $code);
            self::$copies[$key] = $base.'/'.$app;
        }

        return self::$copies[$key];
    }

    private static function tester(): CommandTester
    {
        return new CommandTester((new Application())->find('analyze'));
    }

    /** @return array<string, mixed> */
    private static function dryRun(string $app, bool $deep = false): array
    {
        $key = $app.'|'.($deep ? 'deep' : 'normal');
        if (! isset(self::$runs[$key])) {
            $t = self::tester();
            $args = ['--project-root' => self::copy($app), '--dry-run' => true, '--format' => 'json'];
            if ($deep) {
                $args['--deep'] = true;
            }
            self::assertSame(0, $t->execute($args, ['capture_stderr_separately' => true]), $t->getErrorOutput());
            self::$runs[$key] = json_decode($t->getDisplay(), true, 512, JSON_THROW_ON_ERROR);
        }

        return self::$runs[$key];
    }

    /** @return array<string, string> file name => contents */
    private static function files(string $app): array
    {
        $dir = self::copy($app).'/.semantic-sec/dry-run';
        $files = [];
        foreach (glob($dir.'/*') ?: [] as $path) {
            $files[basename($path)] = (string) file_get_contents($path);
        }
        ksort($files);

        return $files;
    }

    // The route key a payload was built for: the line after "Route:".
    private static function routeOf(string $text): string
    {
        return preg_match('~^Route:\n  (.+)$~m', $text, $m) === 1 ? $m[1] : '';
    }

    public function testWithoutDryRunExitsTwo(): void
    {
        $t = self::tester();
        $code = $t->execute(['--project-root' => self::copy('laravel11-app')], ['capture_stderr_separately' => true]);

        self::assertSame(2, $code);
        self::assertStringContainsString('analysis needs the LLM layer (M5); use --dry-run', $t->getErrorOutput());
    }

    public function testBadFormatExitsTwo(): void
    {
        self::assertSame(2, self::tester()->execute(['--project-root' => self::copy('laravel11-app'), '--dry-run' => true, '--format' => 'sarif']));
    }

    public function testWritesOneFilePerCandidatePayload(): void
    {
        foreach (self::APPS as $app) {
            $data = self::dryRun($app);
            $files = self::files($app);
            $ids = [];
            foreach ($data['candidates'] as $n => $candidate) {
                foreach ($candidate['payloads'] as $payload) {
                    self::assertStringStartsWith(sprintf('%03d-', $n + 1), $payload['id']);
                    self::assertSame($payload['id'].'.txt', $payload['file']);
                    $ids[] = $payload['file'];
                }
            }
            sort($ids);

            self::assertSame($ids, array_keys($files), $app);
            self::assertSame(count($ids), $data['summary']['payloads']);
            self::assertSame(count($data['candidates']), $data['summary']['candidates']);

            // Cross-check against the selector and builder run directly.
            [$candidates] = BenchmarkMaps::selector($app)->select(BenchmarkMaps::build($app), false);
            $expected = [];
            foreach ($candidates as $i => $candidate) {
                foreach (BenchmarkMaps::payloadBuilder($app)->build($candidate, $i + 1)[0] as $payload) {
                    $expected[] = $payload->id.'.txt';
                }
            }
            sort($expected);
            self::assertSame($expected, $ids, $app);
        }
    }

    public function testEveryFileIsOneFencedPayload(): void
    {
        foreach (self::APPS as $app) {
            $files = self::files($app);
            self::assertNotSame([], $files);
            foreach ($files as $name => $text) {
                self::assertSame(1, substr_count($text, PayloadBuilder::OPEN), $name);
                self::assertSame(1, substr_count($text, PayloadBuilder::CLOSE), $name);
                self::assertStringStartsWith('Route:', $text, $name);
            }
        }
    }

    public function testVulnerableSymbolsArePresent(): void
    {
        $checked = 0;
        foreach (BenchmarkCorpus::cases() as $case) {
            $app = (string) $case['app'];
            self::dryRun($app);
            $route = (string) $case['vulnerable']['route'];
            $symbol = (string) $case['vulnerable']['symbol'];
            $found = false;
            foreach (self::files($app) as $text) {
                if (self::routeOf($text) === $route && str_contains($text, ':: '.$symbol.' (L')) {
                    $found = true;
                    break;
                }
            }
            self::assertTrue($found, sprintf('%s: no payload for %s with %s', $case['id'], $route, $symbol));
            $checked++;
        }
        self::assertSame(15, $checked);
    }

    public function testNoFileForCandidateFalseSafeVariants(): void
    {
        $checked = 0;
        foreach (BenchmarkCorpus::cases() as $case) {
            if (($case['safe']['candidate'] ?? true) !== false) {
                continue;
            }
            $app = (string) $case['app'];
            self::dryRun($app);
            $routes = array_map(self::routeOf(...), self::files($app));
            self::assertNotContains((string) $case['safe']['route'], $routes, (string) $case['id']);
            $checked++;
        }
        self::assertSame(15, $checked);
    }

    public function testDeepProducesAtLeastAsManyCandidates(): void
    {
        foreach (self::APPS as $app) {
            $normal = self::dryRun($app);
            $normalRoutes = array_column($normal['candidates'], 'route');
            $deep = self::dryRun($app, true);
            $deepRoutes = array_column($deep['candidates'], 'route');

            self::assertGreaterThanOrEqual($normal['summary']['candidates'], $deep['summary']['candidates'], $app);
            self::assertSame([], array_values(array_diff($normalRoutes, $deepRoutes)), $app);
        }
    }

    public function testDirectoryIsRecreatedEachRun(): void
    {
        $root = self::copy('laravel11-app');
        $dir = $root.'/.semantic-sec/dry-run';
        @mkdir($dir.'/stale', 0777, true);
        file_put_contents($dir.'/999-stale.txt', 'old');
        file_put_contents($dir.'/stale/x.txt', 'old');
        file_put_contents($root.'/.semantic-sec/keep.txt', 'keep');

        self::assertSame(0, self::tester()->execute(['--project-root' => $root, '--dry-run' => true]));

        self::assertFileDoesNotExist($dir.'/999-stale.txt');
        self::assertDirectoryDoesNotExist($dir.'/stale');
        self::assertFileExists($root.'/.semantic-sec/keep.txt');
        self::assertCount(self::dryRun('laravel11-app')['summary']['payloads'], self::files('laravel11-app'));
    }

    public function testConsoleSummary(): void
    {
        $t = self::tester();
        $root = self::copy('laravel11-app');
        self::assertSame(0, $t->execute(['--project-root' => $root, '--dry-run' => true]));
        $display = $t->getDisplay();
        $data = self::dryRun('laravel11-app');

        self::assertStringContainsString('GET /vuln/invoices/{id}', $display);
        foreach (['Route', 'Categories', 'Parts', 'Tokens'] as $header) {
            self::assertStringContainsString($header, $display);
        }
        self::assertStringContainsString(sprintf(
            '%d candidates, %d payloads, ~%d tokens; written to %s/.semantic-sec/dry-run',
            $data['summary']['candidates'],
            $data['summary']['payloads'],
            $data['summary']['tokens'],
            $root,
        ), $display);
    }

    public function testPathsLimitTheCandidates(): void
    {
        $t = self::tester();
        $root = self::copy('laravel11-app', 'paths');
        self::assertSame(0, $t->execute(['--project-root' => $root, '--dry-run' => true, '--format' => 'json', 'paths' => ['app/Http/Controllers/Safe']]));
        $data = json_decode($t->getDisplay(), true, 512, JSON_THROW_ON_ERROR);

        self::assertLessThan(self::dryRun('laravel11-app')['summary']['candidates'], $data['summary']['candidates']);
        foreach ($data['candidates'] as $candidate) {
            self::assertStringContainsString('/safe/', $candidate['route']);
        }
    }

    // Proves only that no known HTTP client class was loaded and no http(s) stream was opened in-process; raw curl_* or socket calls are not intercepted.
    public function testDryRunUsesNoNetworkAndNoApiKey(): void
    {
        $saved = [];
        foreach (['OPENAI_API_KEY', 'ANTHROPIC_API_KEY'] as $var) {
            $saved[$var] = getenv($var);
            putenv($var);
        }
        NetworkTrap::install();
        try {
            $code = self::tester()->execute(['--project-root' => self::copy('laravel10-app'), '--dry-run' => true, '--deep' => true]);
        } finally {
            $opened = NetworkTrap::uninstall();
            foreach ($saved as $var => $value) {
                putenv($value === false ? $var : $var.'='.$value);
            }
        }

        self::assertSame(0, $code);
        self::assertSame([], $opened);
        $loaded = array_filter(self::$httpClients, static fn (string $c): bool => class_exists($c, false) || interface_exists($c, false));
        self::assertSame([], array_values($loaded));
        $http = array_filter(get_declared_classes(), static fn (string $c): bool => preg_match('~Guzzle|HttpClient|Http\\\\Client~i', $c) === 1);
        self::assertSame([], array_values($http));
    }
}
