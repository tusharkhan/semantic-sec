<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Framework\Laravel;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Analysis\Confidence;
use TusharKhan\SemanticSec\Analysis\Severity;
use TusharKhan\SemanticSec\Config\Config;
use TusharKhan\SemanticSec\Framework\DetectedFramework;
use TusharKhan\SemanticSec\Framework\Laravel\ConstantEvaluator;
use TusharKhan\SemanticSec\Framework\Laravel\RouteFile;
use TusharKhan\SemanticSec\Framework\Laravel\RouteFileLocator;
use TusharKhan\SemanticSec\Parsing\AstGenerator;
use TusharKhan\SemanticSec\Parsing\FileFinder;
use TusharKhan\SemanticSec\Parsing\ProjectParser;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTableBuilder;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;

final class RouteFileLocatorTest extends TestCase
{
    /** @var list<string> */
    private array $dirs = [];

    protected function tearDown(): void
    {
        foreach ($this->dirs as $dir) {
            foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST) as $f) {
                $f->isDir() ? rmdir($f->getPathname()) : unlink($f->getPathname());
            }
            rmdir($dir);
        }
    }

    /**
     * @param  list<string>  $extra
     * @return array{0: list<RouteFile>, 1: list<string>}
     */
    private function locate(string $root, int $version, array $extra = []): array
    {
        $parsed = (new ProjectParser(new FileFinder(), new AstGenerator()))->parse($root);
        $symbols = (new SymbolTableBuilder())->build($parsed);
        $config = new Config($root, 'anthropic', null, null, null, 5, null, 8000, 3, Severity::High, Confidence::Medium, [], [], $extra, [], [], []);

        return (new RouteFileLocator())->locate($parsed, $symbols, new DetectedFramework('laravel', $version), $config, new ConstantEvaluator());
    }

    /** @param array<string, string> $files */
    private function project(array $files): string
    {
        $dir = sys_get_temp_dir().'/ss-rfl-'.bin2hex(random_bytes(4));
        mkdir($dir);
        $this->dirs[] = $dir;
        foreach ($files as $path => $code) {
            @mkdir(dirname($dir.'/'.$path), 0777, true);
            file_put_contents($dir.'/'.$path, $code);
        }

        return $dir;
    }

    /**
     * @param  list<RouteFile>  $files
     * @return list<array{0: string, 1: string, 2: list<string>, 3: ?string}>
     */
    private function shape(array $files): array
    {
        return array_map(fn (RouteFile $f): array => [$f->path, $f->prefix, $f->middleware, $f->namespace], $files);
    }

    public function testLaravel11WithRouting(): void
    {
        [$files, $warnings] = $this->locate(BenchmarkCorpus::root().'/laravel11-app', 11);
        self::assertSame([['routes/web.php', '', ['web'], null], ['routes/api.php', 'api', ['api'], null]], $this->shape($files));
        self::assertSame([], $warnings);
    }

    public function testLaravel10RouteServiceProvider(): void
    {
        [$files] = $this->locate(BenchmarkCorpus::root().'/laravel10-app', 10);
        self::assertSame([
            ['routes/api.php', 'api', ['api'], 'App\\Http\\Controllers'],
            ['routes/web.php', '', ['web'], 'App\\Http\\Controllers'],
        ], $this->shape($files));
    }

    public function testApiPrefixArgument(): void
    {
        $root = $this->project([
            'bootstrap/app.php' => "<?php\nreturn Application::configure()->withRouting(api: __DIR__.'/../routes/api.php', apiPrefix: 'v1')->create();",
            'routes/api.php' => '<?php',
        ]);
        [$files] = $this->locate($root, 11);
        self::assertSame([['routes/api.php', 'v1', ['api'], null]], $this->shape($files));
    }

    public function testThenClosureWarns(): void
    {
        $root = $this->project([
            'bootstrap/app.php' => "<?php\nreturn Application::configure()->withRouting(web: __DIR__.'/../routes/web.php', then: function () {})->create();",
            'routes/web.php' => '<?php',
        ]);
        [, $warnings] = $this->locate($root, 11);
        self::assertSame(['bootstrap/app.php:2: then: routes are not analysed'], $warnings);
    }

    public function testFallbackDefaults(): void
    {
        $root = $this->project(['routes/web.php' => '<?php', 'routes/api.php' => '<?php']);
        [$files, $warnings] = $this->locate($root, 10);
        self::assertSame([['routes/web.php', '', ['web'], null], ['routes/api.php', 'api', ['api'], null]], $this->shape($files));
        self::assertSame([], $warnings);
    }

    public function testConfigRouteFilesAppended(): void
    {
        $root = $this->project(['routes/web.php' => '<?php', 'routes/extra.php' => '<?php']);
        [$files] = $this->locate($root, 10, ['routes/extra.php', 'routes/web.php']);
        self::assertSame([['routes/web.php', '', ['web'], null], ['routes/extra.php', '', [], null]], $this->shape($files));
    }

    public function testMissingRouteFileWarns(): void
    {
        $root = $this->project([
            'bootstrap/app.php' => "<?php\nreturn Application::configure()->withRouting(web: __DIR__.'/../routes/web.php')->create();",
        ]);
        [$files, $warnings] = $this->locate($root, 11);
        self::assertSame([], $files);
        self::assertSame(['route file routes/web.php not found'], $warnings);
    }

    public function testUnresolvablePathWarns(): void
    {
        $root = $this->project([
            'app/Providers/RouteServiceProvider.php' => <<<'PHP'
<?php
namespace App\Providers;
use Illuminate\Foundation\Support\Providers\RouteServiceProvider as ServiceProvider;
use Illuminate\Support\Facades\Route;
class RouteServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        $path = 'x';
        Route::middleware('web')->group($path);
        Route::prefix('/admin/')->middleware(['web', 'auth'])->group(base_path('routes/admin.php'));
        Route::middleware('web')->group(function () {});
    }
}
PHP,
            'routes/admin.php' => '<?php',
        ]);
        [$files, $warnings] = $this->locate($root, 10);
        self::assertSame([['routes/admin.php', 'admin', ['web', 'auth'], null]], $this->shape($files));
        self::assertSame(['app/Providers/RouteServiceProvider.php:10: route file path could not be resolved'], $warnings);
    }

    private function provider(string $body): string
    {
        $code = "<?php\nnamespace App\\Providers;\nuse Illuminate\\Foundation\\Support\\Providers\\RouteServiceProvider as ServiceProvider;\nuse Illuminate\\Support\\Facades\\Route;\nclass RouteServiceProvider extends ServiceProvider\n{\n    protected \$namespace = 'App\\\\Http';\n    public function boot(): void\n    {\n".$body."\n    }\n}\n";

        return $this->project(['app/Providers/RouteServiceProvider.php' => $code, 'routes/admin.php' => '<?php']);
    }

    public function testArrayWebArgument(): void
    {
        $root = $this->project([
            'bootstrap/app.php' => "<?php\nreturn A::configure()->withRouting(web: [__DIR__.'/../routes/web.php', __DIR__.'/../routes/more.php'])->create();",
            'routes/web.php' => '<?php',
            'routes/more.php' => '<?php',
        ]);
        [$files] = $this->locate($root, 11);
        self::assertSame([['routes/web.php', '', ['web'], null], ['routes/more.php', '', ['web'], null]], $this->shape($files));
    }

    public function testPositionalWithRoutingWarns(): void
    {
        $root = $this->project(['bootstrap/app.php' => "<?php\nreturn A::configure()->withRouting(__DIR__.'/../routes/web.php')->create();"]);
        [$files, $warnings] = $this->locate($root, 11);
        self::assertSame([], $files);
        self::assertSame(['bootstrap/app.php:2: withRouting positional arguments are not analysed'], $warnings);
    }

    public function testUsingAndSpreadWarn(): void
    {
        $root = $this->project(['bootstrap/app.php' => "<?php\nreturn A::configure()->withRouting(using: function () {}, ...\$args)->create();"]);
        [, $warnings] = $this->locate($root, 11);
        self::assertSame([
            'bootstrap/app.php:2: withRouting using: arguments are not analysed',
            'bootstrap/app.php:2: withRouting spread arguments are not analysed',
        ], $warnings);
    }

    public function testWithRoutingFindingNothingWarns(): void
    {
        $root = $this->project(['bootstrap/app.php' => "<?php\nreturn A::configure()->withRouting(health: '/up')->create();"]);
        [, $warnings] = $this->locate($root, 11);
        self::assertSame(['bootstrap/app.php:2: withRouting found no route files'], $warnings);
    }

    public function testStaticRouteGroupArray(): void
    {
        $root = $this->provider("        Route::group(['prefix' => '/adm/', 'middleware' => ['web', 'auth'], 'namespace' => 'X'], base_path('routes/admin.php'));\n        Route::group(['prefix' => 'z'], function () {});");
        [$files, $warnings] = $this->locate($root, 10);
        self::assertSame([['routes/admin.php', 'adm', ['web', 'auth'], 'X']], $this->shape($files));
        self::assertSame([], $warnings);
    }

    public function testUnresolvedMiddlewareAndNamespaceWarn(): void
    {
        $root = $this->provider("        Route::middleware(['web', \$m, null])->namespace(\$ns)->group(base_path('routes/admin.php'));\n        Route::namespace(null)->group(base_path('routes/admin.php'));");
        [$files, $warnings] = $this->locate($root, 10);
        self::assertSame([['routes/admin.php', '', ['web'], null]], $this->shape($files));
        self::assertSame([
            'app/Providers/RouteServiceProvider.php:10: route middleware could not be resolved',
            'app/Providers/RouteServiceProvider.php:10: route namespace could not be resolved',
        ], $warnings);
    }

    public function testWithoutMiddlewareWarns(): void
    {
        $root = $this->provider("        Route::withoutMiddleware('auth')->group(base_path('routes/admin.php'));");
        [$files, $warnings] = $this->locate($root, 10);
        self::assertCount(1, $files);
        self::assertSame(['app/Providers/RouteServiceProvider.php:10: withoutMiddleware on route-file groups is not analysed'], $warnings);
    }

    public function testNestedGroupWarns(): void
    {
        $root = $this->provider("        Route::prefix('a')->group(function () {\n            Route::prefix('b')->group(base_path('routes/admin.php'));\n        });");
        [$files, $warnings] = $this->locate($root, 10);
        self::assertSame([], $files);
        self::assertSame(['app/Providers/RouteServiceProvider.php:11: nested route groups in providers are not analysed'], $warnings);
    }
}
