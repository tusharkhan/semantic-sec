<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Framework\Laravel;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Framework\Laravel\RouteFile;
use TusharKhan\SemanticSec\Framework\Laravel\RouteParameter;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;

final class RouteCollectorTest extends TestCase
{
    use RouteSnippets;

    public function testBenchmarkLaravel11WebRoutes(): void
    {
        [$routes, $warnings] = $this->collect(BenchmarkCorpus::root().'/laravel11-app', new RouteFile('routes/web.php', '', ['web'], null));

        self::assertSame([], $warnings);
        self::assertCount(25, $routes);
        $show = $this->find($routes, 'GET /vuln/invoices/{id}');
        self::assertSame('App\\Http\\Controllers\\Vuln\\InvoiceController::show', $show->action->symbol());
        self::assertSame(['web', 'auth'], $show->middleware);
        self::assertSame('routes/web.php', $show->file);
        self::assertSame(12, $show->line);
        self::assertEquals([new RouteParameter('id', null, false)], $show->parameters);

        $pdf = $this->find($routes, 'GET /safe/invoices/{invoice}/pdf');
        self::assertSame(['web', 'auth', 'can:view,invoice'], $pdf->middleware);

        $post = $this->find($routes, 'GET /posts/{post:slug}');
        self::assertSame(['web'], $post->middleware);
        self::assertEquals([new RouteParameter('post', 'slug', false)], $post->parameters);
    }

    public function testBenchmarkLaravel11ApiRoutes(): void
    {
        [$routes, $warnings] = $this->collect(BenchmarkCorpus::root().'/laravel11-app', new RouteFile('routes/api.php', 'api', ['api'], null));

        self::assertSame([], $warnings);
        self::assertSame(['api', 'auth:sanctum'], $this->find($routes, 'PUT /api/vuln/cart')->middleware);
        self::assertSame('App\\Http\\Controllers\\Safe\\CartController::restore', $this->find($routes, 'PUT /api/safe/cart')->action->symbol());
    }

    public function testStringActionsUseNamespace(): void
    {
        [$routes, $warnings] = $this->collect(BenchmarkCorpus::root().'/laravel10-app', new RouteFile('routes/web.php', '', ['web'], 'App\\Http\\Controllers'));

        $show = $this->find($routes, 'GET /vuln/reports/{report}');
        self::assertSame('App\\Http\\Controllers\\Vuln\\ReportController::show', $show->action->symbol());
        self::assertSame(['web', 'auth'], $show->middleware);
        self::assertSame('App\\Http\\Controllers\\Safe\\ReportController::show', $this->find($routes, 'GET /safe/reports/{report}')->action->symbol());
        self::assertSame([], $warnings);
    }

    public function testMatchAnyAndInvokable(): void
    {
        [$routes, $warnings] = $this->snippet(<<<'PHP'
            Route::match(['get', 'POST'], '/m', [FooController::class, 'm']);
            Route::any('a', FooController::class);
            Route::get('/', '\App\Home@index');
            Route::options('o/{x?}', 'Plain');
            PHP);

        self::assertSame([], $warnings);
        self::assertSame(['GET', 'POST'], $this->find($routes, 'GET /m')->methods);
        $any = $this->find($routes, 'DELETE /a');
        self::assertSame(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'], $any->methods);
        self::assertSame('App\\Http\\Controllers\\FooController::__invoke', $any->action->symbol());
        self::assertSame('App\\Home::index', $this->find($routes, 'GET /')->action->symbol());
        $opt = $this->find($routes, 'OPTIONS /o/{x?}');
        self::assertSame('Plain::__invoke', $opt->action->symbol());
        self::assertEquals([new RouteParameter('x', null, true)], $opt->parameters);
    }

    public function testArrayGroupSyntax(): void
    {
        [$routes, $warnings] = $this->snippet(<<<'PHP'
            Route::group(['prefix' => '/admin/', 'middleware' => ['auth', 'verified'], 'as' => 'admin.', 'namespace' => 'Admin'], function () {
                Route::group(['prefix' => 'users', 'namespace' => 'Users', 'excluded_middleware' => 'verified'], fn () => Route::get('{user}', 'ShowController@show')->name('show'));
                Route::group(['namespace' => '\Other'], function () {
                    Route::post('x', 'X@y');
                });
            });
            PHP, new RouteFile('routes/web.php', 'p', ['web'], 'App\\Http\\Controllers'));

        self::assertSame([], $warnings);
        $show = $this->find($routes, 'GET /p/admin/users/{user}');
        self::assertSame('App\\Http\\Controllers\\Admin\\Users\\ShowController::show', $show->action->symbol());
        self::assertSame(['web', 'auth', 'verified'], $show->middleware);
        self::assertSame(['verified'], $show->withoutMiddleware);
        self::assertSame('admin.show', $show->name);
        self::assertSame('Other\\X::y', $this->find($routes, 'POST /p/admin/x')->action->symbol());
    }

    public function testControllerGroupWithMethodNames(): void
    {
        [$routes, $warnings] = $this->snippet(<<<'PHP'
            Route::controller(FooController::class)->prefix('foo')->name('foo.')->group(function () {
                Route::get('/', 'index')->name('index');
                Route::post('/{foo}', 'store');
                Route::put('/z', [App\Other::class, 'z']);
            });
            PHP);

        self::assertSame([], $warnings);
        $index = $this->find($routes, 'GET /foo');
        self::assertSame('App\\Http\\Controllers\\FooController::index', $index->action->symbol());
        self::assertSame('foo.index', $index->name);
        self::assertSame('App\\Http\\Controllers\\FooController::store', $this->find($routes, 'POST /foo/{foo}')->action->symbol());
        self::assertSame('App\\Other::z', $this->find($routes, 'PUT /foo/z')->action->symbol());
    }

    public function testRouteLevelCanAndScopeBindings(): void
    {
        [$routes, $warnings] = $this->snippet(<<<'PHP'
            Route::scopeBindings()->group(function () {
                Route::get('u/{user}/p/{post}', [FooController::class, 'a']);
                Route::get('free/{post}', [FooController::class, 'f'])->withoutScopedBindings();
            });
            Route::get('b/{user}/p/{post}', [FooController::class, 'b'])
                ->can('update', 'post')
                ->middleware(['throttle:6,1', 'verified'], )
                ->withoutMiddleware('web')
                ->whereNumber('user')
                ->scopeBindings();
            Route::get('c/{c}', [FooController::class, 'c'])->can('view-any');
            PHP);

        self::assertSame([], $warnings);
        self::assertTrue($this->find($routes, 'GET /u/{user}/p/{post}')->scopeBindings);
        self::assertFalse($this->find($routes, 'GET /free/{post}')->scopeBindings);
        $b = $this->find($routes, 'GET /b/{user}/p/{post}');
        self::assertSame(['web', 'can:update,post', 'throttle:6,1', 'verified'], $b->middleware);
        self::assertSame(['web'], $b->withoutMiddleware);
        self::assertTrue($b->scopeBindings);
        self::assertSame(10, $b->line);
        self::assertSame(['web', 'can:view-any'], $this->find($routes, 'GET /c/{c}')->middleware);
        self::assertFalse($this->find($routes, 'GET /c/{c}')->scopeBindings);
    }

    public function testClosureActionIsKept(): void
    {
        [$routes, $warnings] = $this->snippet(<<<'PHP'
            Route::get('hello', function () { return 'hi'; });
            Route::get('arrow', fn () => 'hi');
            PHP);

        self::assertSame([], $warnings);
        foreach (['GET /hello', 'GET /arrow'] as $key) {
            $route = $this->find($routes, $key);
            self::assertTrue($route->action->isClosure());
            self::assertNull($route->action->symbol());
        }
    }

    public function testUnsupportedConstructsWarnAndContinue(): void
    {
        [$routes, $warnings] = $this->snippet(<<<'PHP'
            if (app()->isLocal()) {
                Route::get('debug', [FooController::class, 'debug']);
            }
            foreach (['a', 'b'] as $x) {
                Route::get($x, [FooController::class, 'x']);
            }
            Route::fallback([FooController::class, 'missing']);
            Route::get('after', [FooController::class, 'after']);
            PHP);

        self::assertSame([
            'routes/web.php:6: If_ in route file is not analysed',
            'routes/web.php:9: Foreach_ in route file is not analysed',
            'routes/web.php:12: Route::fallback is not analysed',
        ], $warnings);
        self::assertCount(1, $routes);
        $this->find($routes, 'GET /after');
    }

    public function testDynamicPartsWarnNeverSilently(): void
    {
        [$routes, $warnings] = $this->snippet(<<<'PHP'
            $router->get('r', 'X@y');
            Route::middleware(['auth', $mw])->group(function () {
                Route::get('one', [FooController::class, 'one'])->middleware($more)->block();
                Route::get($uri, [FooController::class, 'two']);
                Route::view('/welcome', 'welcome');
            });
            Route::get('three', $action);
            Route::group($attrs, function () {
                Route::get('four', [FooController::class, 'four']);
            });
            PHP);

        self::assertSame([
            'routes/web.php:6: MethodCall in route file is not analysed',
            'routes/web.php:7: route middleware could not be resolved',
            'routes/web.php:8: route middleware could not be resolved',
            'routes/web.php:8: route method block is not analysed',
            'routes/web.php:9: route URI could not be resolved',
            'routes/web.php:10: Route::view is not analysed',
            'routes/web.php:12: route action could not be resolved',
            'routes/web.php:13: route group attributes could not be resolved',
        ], $warnings);
        self::assertSame(['web', 'auth'], $this->find($routes, 'GET /one')->middleware);
        self::assertNull($this->find($routes, 'GET /three')->action->symbol());
        $this->find($routes, 'GET /four');
    }

    public function testGroupFilePathsAndCycles(): void
    {
        [$routes, $warnings] = $this->snippet(<<<'PHP'
            Route::prefix('adm')->middleware('auth')->group(__DIR__.'/admin.php');
            Route::group([], base_path('routes/missing.php'));
            require __DIR__.'/auth.php';
            PHP, extra: [
                'routes/admin.php' => "<?php\nRoute::get('dash', 'D@x');\nRoute::prefix('again')->group(base_path('routes/web.php'));\n",
                'routes/auth.php' => "<?php\n\\Route::post('login', 'L@x');\n",
            ]);

        self::assertSame([
            'routes/admin.php:3: route file routes/web.php is loaded recursively',
            'routes/web.php:7: route file routes/missing.php not found',
        ], $warnings);
        $dash = $this->find($routes, 'GET /adm/dash');
        self::assertSame(['web', 'auth'], $dash->middleware);
        self::assertSame('routes/admin.php', $dash->file);
        self::assertSame(2, $dash->line);
        self::assertSame(['web'], $this->find($routes, 'POST /login')->middleware);
    }

    public function testUnresolvableMethodsAndCanModelsWarn(): void
    {
        [$routes, $warnings] = $this->snippet(<<<'PHP'
            Route::match([], 'a', [FooController::class, 'a']);
            Route::match(['get', null], 'b', [FooController::class, 'b']);
            Route::match(['get', $verb], 'c', [FooController::class, 'c']);
            Route::get('d', [FooController::class, 'd'])->can('view', [null]);
            Route::get('e', [FooController::class, 'e'])->can('view', null);
            PHP);

        self::assertSame([
            'routes/web.php:6: route methods could not be resolved',
            'routes/web.php:7: route methods could not be resolved',
            'routes/web.php:8: route methods could not be resolved',
            'routes/web.php:9: route middleware could not be resolved',
        ], $warnings);
        self::assertSame(['web'], $this->find($routes, 'GET /d')->middleware);
        self::assertSame(['web', 'can:view'], $this->find($routes, 'GET /e')->middleware);
        self::assertCount(2, $routes);
    }

    public function testFullyQualifiedStringControllerKeepsLeadingBackslash(): void
    {
        [$routes, $warnings] = $this->snippet(<<<'PHP'
            Route::controller('\App\Other\XController')->group(function () {
                Route::get('x', 'show');
            });
            Route::controller('Admin\YController')->group(fn () => Route::get('y', 'show'));
            PHP, new RouteFile('routes/web.php', '', ['web'], 'App\Http\Controllers'));

        self::assertSame([], $warnings);
        self::assertSame('App\Other\XController::show', $this->find($routes, 'GET /x')->action->symbol());
        self::assertSame('App\Http\Controllers\Admin\YController::show', $this->find($routes, 'GET /y')->action->symbol());
    }

    public function testMissingRouteFileWarns(): void
    {
        [$routes, $warnings] = $this->snippet('', new RouteFile('routes/nope.php', '', [], null));

        self::assertSame([], $routes);
        self::assertSame(['route file routes/nope.php not found'], $warnings);
    }
}
