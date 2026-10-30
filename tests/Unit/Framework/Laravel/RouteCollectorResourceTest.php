<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Framework\Laravel;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Framework\Laravel\RouteEntry;
use TusharKhan\SemanticSec\Framework\Laravel\RouteFile;
use TusharKhan\SemanticSec\Framework\Laravel\RouteParameter;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;

final class RouteCollectorResourceTest extends TestCase
{
    use RouteSnippets;

    public function testResourceExpandsSevenActions(): void
    {
        [$routes, $warnings] = $this->snippet(<<<'PHP'
            Route::middleware('auth')->group(function () {
                Route::resource('photos', FooController::class);
            });
            PHP);

        self::assertSame([], $warnings);
        self::assertSame([
            'GET /photos', 'GET /photos/create', 'POST /photos', 'GET /photos/{photo}', 'GET /photos/{photo}/edit',
            'PUT /photos/{photo}', 'PATCH /photos/{photo}', 'DELETE /photos/{photo}',
        ], $this->keys($routes));
        self::assertSame(
            ['photos.index', 'photos.create', 'photos.store', 'photos.show', 'photos.edit', 'photos.update', 'photos.destroy'],
            array_map(fn (RouteEntry $r): ?string => $r->name, $routes),
        );
        $show = $this->find($routes, 'GET /photos/{photo}');
        self::assertSame('App\\Http\\Controllers\\FooController::show', $show->action->symbol());
        self::assertSame(['web', 'auth'], $show->middleware);
        self::assertEquals([new RouteParameter('photo', null, false)], $show->parameters);
        self::assertSame('routes/web.php', $show->file);
        self::assertSame(7, $show->line);
        self::assertSame(['PUT', 'PATCH'], $this->find($routes, 'PATCH /photos/{photo}')->methods);
        self::assertSame('App\\Http\\Controllers\\FooController::destroy', $this->find($routes, 'DELETE /photos/{photo}')->action->symbol());
    }

    public function testApiResource(): void
    {
        [$routes, $warnings] = $this->snippet(<<<'PHP'
            Route::apiResource('photos', FooController::class);
            Route::apiResource('tags', FooController::class)->except('destroy');
            PHP);

        self::assertSame([], $warnings);
        self::assertSame([
            'GET /photos', 'POST /photos', 'GET /photos/{photo}', 'PUT /photos/{photo}', 'PATCH /photos/{photo}', 'DELETE /photos/{photo}',
            'GET /tags', 'POST /tags', 'GET /tags/{tag}', 'PUT /tags/{tag}', 'PATCH /tags/{tag}',
        ], $this->keys($routes));
    }

    public function testOnlyExcept(): void
    {
        [$routes, $warnings] = $this->snippet(<<<'PHP'
            Route::resource('a', FooController::class)->only('index');
            Route::resource('b', FooController::class)->only(['show', 'index']);
            Route::resource('c', FooController::class)->except(['create', 'edit', 'update', 'destroy']);
            Route::resource('d', FooController::class, ['only' => ['store']]);
            PHP);

        self::assertSame([], $warnings);
        self::assertSame(['GET /a', 'GET /b', 'GET /b/{b}', 'GET /c', 'POST /c', 'GET /c/{c}', 'POST /d'], $this->keys($routes));
    }

    public function testBenchmarkLaravel10NotesResource(): void
    {
        [$routes, $warnings] = $this->collect(BenchmarkCorpus::root().'/laravel10-app', new RouteFile('routes/web.php', '', ['web'], 'App\\Http\\Controllers'));

        self::assertSame([], $warnings);
        $show = $this->find($routes, 'GET /vuln/notes/{note}');
        self::assertSame('App\\Http\\Controllers\\Vuln\\NoteController::show', $show->action->symbol());
        self::assertSame('vuln.notes.show', $show->name);
        self::assertSame(['web', 'auth'], $show->middleware);
        self::assertSame(14, $show->line);
        self::assertSame('App\\Http\\Controllers\\Safe\\NoteController::show', $this->find($routes, 'GET /safe/notes/{note}')->action->symbol());
        $keys = $this->keys($routes);
        self::assertNotContains('GET /vuln/notes/create', $keys);
        self::assertNotContains('GET /vuln/notes/{note}/edit', $keys);
        self::assertContains('PATCH /safe/notes/{note}', $keys);
        self::assertCount(12, $routes);
    }

    public function testNestedResource(): void
    {
        [$routes, $warnings] = $this->snippet(<<<'PHP'
            Route::resource('photos.comments', FooController::class)->only(['index', 'show']);
            Route::resource('admin/posts.tags', FooController::class)->only(['index', 'show', 'update'])->shallow();
            PHP);

        self::assertSame([], $warnings);
        self::assertSame([
            'GET /photos/{photo}/comments', 'GET /photos/{photo}/comments/{comment}',
            'GET /admin/posts/{post}/tags', 'GET /admin/tags/{tag}', 'PUT /admin/tags/{tag}', 'PATCH /admin/tags/{tag}',
        ], $this->keys($routes));
        $show = $this->find($routes, 'GET /photos/{photo}/comments/{comment}');
        self::assertSame('photos.comments.show', $show->name);
        self::assertEquals([new RouteParameter('photo', null, false), new RouteParameter('comment', null, false)], $show->parameters);
        self::assertSame('posts.tags.index', $this->find($routes, 'GET /admin/posts/{post}/tags')->name);
        self::assertSame('tags.show', $this->find($routes, 'GET /admin/tags/{tag}')->name);
    }

    public function testIrregularSingular(): void
    {
        [$routes, $warnings] = $this->snippet(<<<'PHP'
            Route::resource('people', FooController::class)->only('show');
            Route::resource('categories', FooController::class)->only('show');
            Route::resource('user-profiles', FooController::class)->only('show');
            Route::resource('admin/media', FooController::class)->only('show');
            PHP);

        self::assertSame([], $warnings);
        self::assertSame(['GET /people/{person}', 'GET /categories/{category}', 'GET /user-profiles/{user_profile}', 'GET /admin/media/{medium}'], $this->keys($routes));
    }

    public function testParametersOverride(): void
    {
        [$routes, $warnings] = $this->snippet(<<<'PHP'
            Route::resource('photos.comments', FooController::class)->only('show')->parameters(['photos' => 'album', 'comments' => 'note']);
            Route::apiResource('users', FooController::class)->only('show')->parameter('users', 'admin_user');
            Route::resource('tags', FooController::class, ['only' => 'show', 'parameters' => ['tags' => 'label']]);
            PHP);

        self::assertSame([], $warnings);
        self::assertSame(['GET /photos/{album}/comments/{note}', 'GET /users/{admin_user}', 'GET /tags/{label}'], $this->keys($routes));
    }

    public function testNamesMiddlewareAndBindings(): void
    {
        [$routes, $warnings] = $this->snippet(<<<'PHP'
            Route::name('admin.')->group(function () {
                Route::resource('admin/photos', FooController::class)->only(['index', 'show']);
                Route::resource('notes', FooController::class)->only(['index', 'show'])->names('vuln.notes');
                Route::resource('tags', FooController::class)->only(['index', 'show', 'store'])->names(['index' => 'tag.list'])->name('show', 'tag.view');
            });
            Route::resource('posts.comments', FooController::class)->only('show')
                ->middleware(['auth', 'verified'])->middleware('can:view,comment')
                ->withoutMiddleware('web')
                ->scoped(['comment' => 'slug']);
            Route::resource('files', FooController::class)->only('show')->scopeBindings()->whereNumber('file');
            PHP);

        self::assertSame([], $warnings);
        self::assertSame('admin.photos.index', $this->find($routes, 'GET /admin/photos')->name);
        self::assertSame('admin.vuln.notes.show', $this->find($routes, 'GET /notes/{note}')->name);
        self::assertSame('admin.tag.list', $this->find($routes, 'GET /tags')->name);
        self::assertSame('admin.tag.view', $this->find($routes, 'GET /tags/{tag}')->name);
        self::assertSame('admin.tags.store', $this->find($routes, 'POST /tags')->name);
        $comment = $this->find($routes, 'GET /posts/{post}/comments/{comment}');
        self::assertSame(['web', 'can:view,comment'], $comment->middleware);
        self::assertSame(['web'], $comment->withoutMiddleware);
        self::assertTrue($comment->scopeBindings);
        self::assertEquals([new RouteParameter('post', null, false), new RouteParameter('comment', 'slug', false)], $comment->parameters);
        self::assertTrue($this->find($routes, 'GET /files/{file}')->scopeBindings);
        self::assertFalse($this->find($routes, 'GET /tags/{tag}')->scopeBindings);
    }

    public function testResourcesArrayAndNamespace(): void
    {
        [$routes, $warnings] = $this->snippet(<<<'PHP'
            Route::resources(['photos' => 'PhotoController', 'tags' => '\App\Other\TagController'], ['only' => ['show']]);
            Route::apiResources(['users' => FooController::class]);
            PHP, new RouteFile('routes/web.php', '', ['web'], 'App\\Http\\Controllers'));

        self::assertSame([], $warnings);
        self::assertSame('App\\Http\\Controllers\\PhotoController::show', $this->find($routes, 'GET /photos/{photo}')->action->symbol());
        self::assertSame('App\\Other\\TagController::show', $this->find($routes, 'GET /tags/{tag}')->action->symbol());
        self::assertSame('App\\Http\\Controllers\\FooController::index', $this->find($routes, 'GET /users')->action->symbol());
        self::assertCount(7, $routes);
    }

    public function testPerMethodMiddleware(): void
    {
        [$routes, $warnings] = $this->snippet(<<<'PHP'
            Route::resource('a', FooController::class)->only(['index', 'show'])->middleware('auth')->withoutMiddlewareFor('show', 'auth');
            Route::resource('b', FooController::class)->only(['index', 'show', 'update'])
                ->middleware('auth')
                ->middlewareFor(['show', 'update'], 'can:view,b')
                ->middleware(['auth', 'verified'])
                ->withoutMiddleware('web')
                ->withoutMiddlewareFor('update', ['throttle']);
            Route::resource('c', FooController::class, [
                'only' => ['index', 'show'],
                'middleware_for' => ['show' => 'signed'],
                'excluded_middleware_for' => ['index' => ['web']],
            ]);
            Route::resource('d', FooController::class)->only('show')->middlewareFor($methods, 'auth')->withoutMiddlewareFor('show', [$mw]);
            PHP);

        self::assertSame([
            'routes/web.php:18: route middleware could not be resolved',
            'routes/web.php:18: route middleware could not be resolved',
        ], $warnings);
        $show = $this->find($routes, 'GET /a/{a}');
        self::assertSame(['web', 'auth'], $show->middleware);
        self::assertSame(['auth'], $show->withoutMiddleware);
        self::assertSame([], $this->find($routes, 'GET /a')->withoutMiddleware);

        self::assertSame(['web', 'auth', 'verified'], $this->find($routes, 'GET /b')->middleware);
        self::assertSame(['web', 'auth', 'can:view,b', 'verified'], $this->find($routes, 'GET /b/{b}')->middleware);
        self::assertSame(['web'], $this->find($routes, 'GET /b/{b}')->withoutMiddleware);
        self::assertSame(['web', 'throttle'], $this->find($routes, 'PUT /b/{b}')->withoutMiddleware);

        self::assertSame(['web'], $this->find($routes, 'GET /c')->middleware);
        self::assertSame(['web'], $this->find($routes, 'GET /c')->withoutMiddleware);
        self::assertSame(['web', 'signed'], $this->find($routes, 'GET /c/{c}')->middleware);
        self::assertSame(['web'], $this->find($routes, 'GET /d/{d}')->middleware);
    }

    public function testLaterNamesAndParametersReplaceEarlierOnes(): void
    {
        [$routes, $warnings] = $this->snippet(<<<'PHP'
            Route::resource('photos', FooController::class)->only(['index', 'show'])->names(['show' => 'p.view'])->names('foo');
            Route::resource('tags', FooController::class)->only(['index', 'show'])->names('foo')->names(['index' => 't.list']);
            Route::resource('users', FooController::class)->only('show')->parameters(['users' => 'member'])->parameters(['photos' => 'pic']);
            PHP);

        self::assertSame([], $warnings);
        self::assertSame('foo.show', $this->find($routes, 'GET /photos/{photo}')->name);
        self::assertSame('t.list', $this->find($routes, 'GET /tags')->name);
        self::assertSame('tags.show', $this->find($routes, 'GET /tags/{tag}')->name);
        self::assertSame(['GET /photos', 'GET /photos/{photo}', 'GET /tags', 'GET /tags/{tag}', 'GET /users/{user}'], $this->keys($routes));
    }

    public function testFullyDynamicOnlyKeepsAllRoutes(): void
    {
        [$routes, $warnings] = $this->snippet(<<<'PHP'
            Route::apiResource('photos', FooController::class)->only($methods);
            Route::resource('tags', FooController::class)->only([]);
            PHP);

        self::assertSame(['routes/web.php:6: route resource methods could not be resolved'], $warnings);
        self::assertSame(['GET /photos', 'POST /photos', 'GET /photos/{photo}', 'PUT /photos/{photo}', 'PATCH /photos/{photo}', 'DELETE /photos/{photo}'], $this->keys($routes));
    }

    public function testUnsupportedResourcePartsWarn(): void
    {
        [$routes, $warnings] = $this->snippet(<<<'PHP'
            Route::resource($name, FooController::class);
            Route::resource('a', $controller)->only('show');
            Route::resource('b', FooController::class)->only(['show', $more])->missing(fn () => null);
            Route::resources($map);
            Route::resource('c', FooController::class, ['only' => ['show'], 'trashed' => ['show']]);
            Route::singleton('profile', FooController::class);
            PHP);

        self::assertSame([
            'routes/web.php:6: route resource name could not be resolved',
            'routes/web.php:7: route action could not be resolved',
            'routes/web.php:8: route resource methods could not be resolved',
            'routes/web.php:8: route method missing is not analysed',
            'routes/web.php:9: route resources could not be resolved',
            'routes/web.php:10: route resource option trashed is not analysed',
            'routes/web.php:11: Route::singleton is not analysed yet',
        ], $warnings);
        self::assertNull($this->find($routes, 'GET /a/{a}')->action->symbol());
        self::assertSame(['GET /a/{a}', 'GET /b/{b}', 'GET /c/{c}'], $this->keys($routes));
    }
}
