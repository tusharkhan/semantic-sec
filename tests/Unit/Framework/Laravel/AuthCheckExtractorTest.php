<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Framework\Laravel;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Framework\DetectedFramework;
use TusharKhan\SemanticSec\Framework\Laravel\AuthCheck;
use TusharKhan\SemanticSec\Framework\Laravel\AuthCheckExtractor;
use TusharKhan\SemanticSec\Framework\Laravel\ConstantEvaluator;
use TusharKhan\SemanticSec\Framework\Laravel\ControllerMiddlewareReader;
use TusharKhan\SemanticSec\Framework\Laravel\MiddlewareRegistry;
use TusharKhan\SemanticSec\Framework\Laravel\PolicyRegistry;
use TusharKhan\SemanticSec\Framework\Laravel\RouteCollector;
use TusharKhan\SemanticSec\Framework\Laravel\RouteEntry;
use TusharKhan\SemanticSec\Framework\Laravel\RouteFile;
use TusharKhan\SemanticSec\Parsing\AstGenerator;
use TusharKhan\SemanticSec\Parsing\ParseResult;
use TusharKhan\SemanticSec\Parsing\SourceFile;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTableBuilder;

final class AuthCheckExtractorTest extends TestCase
{
    private const BASE = [
        'app/Models/User.php' => '<?php namespace App\Models; class User extends \Illuminate\Foundation\Auth\User {}',
        'app/Models/Post.php' => '<?php namespace App\Models; class Post extends \Illuminate\Database\Eloquent\Model {}',
        'app/Policies/PostPolicy.php' => <<<'PHP'
            <?php
            namespace App\Policies;

            use App\Models\Post;
            use App\Models\User;

            class PostPolicy
            {
                public function viewAny(User $user): bool { return $user->is_admin; }
                public function view(User $user, Post $post): bool { return $user->id === $post->user_id; }
                public function update(User $user, Post $post): bool { return $user->id === $post->user_id; }
                public function delete(User $user, Post $post): bool { return true; }
            }
            PHP,
        'app/Http/Controllers/Controller.php' => '<?php namespace App\Http\Controllers; abstract class Controller { use \Illuminate\Foundation\Auth\Access\AuthorizesRequests; }',
    ];

    private const CONTROLLER_HEAD = <<<'PHP'
        <?php
        namespace App\Http\Controllers;

        use App\Models\Post;
        use App\Models\User;
        use App\Http\Requests\SaveRequest;
        use Illuminate\Http\Request;
        use Illuminate\Support\Facades\Auth;
        use Illuminate\Support\Facades\Gate;
        use App\Support\Access;

        PHP;

    /**
     * @param  array<string, string>  $files
     * @param  list<string>  $helpers
     * @return array{0: array<string, RouteEntry>, 1: list<string>}
     */
    private function analyse(string $routes, array $files = [], array $helpers = []): array
    {
        $files = ['routes/web.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\nuse App\\Http\\Controllers\\C;\nuse App\\Http\\Controllers\\D;\nuse App\\Models\\Post;\nuse Illuminate\\Http\\Request;\n\n".$routes."\n"] + $files + self::BASE;
        $parsed = [];
        foreach ($files as $path => $code) {
            $parsed[] = (new AstGenerator())->parse(new SourceFile($path, '/nonexistent/'.$path, $code));
        }
        $result = new ParseResult($parsed, []);
        $symbols = (new SymbolTableBuilder())->build($result);
        $eval = new ConstantEvaluator();
        [$registry] = MiddlewareRegistry::fromProject($result, $symbols, new DetectedFramework('laravel', 11), $eval);
        [$policies] = PolicyRegistry::fromProject($symbols, $eval);
        [$entries, $collectWarnings] = (new RouteCollector($result, $eval))->collect(new RouteFile('routes/web.php', '', [], null));
        self::assertSame([], $collectWarnings);

        $extractor = new AuthCheckExtractor($symbols, $registry, $policies, new ControllerMiddlewareReader($symbols, $eval), $helpers);
        $out = [];
        $warnings = [];
        foreach ($entries as $entry) {
            [$route, $w] = $extractor->extract($entry);
            array_push($warnings, ...$w);
            foreach ($route->keys() as $key) {
                $out[$key] = $route;
            }
        }

        return [$out, $warnings];
    }

    /** @return array<string, string> */
    private function controller(string $body, string $name = 'C', string $extends = 'Controller', string $implements = ''): array
    {
        return ['app/Http/Controllers/'.$name.'.php' => self::CONTROLLER_HEAD."class {$name} extends {$extends}{$implements}\n{\n{$body}\n}\n"];
    }

    /** @return list<string> kind/strength in output order */
    private static function checks(RouteEntry $route): array
    {
        return array_map(static fn (AuthCheck $c): string => $c->kind->value.'/'.$c->strength->value, $route->checks);
    }

    /** @return list<string> */
    private static function sources(RouteEntry $route): array
    {
        return array_map(static fn (AuthCheck $c): string => $c->source, $route->checks);
    }

    public function testAuthMiddlewareIsAuthentication(): void
    {
        [$routes] = $this->analyse(
            "Route::get('a', [C::class, 'a'])->middleware('auth');\nRoute::get('b', [C::class, 'a'])->middleware(['verified', 'throttle:60,1']);",
            $this->controller('public function a() { return 1; }'),
        );
        self::assertSame(['authentication/authentication'], self::checks($routes['GET /a']));
        self::assertSame(['middleware auth'], self::sources($routes['GET /a']));
        self::assertSame('routes/web.php', $routes['GET /a']->checks[0]->file);
        self::assertSame(9, $routes['GET /a']->checks[0]->line);
        self::assertSame(['authentication/authentication'], self::checks($routes['GET /b']));
    }

    public function testRouteCanWithTrivialPolicyIsNone(): void
    {
        [$routes] = $this->analyse(
            "Route::delete('posts/{post}', [C::class, 'destroy'])->middleware('can:delete,post');\n"
            ."Route::put('posts/{post}', [C::class, 'update'])->can('update', 'post');\n"
            ."Route::post('posts', [C::class, 'store'])->middleware('can:delete,App\\Models\\Post');\n"
            ."Route::get('posts', [C::class, 'store'])->can('viewAny', Post::class);",
            $this->controller('public function destroy(Post $post) {} public function update(Post $post) {} public function store() {}'),
        );
        self::assertSame(['route_ability/none'], self::checks($routes['DELETE /posts/{post}']));
        self::assertSame('App\Models\Post', $routes['DELETE /posts/{post}']->parameters[0]->boundModel);
        self::assertSame(['route_ability/authorization'], self::checks($routes['PUT /posts/{post}']));
        self::assertSame(['middleware can:update,post'], self::sources($routes['PUT /posts/{post}']));
        self::assertSame(['route_ability/none'], self::checks($routes['POST /posts']));
        self::assertSame(['route_ability/authorization'], self::checks($routes['GET /posts']));
    }

    public function testHasMiddlewareCanIsRouteAbility(): void
    {
        $body = <<<'PHP'
                public static function middleware(): array
                {
                    return [new \Illuminate\Routing\Controllers\Middleware('can:view,post', only: ['show'])];
                }
                public function show(Post $post) {}
                public function index() {}
            PHP;
        [$routes] = $this->analyse(
            "Route::get('posts/{post}', [C::class, 'show']);\nRoute::get('posts', [C::class, 'index']);",
            $this->controller($body, implements: ' implements \Illuminate\Routing\Controllers\HasMiddleware'),
        );
        self::assertSame(['route_ability/authorization'], self::checks($routes['GET /posts/{post}']));
        self::assertSame([], self::checks($routes['GET /posts']));
    }

    public function testAuthorizeResourceMapsShowToView(): void
    {
        $body = <<<'PHP'
                public function __construct() { $this->authorizeResource(Post::class, 'post'); }
                public function show(Post $post) {}
                public function destroy(Post $post) {}
                public function index() {}
                public function publish(Post $post) {}
            PHP;
        [$routes] = $this->analyse(
            "Route::get('posts/{post}', [C::class, 'show']);\nRoute::delete('posts/{post}', [C::class, 'destroy']);\n"
            ."Route::get('posts', [C::class, 'index']);\nRoute::post('posts/{post}/publish', [C::class, 'publish']);\n"
            ."Route::get('drafts/{post}', [D::class, 'show']);",
            $this->controller($body) + $this->controller('', 'D', 'C'),
        );
        self::assertSame(['controller_ability/authorization'], self::checks($routes['GET /posts/{post}']));
        self::assertStringContainsString('authorizeResource', self::sources($routes['GET /posts/{post}'])[0]);
        self::assertSame(['controller_ability/none'], self::checks($routes['DELETE /posts/{post}']));
        self::assertSame(['controller_ability/authorization'], self::checks($routes['GET /posts']));
        self::assertSame([], self::checks($routes['POST /posts/{post}/publish']));
        self::assertSame(['controller_ability/authorization'], self::checks($routes['GET /drafts/{post}']));
    }

    public function testThisAuthorizeIsControllerAbility(): void
    {
        $body = <<<'PHP'
                public function update(Request $request, Post $post)
                {
                    $this->authorize('update', $post);
                    $this->authorizeForUser($request->user(), 'view', $post);
                }
            PHP;
        [$routes] = $this->analyse("Route::put('posts/{post}', [C::class, 'update']);", $this->controller($body));
        self::assertSame(['controller_ability/authorization', 'controller_ability/authorization'], self::checks($routes['PUT /posts/{post}']));
        self::assertSame("\$this->authorize('update', \$post)", self::sources($routes['PUT /posts/{post}'])[0]);
        self::assertSame('app/Http/Controllers/C.php', $routes['PUT /posts/{post}']->checks[0]->file);
        self::assertSame(15, $routes['PUT /posts/{post}']->checks[0]->line);
    }

    public function testTrivialPolicyAuthorizeIsNone(): void
    {
        $body = <<<'PHP'
                public function a(Post $post) { $this->authorize('delete', $post); }
                public function b() { $this->authorize('delete', Post::class); }
                public function c(int $id) { $p = Post::findOrFail($id); $this->authorize('delete', $p); }
                public function d(int $id) { $p = Post::where('id', $id)->firstOrFail(); $this->authorize('delete', $p); }
                public function e($thing) { $this->authorize('delete', $thing); }
                public function f(int $id) { $p = Post::findOrFail($id); $p = $this->load($p); $this->authorize('delete', $p); }
                public function g(Post $post) { $this->authorize('delete', [$post]); }
            PHP;
        $routes = '';
        foreach (['a', 'b', 'c', 'd', 'e', 'f', 'g'] as $m) {
            $routes .= "Route::delete('{$m}', [C::class, '{$m}']);\n";
        }
        [$out] = $this->analyse($routes, $this->controller($body));
        foreach (['a', 'b', 'c', 'd', 'g'] as $m) {
            self::assertSame(['controller_ability/none'], self::checks($out['DELETE /'.$m]), $m);
        }
        self::assertStringContainsString('PostPolicy::delete returns true', self::sources($out['DELETE /a'])[0]);
        self::assertSame(['controller_ability/authorization'], self::checks($out['DELETE /e']));
        self::assertSame(['controller_ability/authorization'], self::checks($out['DELETE /f']));
    }

    public function testGateAndUserCanForms(): void
    {
        $body = <<<'PHP'
                public function a(Post $post) { Gate::authorize('update', $post); }
                public function b(Post $post) { if (Gate::denies('update', $post)) { abort(403); } }
                public function c(Request $request, Post $post) { if ($request->user()->cannot('update', $post)) { abort(403); } }
                public function d(Post $post) { return auth()->user()->can('view', $post) ? 1 : 0; }
                public function e(User $user, Post $post) { return $user->can('update', $post); }
                public function f(User $user, Post $post) { return $user->can('update', $post); }
                public function g(Post $post, Post $other) { return $other->can('update', $post); }
                public function h(Post $post) { return Gate::allows('delete', $post); }
                public function i(Request $request, Post $post) { $me = $request->user(); return $me->can('update', $post); }
            PHP;
        [$out] = $this->analyse(
            "Route::put('a/{post}', [C::class, 'a']);\nRoute::put('b/{post}', [C::class, 'b']);\nRoute::put('c/{post}', [C::class, 'c']);\n"
            ."Route::put('d/{post}', [C::class, 'd']);\nRoute::put('e/{post}', [C::class, 'e']);\nRoute::put('users/{user}/f/{post}', [C::class, 'f']);\n"
            ."Route::put('g/{post}', [C::class, 'g']);\nRoute::put('h/{post}', [C::class, 'h']);\nRoute::put('i/{post}', [C::class, 'i']);",
            $this->controller($body),
        );
        foreach (['a', 'b', 'c', 'd', 'e', 'i'] as $m) {
            self::assertSame(['controller_ability/authorization'], self::checks($out['PUT /'.$m.'/{post}']), $m);
        }
        // A route-bound $user is attacker-chosen, so its can() proves nothing.
        self::assertSame([], self::checks($out['PUT /users/{user}/f/{post}']));
        self::assertSame([], self::checks($out['PUT /g/{post}']));
        self::assertSame(['controller_ability/none'], self::checks($out['PUT /h/{post}']));
    }

    public function testAbortGuardOnlyWithAuthExpression(): void
    {
        $body = <<<'PHP'
                public function a(Post $order) { abort_unless($order->status === 'paid', 422); }
                public function b(Post $post) { abort_if($post->user_id !== auth()->id(), 403); }
                public function c(Request $request, Post $post) { throw_unless($post->user_id === $request->user()->id, new \Exception()); }
                public function d(Post $post) { throw_if(Auth::id() !== $post->user_id, new \Exception()); }
            PHP;
        [$out] = $this->analyse("Route::get('a/{order}', [C::class, 'a']);\nRoute::get('b/{post}', [C::class, 'b']);\nRoute::get('c/{post}', [C::class, 'c']);\nRoute::get('d/{post}', [C::class, 'd']);", $this->controller($body));
        self::assertSame([], self::checks($out['GET /a/{order}']));
        self::assertSame(['abort_guard/authorization'], self::checks($out['GET /b/{post}']));
        self::assertSame(['abort_guard/authorization'], self::checks($out['GET /c/{post}']));
        self::assertSame(['abort_guard/authorization'], self::checks($out['GET /d/{post}']));
    }

    public function testQueryScopeRelationRead(): void
    {
        $body = <<<'PHP'
                public function a(Request $request, int $id) { return $request->user()->posts()->findOrFail($id); }
                public function b() { return auth()->user()->posts()->where('draft', false)->get(); }
                public function c() { return Auth::user()->posts()->paginate(); }
                public function d(Request $request) { $user = $request->user(); return $user->posts()->first(); }
                public function e() { return request()->user()->posts()->latest()->get(); }
                public function f(Request $request, int $id) { return $request->user()->posts->find($id); }
                public function g(int $id) { return Post::findOrFail($id); }
                public function h(Request $request, int $id) { return $request->user()->find($id); }
            PHP;
        $routes = '';
        foreach (['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'] as $m) {
            $routes .= "Route::get('{$m}', [C::class, '{$m}']);\n";
        }
        [$out] = $this->analyse($routes, $this->controller($body));
        foreach (['a', 'b', 'c', 'd', 'e'] as $m) {
            self::assertSame(['query_scope/authorization'], self::checks($out['GET /'.$m]), $m);
        }
        foreach (['f', 'g', 'h'] as $m) {
            self::assertSame([], self::checks($out['GET /'.$m]), $m);
        }
    }

    public function testRelationWriteIsNotScope(): void
    {
        $body = <<<'PHP'
                public function a(Request $request) { $request->user()->account->update(['x' => 1]); }
                public function b(Request $request) { return $request->user()->workspaces()->create(['x' => 1]); }
                public function c(Request $request) { return $request->user()->cart()->updateOrCreate([], ['x' => 1]); }
            PHP;
        [$out] = $this->analyse("Route::put('a', [C::class, 'a']);\nRoute::put('b', [C::class, 'b']);\nRoute::put('c', [C::class, 'c']);", $this->controller($body));
        self::assertSame([], self::checks($out['PUT /a']));
        self::assertSame([], self::checks($out['PUT /b']));
        self::assertSame([], self::checks($out['PUT /c']));
    }

    public function testWhereAuthIdIsScope(): void
    {
        $body = <<<'PHP'
                public function a() { return Post::where('user_id', auth()->id())->get(); }
                public function b() { return Post::query()->where('owner_id', '=', Auth::id())->first(); }
                public function c(Request $request) { return Post::where('x', 1)->orWhere('user_id', $request->user()->id)->get(); }
                public function d(Request $request) { return Post::where('user_id', $request->user()->getKey())->get(); }
                public function e(int $id) { return Post::where('user_id', $id)->get(); }
            PHP;
        $routes = '';
        foreach (['a', 'b', 'c', 'd', 'e'] as $m) {
            $routes .= "Route::get('{$m}', [C::class, '{$m}']);\n";
        }
        [$out] = $this->analyse($routes, $this->controller($body));
        foreach (['a', 'b', 'c', 'd'] as $m) {
            self::assertSame(['query_scope/authorization'], self::checks($out['GET /'.$m]), $m);
        }
        self::assertSame([], self::checks($out['GET /e']));
    }

    public function testWhereBelongsTo(): void
    {
        $body = <<<'PHP'
                public function a(Request $request) { return Post::whereBelongsTo($request->user())->get(); }
                public function b(User $author) { return Post::whereBelongsTo($author)->get(); }
            PHP;
        [$out] = $this->analyse("Route::get('a', [C::class, 'a']);\nRoute::get('b', [C::class, 'b']);", $this->controller($body));
        self::assertSame(['query_scope/authorization'], self::checks($out['GET /a']));
        self::assertSame([], self::checks($out['GET /b']));
    }

    public function testCustomHelper(): void
    {
        $body = <<<'PHP'
                public function a(Post $post) { $this->ensureOwner($post); }
                public function b(Post $post) { Access::check($post); }
                public function c(Post $post) { $this->ownedBy($post); }
                public function d(Post $post) { Access::other($post); }
                private function ownedBy(Post $post): void {}
            PHP;
        [$out] = $this->analyse(
            "Route::get('a/{post}', [C::class, 'a']);\nRoute::get('b/{post}', [C::class, 'b']);\nRoute::get('c/{post}', [C::class, 'c']);\nRoute::get('d/{post}', [C::class, 'd']);",
            $this->controller($body),
            ['ensureOwner', 'App\Support\Access::check', 'App\Http\Controllers\C::ownedBy'],
        );
        self::assertSame(['custom_helper/authorization'], self::checks($out['GET /a/{post}']));
        self::assertSame(['custom_helper/authorization'], self::checks($out['GET /b/{post}']));
        self::assertSame(['custom_helper/authorization'], self::checks($out['GET /c/{post}']));
        self::assertSame([], self::checks($out['GET /d/{post}']));
    }

    /** @return array<string, string> */
    private function formRequest(string $body): array
    {
        return ['app/Http/Requests/SaveRequest.php' => "<?php namespace App\\Http\\Requests; class BaseRequest extends \\Illuminate\\Foundation\\Http\\FormRequest {}\nclass SaveRequest extends BaseRequest {\n{$body}\n}"];
    }

    public function testFormRequestTrivialIsNone(): void
    {
        [$out] = $this->analyse(
            "Route::put('posts/{post}', [C::class, 'update']);",
            $this->controller('public function update(SaveRequest $request, Post $post) {}') + $this->formRequest('public function authorize(): bool { return true; }'),
        );
        self::assertSame(['form_request/none'], self::checks($out['PUT /posts/{post}']));
        self::assertSame(['FormRequest SaveRequest::authorize returns true'], self::sources($out['PUT /posts/{post}']));
    }

    public function testFormRequestWithLogicIsAuthorization(): void
    {
        [$out] = $this->analyse(
            "Route::put('posts/{post}', [C::class, 'update']);",
            $this->controller('public function update(SaveRequest $request, Post $post) {}') + $this->formRequest("public function authorize(): bool { return \$this->user()->can('update', \$this->route('post')); }"),
        );
        self::assertSame(['form_request/authorization'], self::checks($out['PUT /posts/{post}']));
    }

    public function testMissingFormRequestAuthorizeIsNone(): void
    {
        [$out] = $this->analyse(
            "Route::put('posts/{post}', [C::class, 'update']);",
            $this->controller('public function update(SaveRequest $request, Post $post) {}') + $this->formRequest('public function rules(): array { return []; }'),
        );
        self::assertSame(['form_request/none'], self::checks($out['PUT /posts/{post}']));
    }

    public function testClosureActionBodyAnalysed(): void
    {
        [$out] = $this->analyse(
            "Route::get('c/{id}', function (Request \$request, int \$id) { return \$request->user()->posts()->findOrFail(\$id); });\n"
            ."Route::get('p/{post}', fn (Post \$post) => \$post);",
        );
        self::assertSame(['query_scope/authorization'], self::checks($out['GET /c/{id}']));
        self::assertSame('routes/web.php', $out['GET /c/{id}']->checks[0]->file);
        self::assertSame('App\Models\Post', $out['GET /p/{post}']->parameters[0]->boundModel);
        self::assertNull($out['GET /c/{id}']->parameters[0]->boundModel);
    }

    public function testWithoutMiddlewareRemovesAuth(): void
    {
        [$out] = $this->analyse(
            "Route::middleware('auth')->group(function () {\n"
            ."    Route::get('a', [C::class, 'a'])->withoutMiddleware('auth');\n"
            ."    Route::get('b', [C::class, 'a'])->withoutMiddleware(\\Illuminate\\Auth\\Middleware\\Authenticate::class);\n"
            ."    Route::get('c', [C::class, 'a'])->withoutMiddleware('verified');\n"
            ."});\n"
            ."Route::get('d', [C::class, 'a'])->middleware('auth:sanctum')->withoutMiddleware('auth');",
            $this->controller('public function a() {}'),
        );
        self::assertSame([], self::checks($out['GET /a']));
        self::assertSame([], self::checks($out['GET /b']));
        self::assertSame(['authentication/authentication'], self::checks($out['GET /c']));
        // Laravel excludes by exact resolved name, so auth:sanctum survives.
        self::assertSame(['authentication/authentication'], self::checks($out['GET /d']));
    }

    public function testUnknownActionWarns(): void
    {
        [$out, $warnings] = $this->analyse(
            "Route::get('a/{post}', [\\App\\Http\\Controllers\\Missing::class, 'show'])->middleware('auth')->scopeBindings();\n"
            ."Route::get('b', [C::class, 'gone'])->middleware('auth');",
            $this->controller('public function a() {}'),
        );
        self::assertSame(['authentication/authentication'], self::checks($out['GET /a/{post}']));
        self::assertNull($out['GET /a/{post}']->parameters[0]->boundModel);
        self::assertSame(['authentication/authentication'], self::checks($out['GET /b']));
        self::assertSame([
            'routes/web.php:9: action App\Http\Controllers\Missing::show not found',
            'routes/web.php:10: action App\Http\Controllers\C::gone not found',
        ], $warnings);
    }

    public function testBoundModelsOnlyForClassTypedParams(): void
    {
        $files = $this->controller('public function a(Post $post, int $id, $thing, \Vendor\Thing $vendor, \App\Contracts\Ownable $owned, ?string $slug = null) {}')
            + ['app/Contracts/Ownable.php' => '<?php namespace App\Contracts; interface Ownable {}'];
        [$out] = $this->analyse("Route::get('a/{post}/{id}/{thing}/{vendor}/{owned}/{slug?}/{other}', [C::class, 'a']);", $files);
        $bound = [];
        foreach ($out['GET /a/{post}/{id}/{thing}/{vendor}/{owned}/{slug?}/{other}']->parameters as $p) {
            $bound[$p->name] = $p->boundModel;
        }
        self::assertSame(['post' => 'App\Models\Post', 'id' => null, 'thing' => null, 'vendor' => 'Vendor\Thing', 'owned' => 'App\Contracts\Ownable', 'slug' => null, 'other' => null], $bound);
    }

    public function testScopeBindingsIsQueryScope(): void
    {
        [$out] = $this->analyse(
            "Route::get('users/{user}/posts/{post}', [C::class, 'a'])->scopeBindings();",
            $this->controller('public function a(User $user, Post $post) {}'),
        );
        self::assertSame(['query_scope/authorization'], self::checks($out['GET /users/{user}/posts/{post}']));
    }

    public function testImplicitChildBindingIsScoped(): void
    {
        [$out] = $this->analyse(
            "Route::get('users/{user}/posts/{post:slug}', [C::class, 'a']);\n"
            ."Route::get('posts/{post:slug}', [C::class, 'b']);\n"
            ."Route::get('ids/{id}/posts/{post:slug}', [C::class, 'c']);",
            $this->controller('public function a(User $user, Post $post) {} public function b(Post $post) {} public function c(int $id, Post $post) {}'),
        );
        self::assertSame(['query_scope/authorization'], self::checks($out['GET /users/{user}/posts/{post:slug}']));
        self::assertSame(['implicit scoped binding {post:slug}'], self::sources($out['GET /users/{user}/posts/{post:slug}']));
        self::assertSame([], self::checks($out['GET /posts/{post:slug}']));
        self::assertSame([], self::checks($out['GET /ids/{id}/posts/{post:slug}']));
    }

    public function testChecksComeOutInStableOrder(): void
    {
        $body = <<<'PHP'
                public function __construct()
                {
                    $this->middleware('can:view,post');
                    $this->authorizeResource(Post::class, 'post');
                }
                public function update(SaveRequest $request, Post $post)
                {
                    abort_if($post->user_id !== auth()->id(), 403);
                    $this->authorize('update', $post);
                }
            PHP;
        [$out] = $this->analyse(
            "Route::put('posts/{post}', [C::class, 'update'])->middleware('auth')->scopeBindings();",
            $this->controller($body) + $this->formRequest('public function authorize(): bool { return $this->user() !== null; }'),
        );
        self::assertSame([
            'authentication/authentication',
            'route_ability/authorization',
            'query_scope/authorization',
            'controller_ability/authorization',
            'form_request/authorization',
            'abort_guard/authorization',
            'controller_ability/authorization',
        ], self::checks($out['PUT /posts/{post}']));
    }
}
