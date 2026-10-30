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
        foreach (['a', 'b', 'd'] as $m) {
            self::assertSame(['query_scope/authorization'], self::checks($out['GET /'.$m]), $m);
        }
        self::assertSame([], self::checks($out['GET /c']));
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
            "Route::get('users/{user}/posts/{post}', [C::class, 'a'])->scopeBindings();\n"
            ."Route::get('owners/{user}/posts/{post}', [C::class, 'a'])->scopeBindings()->can('view', 'user');\n"
            ."Route::get('posts/{post}', [C::class, 'b'])->scopeBindings();",
            $this->controller('public function a(User $user, Post $post) {} public function b(Post $post) {}'),
        );
        self::assertSame(['query_scope/none'], self::checks($out['GET /users/{user}/posts/{post}']));
        self::assertSame(['scoped to URL parent {user}'], self::sources($out['GET /users/{user}/posts/{post}']));
        self::assertSame(['route_ability/authorization', 'query_scope/authorization'], self::checks($out['GET /owners/{user}/posts/{post}']));
        self::assertSame([], self::checks($out['GET /posts/{post}']));
    }

    public function testImplicitChildBindingIsScoped(): void
    {
        $body = <<<'PHP'
                public function a(User $user, Post $post) {}
                public function b(Post $post) {}
                public function c(int $id, Post $post) {}
                public function d(User $user, Post $post) { $this->authorize('view', $user); }
                public function e(User $user, Post $post) { $this->authorize('view', [$user]); }
                public function f(User $user, Post $post) { $this->authorize('view', $post); }
            PHP;
        [$out] = $this->analyse(
            "Route::get('users/{user}/posts/{post:slug}', [C::class, 'a']);\n"
            ."Route::get('posts/{post:slug}', [C::class, 'b']);\n"
            ."Route::get('ids/{id}/posts/{post:slug}', [C::class, 'c']);\n"
            ."Route::get('free/{user}/posts/{post:slug}', [C::class, 'a'])->withoutScopedBindings();\n"
            ."Route::get('can/{user}/posts/{post:slug}', [C::class, 'a'])->middleware('can:view,user');\n"
            ."Route::get('d/{user}/posts/{post:slug}', [C::class, 'd']);\n"
            ."Route::get('e/{user}/posts/{post:slug}', [C::class, 'e']);\n"
            ."Route::get('f/{user}/posts/{post:slug}', [C::class, 'f']);",
            $this->controller($body),
        );
        self::assertSame(['query_scope/none'], self::checks($out['GET /users/{user}/posts/{post:slug}']));
        self::assertSame(['scoped to URL parent {user}'], self::sources($out['GET /users/{user}/posts/{post:slug}']));
        self::assertSame([], self::checks($out['GET /posts/{post:slug}']));
        self::assertSame([], self::checks($out['GET /ids/{id}/posts/{post:slug}']));
        self::assertSame([], self::checks($out['GET /free/{user}/posts/{post:slug}']));
        self::assertSame(['route_ability/authorization', 'query_scope/authorization'], self::checks($out['GET /can/{user}/posts/{post:slug}']));
        self::assertSame('implicit scoped binding {post:slug}', self::sources($out['GET /can/{user}/posts/{post:slug}'])[1]);
        self::assertSame(['query_scope/authorization', 'controller_ability/authorization'], self::checks($out['GET /d/{user}/posts/{post:slug}']));
        self::assertSame(['query_scope/authorization', 'controller_ability/authorization'], self::checks($out['GET /e/{user}/posts/{post:slug}']));
        // Authorizing the child says nothing about the URL parent.
        self::assertSame(['query_scope/none', 'controller_ability/authorization'], self::checks($out['GET /f/{user}/posts/{post:slug}']));
    }

    public function testChecksComeOutInStableOrder(): void
    {
        $body = <<<'PHP'
                public function __construct()
                {
                    $this->middleware('can:view,user');
                    $this->authorizeResource(Post::class, 'post');
                }
                public function update(SaveRequest $request, User $user, Post $post)
                {
                    abort_if($post->user_id !== auth()->id(), 403);
                    $this->authorize('update', $post);
                }
            PHP;
        [$out] = $this->analyse(
            "Route::put('users/{user}/posts/{post}', [C::class, 'update'])->middleware('auth')->scopeBindings();",
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
        ], self::checks($out['PUT /users/{user}/posts/{post}']));
    }

    public function testQueriedModelStopsAtRelationHop(): void
    {
        $body = <<<'PHP'
                public function a(int $id) { $c = Post::findOrFail($id)->comments()->firstOrFail(); $this->authorize('delete', $c); }
                public function b(int $id) { $c = Post::where('id', $id)->first()->comments()->first(); $this->authorize('delete', $c); }
                public function c(int $id) { $c = Post::query()->where('id', $id)->first(); $this->authorize('delete', $c); }
            PHP;
        [$out] = $this->analyse("Route::delete('a', [C::class, 'a']);\nRoute::delete('b', [C::class, 'b']);\nRoute::delete('c', [C::class, 'c']);", $this->controller($body));
        self::assertSame(['controller_ability/authorization'], self::checks($out['DELETE /a']));
        self::assertSame(['controller_ability/authorization'], self::checks($out['DELETE /b']));
        self::assertSame(['controller_ability/none'], self::checks($out['DELETE /c']));
    }

    public function testBindingNamesMatchLaravelSnakeCase(): void
    {
        $files = $this->controller('public function a(BlogPost $blogPost) {} public function b(\App\Models\BlogPost $blogPost) { $this->authorize(\'update\', $blogPost); }')
            + [
                'app/Models/BlogPost.php' => '<?php namespace App\Models; class BlogPost extends \Illuminate\Database\Eloquent\Model {}',
                'app/Policies/BlogPostPolicy.php' => '<?php namespace App\Policies; class BlogPostPolicy { public function update($u, $p) { return true; } }',
            ];
        $files['app/Http/Controllers/C.php'] = str_replace('use App\Models\User;', "use App\\Models\\User;\nuse App\\Models\\BlogPost;", $files['app/Http/Controllers/C.php']);
        [$out] = $this->analyse(
            "Route::put('posts/{blog_post}', [C::class, 'a'])->middleware('can:update,blog_post');\n"
            ."Route::patch('posts/{blog_post}', [C::class, 'a'])->middleware('can:update,blogPost');\n"
            ."Route::post('posts/{blog_post}', [C::class, 'b']);",
            $files,
        );
        self::assertSame('App\Models\BlogPost', $out['PUT /posts/{blog_post}']->parameters[0]->boundModel);
        self::assertSame(['route_ability/none'], self::checks($out['PUT /posts/{blog_post}']));
        self::assertSame(['route_ability/none'], self::checks($out['PATCH /posts/{blog_post}']));
        self::assertSame(['controller_ability/none'], self::checks($out['POST /posts/{blog_post}']));
    }

    public function testDiscardedNonThrowingAbilityCallsGiveNothing(): void
    {
        $body = <<<'PHP'
                public function a(Post $post) { Gate::allows('update', $post); }
                public function b(Request $request, Post $post) { $request->user()->can('update', $post); }
                public function c(Post $post) { Gate::inspect('update', $post); }
                public function d(Post $post) { Gate::authorize('update', $post); }
                public function e(Post $post) { $this->authorize('update', $post); }
                public function f(Post $post) { $ok = Gate::check('update', $post); return $ok; }
            PHP;
        $routes = '';
        foreach (['a', 'b', 'c', 'd', 'e', 'f'] as $m) {
            $routes .= "Route::put('{$m}/{post}', [C::class, '{$m}']);\n";
        }
        [$out] = $this->analyse($routes, $this->controller($body));
        foreach (['a', 'b', 'c'] as $m) {
            self::assertSame([], self::checks($out['PUT /'.$m.'/{post}']), $m);
        }
        foreach (['d', 'e', 'f'] as $m) {
            self::assertSame(['controller_ability/authorization'], self::checks($out['PUT /'.$m.'/{post}']), $m);
        }
    }

    public function testWhereScopeNeedsEquality(): void
    {
        $body = <<<'PHP'
                public function a() { return Post::where('user_id', '!=', auth()->id())->get(); }
                public function b() { return Post::where('user_id', '<>', Auth::id())->get(); }
                public function c() { return Post::where('user_id', '=', auth()->id())->get(); }
                public function d() { return Post::orWhere('user_id', auth()->id())->get(); }
            PHP;
        [$out] = $this->analyse("Route::get('a', [C::class, 'a']);\nRoute::get('b', [C::class, 'b']);\nRoute::get('c', [C::class, 'c']);\nRoute::get('d', [C::class, 'd']);", $this->controller($body));
        self::assertSame([], self::checks($out['GET /a']));
        self::assertSame([], self::checks($out['GET /b']));
        self::assertSame(['query_scope/authorization'], self::checks($out['GET /c']));
        self::assertSame([], self::checks($out['GET /d']));
    }

    public function testRelationChainStopsAtQueryReset(): void
    {
        $body = <<<'PHP'
                public function a(Request $r, int $id) { return $r->user()->posts()->newQuery()->find($id); }
                public function b(Request $r, int $id) { return $r->user()->posts()->getModel()->find($id); }
                public function c(Request $r, int $id) { return $r->user()->newModelQuery()->find($id); }
                public function d(Request $r, int $id) { return $r->user()->posts()->with('tags')->findOrFail($id); }
                public function e(Request $r, int $id) { return $r->user()->posts()->without('tags')->find($id); }
                public function f(Request $r, int $id) { return $r->user()->replicate()->posts()->find($id); }
                public function g(Request $r, int $id) { return $r->user()->posts()->query()->find($id); }
            PHP;
        $routes = '';
        foreach (['a', 'b', 'c', 'd', 'e', 'f', 'g'] as $m) {
            $routes .= "Route::get('{$m}', [C::class, '{$m}']);\n";
        }
        [$out] = $this->analyse($routes, $this->controller($body));
        foreach (['a', 'b', 'c', 'f', 'g'] as $m) {
            self::assertSame([], self::checks($out['GET /'.$m]), $m);
        }
        // Eager loading keeps the relation's constraints.
        self::assertSame(['query_scope/authorization'], self::checks($out['GET /d']));
        self::assertSame(['query_scope/authorization'], self::checks($out['GET /e']));
    }

    public function testAbortGuardNeedsComparisonWithAuth(): void
    {
        $body = <<<'PHP'
                public function a(Request $request) { abort_unless($request->user(), 401); }
                public function b(Request $request) { abort_unless($request->user()->isAdmin(), 403); }
                public function c(Post $post) { abort_if($post->user_id != auth()->id(), 403); }
                public function d(Request $request, Post $post) { abort_unless($request->user() == $post->owner, 403); }
                public function e(Request $request, Post $post) { abort_if($post->user_id !== $post->editor_id && $request->user(), 403); }
            PHP;
        $routes = '';
        foreach (['a', 'b', 'c', 'd', 'e'] as $m) {
            $routes .= "Route::get('{$m}/{post}', [C::class, '{$m}']);\n";
        }
        [$out] = $this->analyse($routes, $this->controller($body));
        self::assertSame([], self::checks($out['GET /a/{post}']));
        self::assertSame([], self::checks($out['GET /b/{post}']));
        self::assertSame(['abort_guard/authorization'], self::checks($out['GET /c/{post}']));
        self::assertSame(['abort_guard/authorization'], self::checks($out['GET /d/{post}']));
        self::assertSame([], self::checks($out['GET /e/{post}']));
    }

    public function testClosureFormRequestIsChecked(): void
    {
        [$out] = $this->analyse(
            "Route::put('x', function (\\App\\Http\\Requests\\SaveRequest \$request) { return 1; });",
            $this->formRequest('public function authorize(): bool { return true; }'),
        );
        self::assertSame(['form_request/none'], self::checks($out['PUT /x']));
        self::assertSame('routes/web.php', $out['PUT /x']->checks[0]->file);
    }

    public function testUnresolvableAuthorizeResourceOptionsWarn(): void
    {
        $body = <<<'PHP'
                public function __construct()
                {
                    $this->authorizeResource(Post::class, 'post', ['except' => $this->skipped]);
                }
                public function show(Post $post) {}
            PHP;
        [$out, $warnings] = $this->analyse("Route::get('posts/{post}', [C::class, 'show']);", $this->controller($body));
        self::assertSame([], self::checks($out['GET /posts/{post}']));
        self::assertSame(['app/Http/Controllers/C.php:15: authorizeResource options could not be resolved'], $warnings);
    }
}
