<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Candidates;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Analysis\Category;
use TusharKhan\SemanticSec\Analysis\Confidence;
use TusharKhan\SemanticSec\Analysis\Severity;
use TusharKhan\SemanticSec\Candidates\Candidate;
use TusharKhan\SemanticSec\Candidates\CandidateSelector;
use TusharKhan\SemanticSec\Candidates\Exclusion;
use TusharKhan\SemanticSec\Config\Config;
use TusharKhan\SemanticSec\Framework\DetectedFramework;
use TusharKhan\SemanticSec\Framework\Laravel\LaravelContext;
use TusharKhan\SemanticSec\Parsing\AstGenerator;
use TusharKhan\SemanticSec\Parsing\ParseResult;
use TusharKhan\SemanticSec\Parsing\SourceFile;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTableBuilder;

final class CandidateSelectorTest extends TestCase
{
    private const FILES = [
        'app/Models/User.php' => <<<'PHP'
            <?php
            namespace App\Models;

            class User extends \Illuminate\Foundation\Auth\User
            {
                public function posts(): \Illuminate\Database\Eloquent\Relations\HasMany { return $this->hasMany(Post::class); }
                public function account(): \Illuminate\Database\Eloquent\Relations\HasOne { return $this->hasOne(Account::class); }
            }
            PHP,
        'app/Models/Post.php' => "<?php namespace App\\Models; class Post extends \\Illuminate\\Database\\Eloquent\\Model { protected \$fillable = ['title', 'body']; }",
        'app/Models/Comment.php' => "<?php namespace App\\Models; class Comment extends \\Illuminate\\Database\\Eloquent\\Model { protected \$fillable = ['body']; }",
        'app/Models/Account.php' => '<?php namespace App\\Models; class Account extends \\Illuminate\\Database\\Eloquent\\Model { protected $guarded = []; }',
        'app/Models/Team.php' => "<?php namespace App\\Models; class Team extends \\Illuminate\\Database\\Eloquent\\Model { protected \$fillable = ['name', 'owner_id']; }",
        'app/Models/Order.php' => "<?php namespace App\\Models; class Order extends \\Illuminate\\Database\\Eloquent\\Model { protected \$fillable = ['total']; }",
        'app/Policies/PostPolicy.php' => <<<'PHP'
            <?php
            namespace App\Policies;

            use App\Models\Post;
            use App\Models\User;

            class PostPolicy
            {
                public function view(User $user, Post $post): bool { return $user->id === $post->user_id; }
            }
            PHP,
        'app/Contracts/Checker.php' => '<?php namespace App\Contracts; interface Checker { public function check(\App\Models\Post $post): void; }',
        'app/Services/GateChecker.php' => <<<'PHP'
            <?php
            namespace App\Services;

            use App\Models\Post;
            use Illuminate\Support\Facades\Gate;

            class GateChecker implements \App\Contracts\Checker
            {
                public function check(Post $post): void { Gate::authorize('view', $post); }
            }
            PHP,
        'app/Services/PostService.php' => <<<'PHP'
            <?php
            namespace App\Services;

            use App\Models\Post;
            use Illuminate\Support\Facades\Gate;

            class PostService
            {
                public function outer(Post $post): void { $this->inner($post); }
                public function inner(Post $post): void { Gate::authorize('view', $post); }
                public function check(Post $post): void { Gate::authorize('view', $post); }
                public function admin(): void { Gate::authorize('admin'); }
                public function scoped($id) { return Post::where('user_id', auth()->id())->findOrFail($id); }
                public function open($id) { return Post::findOrFail($id); }
                public function store(array $data) { return \App\Models\Team::create($data); }
            }
            PHP,
        'app/Http/Controllers/Controller.php' => '<?php namespace App\Http\Controllers; abstract class Controller { use \Illuminate\Foundation\Auth\Access\AuthorizesRequests; }',
        'app/Http/Controllers/C.php' => <<<'PHP'
            <?php
            namespace App\Http\Controllers;

            use App\Contracts\Checker;
            use App\Models\Account;
            use App\Models\Comment;
            use App\Models\Order;
            use App\Models\Post;
            use App\Models\Team;
            use App\Services\PostService;
            use Illuminate\Http\Request;
            use Illuminate\Support\Facades\Gate;

            class C extends Controller
            {
                public function __construct(private PostService $service, private Checker $checker) {}

                public function show(Post $post) { return $post; }
                public function showAuthorized(Post $post) { $this->authorize('view', $post); return $post; }
                public function both(Post $post, Comment $comment) { $this->authorize('view', $post); return $comment; }
                public function rawScoped(Request $request, int $id) { return $request->user()->posts()->findOrFail($id); }
                public function rawOther(Request $request, int $id) { $request->user()->posts()->get(); return Comment::findOrFail($id); }
                public function rawUnknown(Request $request, int $id) { $request->user()->posts()->get(); return $this->service->mystery($id); }
                public function rawOpen(int $id) { return Post::findOrFail($id); }
                public function admin(Post $post) { Gate::authorize('admin'); return $post; }
                public function classAbility(Post $post) { $this->authorize('viewAny', Post::class); return $post; }
                public function inputId(Request $request) { return Post::find($request->input('post_id')); }
                public function inputName(Request $request) { return Post::where('title', $request->input('title'))->get(); }
                public function calleeCheck(Post $post) { $this->service->check($post); return $post; }
                public function calleeAdmin(Post $post) { $this->service->admin(); return $post; }
                public function calleeScoped(int $id) { return $this->service->scoped($id); }
                public function calleeOpen(int $id) { return $this->service->open($id); }
                public function transitive(Post $post, bool $flag) { if ($flag) { $this->service->outer($post); } return $post; }
                public function direct(Post $post) { $this->service->outer($post); return $post; }
                public function assumed(Post $post) { $this->checker->check($post); return $post; }
                public function store(Request $request) { return Post::create($request->validated()); }
                public function storeAdmin(Request $request) { Gate::authorize('admin'); return Post::create($request->validated()); }
                public function storeOwn(Request $request) { return $request->user()->posts()->create($request->validated()); }
                public function storeOwnVar(Request $request) { $account = $request->user()->account; $account->update($request->validated()); return $account; }
                public function storeMixed(Request $request) { $request->user()->posts()->create($request->validated()); Comment::create($request->validated()); }
                public function getWrites() { Comment::create(['body' => 'x']); }
                public function nothing() { return view('home'); }
                public function massGuarded(Request $request) { $request->user()->account->update($request->all()); }
                public function massFillable(Request $request) { return Team::create($request->all()); }
                public function massSafe(Request $request) { return Post::create($request->all()); }
                public function massVariable(Request $request) { $data = $request->except('x'); return Team::create($data); }
                public function massUnknown(Request $request, $thing) { $thing->update($request->all()); }
                public function massForce(Request $request) { $post = new Post(); $post->forceFill($request->all()); }
                public function massCallee(Request $request) { return $this->service->store($request->all()); }
                public function deser(Request $request) { return unserialize($request->cookie('cart')); }
                public function deserLimited(Request $request) { return unserialize($request->cookie('cart'), ['allowed_classes' => false]); }
                public function deserConstant() { return unserialize('a:0:{}'); }
                public function refund(Order $order) { $this->authorize('view', $order); $order->update(['status' => 'refunded']); }
                public function refundGuarded(Order $order) { $this->authorize('view', $order); abort_unless($order->status === 'paid', 422); $order->update(['status' => 'refunded']); }
                public function refundOtherField(Order $order) { $this->authorize('view', $order); abort_unless($order->total > 0, 422); $order->update(['status' => 'refunded']); }
                public function refundLateGuard(Order $order) { $this->authorize('view', $order); $order->update(['status' => 'refunded']); abort_unless($order->status === 'paid', 422); }
                public function refundIfGuard(Order $order) { $this->authorize('view', $order); if ($order->state !== 'open') { abort(422); } $order->state = 'closed'; $order->save(); }
                public function cancel(Order $order) { $this->authorize('view', $order); $order->cancel(); }
            }
            PHP,
        'routes/web.php' => <<<'PHP'
            <?php
            use App\Http\Controllers\C;
            use Illuminate\Support\Facades\Route;

            Route::middleware('auth')->group(function () {
                Route::get('posts/{post}', [C::class, 'show']);
                Route::get('authorized/{post}', [C::class, 'showAuthorized']);
                Route::get('both/{post}/{comment}', [C::class, 'both']);
                Route::get('raw-scoped/{id}', [C::class, 'rawScoped']);
                Route::get('raw-other/{id}', [C::class, 'rawOther']);
                Route::get('raw-unknown/{id}', [C::class, 'rawUnknown']);
                Route::get('raw-open/{id}', [C::class, 'rawOpen']);
                Route::get('admin/{post}', [C::class, 'admin']);
                Route::get('class-ability/{post}', [C::class, 'classAbility']);
                Route::get('can-plain/{post}', [C::class, 'show'])->middleware('can:admin');
                Route::get('can-args/{post}', [C::class, 'show'])->middleware('can:view,post');
                Route::get('input-id', [C::class, 'inputId']);
                Route::get('input-name', [C::class, 'inputName']);
                Route::get('callee-check/{post}', [C::class, 'calleeCheck']);
                Route::get('callee-admin/{post}', [C::class, 'calleeAdmin']);
                Route::get('callee-scoped/{id}', [C::class, 'calleeScoped']);
                Route::get('callee-open/{id}', [C::class, 'calleeOpen']);
                Route::get('transitive/{post}', [C::class, 'transitive']);
                Route::get('direct/{post}', [C::class, 'direct']);
                Route::get('assumed/{post}', [C::class, 'assumed']);
                Route::post('store', [C::class, 'store']);
                Route::post('store-admin', [C::class, 'storeAdmin']);
                Route::post('store-own', [C::class, 'storeOwn']);
                Route::put('store-own-var', [C::class, 'storeOwnVar']);
                Route::post('store-mixed', [C::class, 'storeMixed']);
                Route::get('get-writes', [C::class, 'getWrites']);
                Route::get('nothing', [C::class, 'nothing']);
                Route::put('mass-guarded', [C::class, 'massGuarded']);
                Route::post('mass-fillable', [C::class, 'massFillable']);
                Route::post('mass-safe', [C::class, 'massSafe']);
                Route::post('mass-variable', [C::class, 'massVariable']);
                Route::post('mass-unknown', [C::class, 'massUnknown']);
                Route::post('mass-force', [C::class, 'massForce']);
                Route::post('mass-callee', [C::class, 'massCallee']);
                Route::get('deser', [C::class, 'deser']);
                Route::get('deser-limited', [C::class, 'deserLimited']);
                Route::get('deser-constant', [C::class, 'deserConstant']);
                Route::post('orders/{order}/refund', [C::class, 'refund']);
                Route::post('orders/{order}/refund-guarded', [C::class, 'refundGuarded']);
                Route::post('orders/{order}/refund-other', [C::class, 'refundOtherField']);
                Route::post('orders/{order}/refund-late', [C::class, 'refundLateGuard']);
                Route::post('orders/{order}/refund-if', [C::class, 'refundIfGuard']);
                Route::post('orders/{order}/cancel', [C::class, 'cancel']);
            });
            PHP,
        'routes/api.php' => <<<'PHP'
            <?php
            use Illuminate\Support\Facades\Route;

            Route::get('closure/{post}', function (\App\Models\Post $post) { return $post; });
            PHP,
    ];

    /** @var array<string, array{0: array<string, Candidate>, 1: list<Exclusion>}> */
    private static array $runs = [];

    public function testIdorRouteParameterWithNoAuthorizationIsACandidate(): void
    {
        self::assertSame(['idor'], self::categories('GET /posts/{post}'));
        self::assertStringContainsString('{post}', self::reason('GET /posts/{post}', Category::Idor));
    }

    public function testIdorExcludedByACheckCoveringTheParameter(): void
    {
        self::assertNull(self::candidate('GET /authorized/{post}'));
        $exclusion = self::exclusion('GET /authorized/{post}', Category::Idor);
        self::assertStringContainsString("authorize('view', \$post)", $exclusion->checkSource);
        self::assertNull(self::candidate('GET /can-args/{post}'));
    }

    public function testEveryIdentifierMustBeCovered(): void
    {
        self::assertSame(['idor'], self::categories('GET /both/{post}/{comment}'));
        self::assertStringContainsString('{comment}', self::reason('GET /both/{post}/{comment}', Category::Idor));
    }

    public function testQueryScopeOnTheLookupModelExcludes(): void
    {
        self::assertNull(self::candidate('GET /raw-scoped/{id}'));
        self::assertStringContainsString('posts()', self::exclusion('GET /raw-scoped/{id}', Category::Idor)->checkSource);
    }

    public function testQueryScopeOnAnotherModelDoesNotExclude(): void
    {
        self::assertSame(['idor'], self::categories('GET /raw-other/{id}'));
        self::assertSame(['idor'], self::categories('GET /raw-open/{id}'));
    }

    public function testQueryScopeWithAnUnknownLookupDoesNotExclude(): void
    {
        self::assertSame(['idor'], self::categories('GET /raw-unknown/{id}'));
    }

    public function testRouteWideChecksExclude(): void
    {
        self::assertNull(self::candidate('GET /admin/{post}'));
        self::assertStringContainsString("Gate::authorize('admin')", self::exclusion('GET /admin/{post}', Category::Idor)->checkSource);
        self::assertNull(self::candidate('GET /can-plain/{post}'));
    }

    public function testAnAbilityWithAModelArgumentIsNotRouteWide(): void
    {
        self::assertSame(['idor'], self::categories('GET /class-ability/{post}'));
    }

    public function testRequestInputIdentifierReachingALookup(): void
    {
        self::assertSame(['idor'], self::categories('GET /input-id'));
        self::assertStringContainsString('post_id', self::reason('GET /input-id', Category::Idor));
        // A non-id input is no identifier; the unscoped Post list makes it an idor candidate on its own (M8 list rule).
        self::assertSame('unscoped read of owned Post collection', self::reason('GET /input-name', Category::Idor));
    }

    public function testUnconditionalCalleeChecksCount(): void
    {
        self::assertNull(self::candidate('GET /callee-check/{post}'));
        self::assertNull(self::candidate('GET /callee-admin/{post}'));
        self::assertNull(self::candidate('GET /direct/{post}'));
        self::assertNull(self::candidate('GET /callee-scoped/{id}'));
        self::assertSame(['idor'], self::categories('GET /callee-open/{id}'));
    }

    public function testCheckBehindATransitivelyConditionalCallDoesNotCount(): void
    {
        self::assertSame(['idor'], self::categories('GET /transitive/{post}'));
    }

    public function testCheckInAnAssumedImplementationDoesNotCount(): void
    {
        self::assertSame(['idor'], self::categories('GET /assumed/{post}'));
    }

    public function testClosureActionsAreSelected(): void
    {
        self::assertSame(['idor'], self::categories('GET /api/closure/{post}'));
    }

    public function testMissingAuthorizationOnStateChanges(): void
    {
        self::assertSame(['missing_authorization'], self::categories('POST /store'));
        self::assertSame(['missing_authorization'], self::categories('GET /get-writes'));
        self::assertNull(self::candidate('POST /store-admin'));
        self::assertStringContainsString("Gate::authorize('admin')", self::exclusion('POST /store-admin', Category::MissingAuthorization)->checkSource);
    }

    public function testSelfScopedWritesAreExempt(): void
    {
        self::assertNull(self::candidate('POST /store-own'));
        self::assertNull(self::candidate('PUT /store-own-var'));
        self::assertStringContainsString('$account->update', self::exclusion('PUT /store-own-var', Category::MissingAuthorization)->checkSource);
        self::assertSame(['missing_authorization'], self::categories('POST /store-mixed'));
    }

    public function testNoIdentifierAndNoStateChangeIsNeverACandidate(): void
    {
        self::assertNull(self::candidate('GET /nothing'));
        self::assertNull(self::candidate('GET /nothing', true));
        $exclusion = self::exclusion('GET /nothing', null);
        self::assertSame('no identifier / no state change', $exclusion->reason);
    }

    public function testMassAssignmentTriggers(): void
    {
        self::assertContains('mass_assignment', self::categories('PUT /mass-guarded'));
        self::assertStringContainsString('Account', self::reason('PUT /mass-guarded', Category::MassAssignment));
        self::assertContains('mass_assignment', self::categories('POST /mass-fillable'));
        self::assertStringContainsString('owner_id', self::reason('POST /mass-fillable', Category::MassAssignment));
        self::assertContains('mass_assignment', self::categories('POST /mass-variable'));
        self::assertContains('mass_assignment', self::categories('POST /mass-force'));
        self::assertContains('mass_assignment', self::categories('POST /mass-callee'));
        self::assertStringContainsString('model unknown', self::reason('POST /mass-unknown', Category::MassAssignment));
    }

    public function testMassAssignmentExclusions(): void
    {
        self::assertNotContains('mass_assignment', self::categories('POST /mass-safe'));
        self::assertStringContainsString('$fillable', self::exclusion('POST /mass-safe', Category::MassAssignment)->checkSource);
        self::assertNotContains('mass_assignment', self::categories('POST /store'));
    }

    public function testInsecureDeserialization(): void
    {
        self::assertSame(['insecure_deserialization'], self::categories('GET /deser'));
        self::assertStringContainsString('allowed_classes', self::reason('GET /deser-limited', Category::InsecureDeserialization));
        self::assertNull(self::candidate('GET /deser-constant'));
    }

    public function testWorkflowBypass(): void
    {
        self::assertSame(['workflow_bypass'], self::categories('POST /orders/{order}/refund'));
        self::assertNull(self::candidate('POST /orders/{order}/refund-guarded'));
        self::assertStringContainsString('abort_unless', self::exclusion('POST /orders/{order}/refund-guarded', Category::WorkflowBypass)->checkSource);
        self::assertSame(['workflow_bypass'], self::categories('POST /orders/{order}/refund-other'));
        self::assertSame(['workflow_bypass'], self::categories('POST /orders/{order}/refund-late'));
        // The property write makes $order no longer the untouched bound model, so only idor remains.
        self::assertSame(['idor'], self::categories('POST /orders/{order}/refund-if'));
        self::assertSame(['workflow_bypass'], self::categories('POST /orders/{order}/cancel'));
    }

    public function testDeepTurnsOffAuthorizationExclusions(): void
    {
        self::assertSame(['idor'], self::categories('GET /authorized/{post}', true));
        self::assertSame(['idor'], self::categories('GET /raw-scoped/{id}', true));
        self::assertSame(['idor'], self::categories('GET /admin/{post}', true));
        self::assertSame(['missing_authorization'], self::categories('POST /store-admin', true));
        // A status guard is not an authorization check, so --deep keeps it.
        self::assertSame(['idor', 'missing_authorization'], self::categories('POST /orders/{order}/refund-guarded', true));
    }

    public function testDeepReasonsKeepTheNormalDetail(): void
    {
        $checked = 0;
        foreach (self::selectAll(false)[0] as $key => $normal) {
            $deep = self::candidate($key, true);
            self::assertNotNull($deep, $key);
            foreach ($normal->reasons as $category => $reason) {
                self::assertSame(self::deepPrefixed($category, $reason), $deep->reasons[$category] ?? null, $key.' '.$category);
                $checked++;
            }
        }
        self::assertGreaterThan(10, $checked);
    }

    public function testDeepReasonsNameTheCheckTheyIgnore(): void
    {
        self::assertStringContainsString("authorize('view', \$post)", self::reason('GET /authorized/{post}', Category::Idor, true));
        self::assertStringContainsString("Gate::authorize('admin')", self::reason('POST /store-admin', Category::MissingAuthorization, true));
        self::assertStringContainsString('$account->update', self::reason('PUT /store-own-var', Category::MissingAuthorization, true));
    }

    public function testPathsFilterSkipsActionsOutsideThePaths(): void
    {
        [$candidates, $exclusions] = self::selectAll(false, ['app/Http/Controllers/Other']);
        self::assertArrayNotHasKey('GET /posts/{post}', $candidates);
        $skipped = array_values(array_filter($exclusions, static fn (Exclusion $e): bool => $e->routeKey === 'GET /posts/{post}'));
        self::assertCount(1, $skipped);
        self::assertStringContainsString('app/Http/Controllers/Other', $skipped[0]->checkSource);
        [$candidates] = self::selectAll(false, ['app/Http/Controllers/']);
        self::assertArrayHasKey('GET /posts/{post}', $candidates);
    }

    public function testEveryExclusionHasAJustification(): void
    {
        foreach ([false, true] as $deep) {
            [, $exclusions] = self::selectAll($deep);
            self::assertNotSame([], $exclusions);
            foreach ($exclusions as $exclusion) {
                if ($exclusion->reason === CandidateSelector::NO_TRIGGER || str_starts_with($exclusion->reason, CandidateSelector::NO_TRIGGER_PREFIX)) {
                    continue;
                }
                self::assertNotSame('', trim($exclusion->checkSource), $exclusion->routeKey.' '.($exclusion->category->value ?? '*').': '.$exclusion->reason);
            }
        }
    }

    public function testCandidatesCarryTheirExecutionPath(): void
    {
        $candidate = self::candidate('GET /callee-open/{id}');
        self::assertNotNull($candidate);
        self::assertSame('App\Http\Controllers\C::calleeOpen', $candidate->path->entry()->id);
        self::assertSame([Category::Idor], $candidate->categories);
    }

    private static function candidate(string $key, bool $deep = false): ?Candidate
    {
        return self::selectAll($deep)[0][$key] ?? null;
    }

    /** @return list<string> */
    private static function categories(string $key, bool $deep = false): array
    {
        $candidate = self::candidate($key, $deep);
        self::assertNotNull($candidate, $key.' is not a candidate; exclusions: '.self::describeExclusions($key, $deep));

        return array_map(static fn (Category $c): string => $c->value, $candidate->categories);
    }

    private static function reason(string $key, Category $category, bool $deep = false): string
    {
        $candidate = self::candidate($key, $deep);
        self::assertNotNull($candidate);

        return $candidate->reasons[$category->value] ?? '';
    }

    private static function exclusion(string $key, ?Category $category): Exclusion
    {
        foreach (self::selectAll(false)[1] as $exclusion) {
            if ($exclusion->routeKey === $key && $exclusion->category === $category) {
                return $exclusion;
            }
        }
        self::fail(sprintf('no %s exclusion for %s: %s', $category->value ?? '*', $key, self::describeExclusions($key, false)));
    }

    private static function describeExclusions(string $key, bool $deep): string
    {
        $out = [];
        foreach (self::selectAll($deep)[1] as $e) {
            if ($e->routeKey === $key) {
                $out[] = ($e->category->value ?? '*').': '.$e->reason.' ['.$e->checkSource.']';
            }
        }

        return implode('; ', $out);
    }

    /**
     * @param  list<string>  $paths
     * @return array{0: array<string, Candidate>, 1: list<Exclusion>}
     */
    private static function selectAll(bool $deep, array $paths = []): array
    {
        $cacheKey = ($deep ? 'deep' : 'normal').implode(',', $paths);
        if (isset(self::$runs[$cacheKey])) {
            return self::$runs[$cacheKey];
        }
        $files = [];
        foreach (self::FILES as $path => $code) {
            $files[] = (new AstGenerator())->parse(new SourceFile($path, '/nonexistent/'.$path, $code));
        }
        $parsed = new ParseResult($files, []);
        $symbols = (new SymbolTableBuilder())->build($parsed);
        $config = new Config('/nonexistent', 'anthropic', null, null, null, 5, null, 8000, 3, Severity::High, Confidence::Medium, $paths, [], [], Config::DEFAULT_SENSITIVE_FIELDS, [], []);
        $framework = new DetectedFramework('laravel', 11);
        $context = new LaravelContext();
        $map = $context->buildAuthorizationMap($parsed, $symbols, $config, $framework);
        $selector = $context->candidateSelector($parsed, $symbols, $config, $framework);
        [$candidates] = $selector->select($map, $deep);
        $byKey = [];
        foreach ($candidates as $candidate) {
            foreach ($candidate->route->keys() as $key) {
                $byKey[$key] = $candidate;
            }
        }

        return self::$runs[$cacheKey] = [$byKey, $selector->exclusions()];
    }

    // --deep relabels only the categories it stops excluding; the normal detail follows the prefix.
    private static function deepPrefixed(string $category, string $reason): string
    {
        return in_array($category, [Category::Idor->value, Category::MissingAuthorization->value], true) ? '--deep: '.$reason : $reason;
    }
}
