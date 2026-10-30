<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Candidates;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Analysis\Category;
use TusharKhan\SemanticSec\Analysis\Confidence;
use TusharKhan\SemanticSec\Analysis\Severity;
use TusharKhan\SemanticSec\Candidates\Candidate;
use TusharKhan\SemanticSec\Candidates\Exclusion;
use TusharKhan\SemanticSec\Config\Config;
use TusharKhan\SemanticSec\Framework\DetectedFramework;
use TusharKhan\SemanticSec\Framework\Laravel\LaravelContext;
use TusharKhan\SemanticSec\Parsing\AstGenerator;
use TusharKhan\SemanticSec\Parsing\ParseResult;
use TusharKhan\SemanticSec\Parsing\SourceFile;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTableBuilder;

/** Review round 1: probes that were wrongly excluded, plus the scoped shapes that must stay excluded. */
final class CandidateSelectorRegressionTest extends TestCase
{
    /** @var array{0: array<string, Candidate>, 1: list<Exclusion>}|null */
    private static ?array $result = null;

    /** @return array<string, array{string, string}> */
    public static function wronglyExcluded(): array
    {
        return [
            'unrelated scope, bound' => ['GET /c1get/{invoice}', 'idor'],
            'unrelated scoped count, bound' => ['GET /c1where/{invoice}', 'idor'],
            'unrelated scope, raw id' => ['GET /c1raw/{id}', 'idor'],
            'input through two variables' => ['GET /input-two-vars', 'idor'],
            'input in a where array' => ['GET /input-array', 'idor'],
            'input as property' => ['GET /input-prop', 'idor'],
            'input as array offset' => ['GET /input-bracket', 'idor'],
            'query scope is not authorization for writes' => ['POST /c2', 'missing_authorization'],
            'unresolved call voids self-scope' => ['POST /c3', 'missing_authorization'],
            'app helper voids self-scope' => ['POST /helper-voids', 'missing_authorization'],
            'find on the user is not a relation' => ['POST /self-find', 'missing_authorization'],
            'where on the user is not a relation' => ['POST /self-where', 'missing_authorization'],
            'merge with all()' => ['POST /mass-merge', 'mass_assignment'],
            'toArray()' => ['POST /mass-toarray', 'mass_assignment'],
            'all() inside Arr::except' => ['POST /mass-arr', 'mass_assignment'],
            'compound assignment of all()' => ['POST /mass-compound', 'mass_assignment'],
            'guard on another receiver (update)' => ['POST /wf/{order}/{invoice}', 'workflow_bypass'],
            'guard on another receiver (assign)' => ['POST /wfa/{order}/{invoice}', 'workflow_bypass'],
            'unserialize as a callable' => ['GET /deser-callable', 'insecure_deserialization'],
            'named arguments' => ['GET /named/{post}', 'idor'],
        ];
    }

    #[DataProvider('wronglyExcluded')]
    public function testWronglyExcludedProbeIsSelected(string $key, string $category): void
    {
        $candidate = self::probes()[0][$key] ?? null;
        $exclusions = implode('; ', array_map(static fn (Exclusion $e): string => ($e->category->value ?? '*').': '.$e->reason.' ['.$e->checkSource.']', array_filter(self::probes()[1], static fn (Exclusion $e): bool => $e->routeKey === $key)));
        self::assertNotNull($candidate, $key.' not selected: '.$exclusions);
        self::assertContains($category, array_map(static fn (Category $c): string => $c->value, $candidate->categories), $key.': '.$exclusions);
    }

    public function testScopedLookupOfABoundParameterStillExcludes(): void
    {
        self::assertArrayNotHasKey('GET /bound-scoped/{invoice}', self::probes()[0]);
    }

    public function testScopedLookupAndWriteStillExclude(): void
    {
        self::assertArrayNotHasKey('POST /scoped-write/{id}', self::probes()[0]);
        $reasons = [];
        foreach (self::probes()[1] as $e) {
            if ($e->routeKey === 'POST /scoped-write/{id}') {
                $reasons[$e->category->value ?? '*'] = $e->checkSource;
            }
        }
        self::assertStringContainsString("where('user_id', auth()->id())", $reasons['idor'] ?? '');
        self::assertStringContainsString('$d->update', $reasons['missing_authorization'] ?? '');
    }

    public function testCategoriesWithNoTriggerAreRecorded(): void
    {
        $found = array_filter(self::probes()[1], static fn (Exclusion $e): bool => $e->routeKey === 'POST /mass-plain' && $e->category === Category::Idor);
        self::assertCount(1, $found);
        self::assertStringStartsWith('no trigger', array_values($found)[0]->reason);
    }

    /** @return array{0: array<string, Candidate>, 1: list<Exclusion>} */
    private static function probes(): array
    {
        if (self::$result !== null) {
            return self::$result;
        }
        $m = static fn (string $n, string $body = ''): string => "<?php namespace App\\Models; class $n extends \\Illuminate\\Database\\Eloquent\\Model { $body }";
        $sources = [
            'app/Models/User.php' => <<<'PHP'
            <?php
            namespace App\Models;
            class User extends \Illuminate\Foundation\Auth\User
            {
                public function posts(): \Illuminate\Database\Eloquent\Relations\HasMany { return $this->hasMany(Post::class); }
                public function invoices(): \Illuminate\Database\Eloquent\Relations\HasMany { return $this->hasMany(Invoice::class); }
            }
            PHP,
            'app/Models/Post.php' => $m('Post', "protected \$fillable = ['title'];"),
            'app/Models/Invoice.php' => $m('Invoice', "protected \$fillable = ['total'];"),
            'app/Models/Order.php' => $m('Order', "protected \$fillable = ['total'];"),
            'app/Models/Setting.php' => $m('Setting', "protected \$fillable = ['value'];"),
            'app/Models/Team.php' => $m('Team', "protected \$fillable = ['name', 'owner_id'];"),
            'app/Policies/PostPolicy.php' => '<?php namespace App\Policies; use App\Models\{Post,User}; class PostPolicy { public function view(User $u, Post $p): bool { return $u->id === $p->user_id; } }',
            'app/Policies/InvoicePolicy.php' => '<?php namespace App\Policies; use App\Models\{Invoice,User}; class InvoicePolicy { public function view(User $u, Invoice $p): bool { return $u->id === $p->user_id; } }',
            'app/Contracts/Checker.php' => '<?php namespace App\Contracts; interface Checker { public function check(\App\Models\Post $post): void; }',
            'app/Services/Svc.php' => <<<'PHP'
            <?php
            namespace App\Services;
            use App\Models\Post;
            use Illuminate\Support\Facades\Gate;
            class Svc
            {
                public function __construct(private \App\Contracts\Checker $checker) {}
                public function two(Post $a, Post $b): void { Gate::authorize('view', $a); }
                public function admin(): void { Gate::authorize('admin'); }
                public function adminUnlessLocal(): void { if (app()->isLocal()) { return; } Gate::authorize('admin'); }
                public function viaChecker(Post $p): void { $this->checker->check($p); }
                public function decode($v) { return unserialize($v); }
                public function boolCheck(Post $p) { if (Gate::denies('view', $p)) { return false; } return true; }
            }
            PHP,
            'app/Http/Controllers/Controller.php' => '<?php namespace App\Http\Controllers; abstract class Controller { use \Illuminate\Foundation\Auth\Access\AuthorizesRequests; }',
            'app/Http/Controllers/P.php' => <<<'PHP'
            <?php
            namespace App\Http\Controllers;
            use App\Models\{Invoice,Order,Post,Setting,Team,User};
            use App\Services\Svc;
            use Illuminate\Http\Request;
            use Illuminate\Support\Arr;
            use Illuminate\Support\Facades\Gate;
            class P extends Controller
            {
                public function __construct(private Svc $svc, private $mystery) {}
                // concern 1
                public function c1get(Invoice $invoice) { auth()->user()->invoices()->get(); return $invoice; }
                public function c1where(Invoice $invoice) { $n = auth()->user()->invoices()->where('paid', 1)->count(); return [$invoice, $n]; }
                public function c1raw(Request $r, $id) { $r->user()->invoices()->get(); return Invoice::findOrFail($id); }
                // identifier through variable / function
                public function viaVar(Request $r, $id) { $r->user()->invoices()->get(); $x = $id; return Invoice::findOrFail($x); }
                public function inputTwoVars(Request $r) { $x = $r->input('invoice_id'); $y = $x; return Invoice::find($y); }
                public function inputArray(Request $r) { return Invoice::where(['id' => $r->input('invoice_id')])->first(); }
                public function inputProp(Request $r) { return Invoice::find($r->invoice_id); }
                public function inputBracket(Request $r) { return Invoice::find($r['invoice_id']); }
                // several identifiers / covers from another param
                public function twoParams(Post $post, Post $other) { $this->authorize('view', $post); return $other; }
                public function namedArgs(Post $post) { $this->svc->two(b: $post, a: Post::first()); return $post; }
                // route-wide but conditional
                public function earlyReturnCaller(Request $r, Post $post) { if ($r->boolean('skip')) { return $post; } $this->svc->admin(); return $post; }
                public function calleeEarlyReturn(Post $post) { $this->svc->adminUnlessLocal(); return $post; }
                public function tryCatch(Post $post) { try { $this->svc->admin(); } catch (\Throwable $e) {} return $post; }
                public function boolIgnored(Post $post) { $this->svc->boolCheck($post); return $post; }
                // assumed
                public function assumedDeep(Post $post) { $this->svc->viaChecker($post); return $post; }
                // concern 2
                public function c2(Request $r) { $r->user()->posts()->get(); Setting::first()->update($r->validated()); }
                // concern 3
                public function c3(Request $r) { $r->user()->posts()->create($r->validated()); $this->mystery->purge(); }
                public function selfFind(Request $r) { $r->user()->find($r->input('target'))->delete(); }
                public function selfWhere(Request $r) { $r->user()->where('email', $r->input('email'))->update(['name' => 'x']); }
                // mass
                public function massMerge(Request $r) { $this->authorize('create', Team::class); $data = $r->validated(); $data = array_merge($data, $r->all()); return Team::create($data); }
                public function massToArray(Request $r) { $this->authorize('create', Team::class); return Team::create($r->toArray()); }
                public function massArr(Request $r) { $this->authorize('create', Team::class); return Team::create(Arr::except($r->all(), ['x'])); }
                // workflow
                public function wfOther(Order $order, Invoice $invoice) { $this->authorize('view', $order); $this->authorize('view', $invoice); abort_unless($invoice->status === 'paid', 422); $order->update(['status' => 'refunded']); }
                public function massPlain(Request $r) { $this->authorize("create", Team::class); return Team::create($r->all()); }
                public function massCompound(Request $r) { $this->authorize("create", Team::class); $d = $r->validated(); $d += $r->all(); return Team::create($d); }
                public function wfAssign(Order $order, Invoice $invoice) { $this->authorize("view", $order); $this->authorize("view", $invoice); abort_if($invoice->status !== "paid", 422); $order->status = "shipped"; $order->save(); }
                // deser
                public function deserCallee(Request $r) { return $this->svc->decode($r->cookie('x')); }
                public function deserCallable(Request $r) { return array_map('unserialize', $r->input('items', [])); }
                // still excluded
                public function boundScoped(Request $r, Invoice $invoice) { return $r->user()->invoices()->findOrFail($invoice->id); }
                public function scopedWrite(Request $r, $id) { $d = Invoice::where('id', $id)->where('user_id', auth()->id())->first(); $d->update(['total' => 1]); }
                public function helperVoids(Request $r) { $r->user()->posts()->create($r->validated()); audit_log('x'); }
            }
            PHP,
            'routes/web.php' => <<<'PHP'
            <?php
            use App\Http\Controllers\P;
            use Illuminate\Support\Facades\Route;
            Route::middleware('auth')->group(function () {
                Route::get('c1get/{invoice}', [P::class, 'c1get']);
                Route::get('c1where/{invoice}', [P::class, 'c1where']);
                Route::get('c1raw/{id}', [P::class, 'c1raw']);
                Route::get('via-var/{id}', [P::class, 'viaVar']);
                Route::get('input-two-vars', [P::class, 'inputTwoVars']);
                Route::get('input-array', [P::class, 'inputArray']);
                Route::get('input-prop', [P::class, 'inputProp']);
                Route::get('input-bracket', [P::class, 'inputBracket']);
                Route::get('two/{post}/{other}', [P::class, 'twoParams']);
                Route::get('named/{post}', [P::class, 'namedArgs']);
                Route::get('early/{post}', [P::class, 'earlyReturnCaller']);
                Route::get('callee-early/{post}', [P::class, 'calleeEarlyReturn']);
                Route::get('try/{post}', [P::class, 'tryCatch']);
                Route::get('bool/{post}', [P::class, 'boolIgnored']);
                Route::get('assumed-deep/{post}', [P::class, 'assumedDeep']);
                Route::post('c2', [P::class, 'c2']);
                Route::post('c3', [P::class, 'c3']);
                Route::post('self-find', [P::class, 'selfFind']);
                Route::post('self-where', [P::class, 'selfWhere']);
                Route::post('mass-merge', [P::class, 'massMerge']);
                Route::post('mass-toarray', [P::class, 'massToArray']);
                Route::post('mass-arr', [P::class, 'massArr']);
                Route::post('wf/{order}/{invoice}', [P::class, 'wfOther']);
                Route::post("mass-plain", [P::class, "massPlain"]);
                Route::post("mass-compound", [P::class, "massCompound"]);
                Route::post("wfa/{order}/{invoice}", [P::class, "wfAssign"]);
                Route::get('deser-callee', [P::class, 'deserCallee']);
                Route::get('deser-callable', [P::class, 'deserCallable']);
                Route::get('bound-scoped/{invoice}', [P::class, 'boundScoped']);
                Route::post('scoped-write/{id}', [P::class, 'scopedWrite']);
                Route::post('helper-voids', [P::class, 'helperVoids']);
            });
            PHP,
        ];
        $files = [];
        foreach ($sources as $path => $code) {
            $files[] = (new AstGenerator())->parse(new SourceFile($path, '/nonexistent/'.$path, $code));
        }
        $parsed = new ParseResult($files, []);
        $symbols = (new SymbolTableBuilder())->build($parsed);
        $config = new Config('/nonexistent', 'anthropic', null, null, null, 5, null, 8000, 3, Severity::High, Confidence::Medium, [], [], [], Config::DEFAULT_SENSITIVE_FIELDS, [], []);
        $framework = new DetectedFramework('laravel', 11);
        $context = new LaravelContext();
        $selector = $context->candidateSelector($parsed, $symbols, $config, $framework);
        [$candidates] = $selector->select($context->buildAuthorizationMap($parsed, $symbols, $config, $framework), false);
        $byKey = [];
        foreach ($candidates as $candidate) {
            foreach ($candidate->route->keys() as $key) {
                $byKey[$key] = $candidate;
            }
        }

        return self::$result = [$byKey, $selector->exclusions()];
    }
}
