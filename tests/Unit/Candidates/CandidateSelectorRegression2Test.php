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

/** Review round 2: scope escapes, exemption width, loose id flow, workflow guard soundness, more mass reads. */
final class CandidateSelectorRegression2Test extends TestCase
{
    /** @var array{0: array<string, Candidate>, 1: list<Exclusion>}|null */
    private static ?array $probes = null;

    /** @return array<string, array{string, string}> */
    public static function wronglyExcluded(): array
    {
        return [
            'id copied into an array' => ['GET /n2/{id}', 'idor'],
            'id in arithmetic' => ['GET /n3/{id}', 'idor'],
            'id in a string' => ['GET /n3b/{id}', 'idor'],
            'lookup after first() on a relation' => ['GET /n4/{id}', 'idor'],
            'lookup after first() on a scoped query' => ['GET /n4b/{id}', 'idor'],
            'non-throwing scoped find of a bound model' => ['GET /n5/{invoice}', 'idor'],
            'id inside compact()' => ['GET /n16', 'idor'],
            'multi-hop relation write' => ['POST /n7', 'missing_authorization'],
            'relation, first, relation write' => ['POST /n7b', 'missing_authorization'],
            'find after first() on a relation' => ['POST /n8', 'missing_authorization'],
            'find after first() on a scoped query' => ['POST /w1', 'missing_authorization'],
            'app() root voids self-scope' => ['POST /n9', 'missing_authorization'],
            'optional() root voids self-scope' => ['POST /n9b', 'missing_authorization'],
            'call_user_func voids self-scope' => ['POST /n9c', 'missing_authorization'],
            'resolve() root voids self-scope' => ['POST /n9d', 'missing_authorization'],
            'tap() root voids self-scope' => ['POST /n9f', 'missing_authorization'],
            'vendor-typed receiver voids self-scope' => ['POST /n9g', 'missing_authorization'],
            'unknown method on the user voids self-scope' => ['POST /n9h', 'missing_authorization'],
            'receiver reassigned after the guard' => ['POST /n10/{order}', 'workflow_bypass'],
            'guard defeated by || true' => ['POST /n10b/{order}', 'workflow_bypass'],
            'getContent()' => ['POST /n12', 'mass_assignment'],
            'query() with no keys' => ['POST /n12b', 'mass_assignment'],
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

    public function testThrowingScopedLookupOfABoundModelStillExcludes(): void
    {
        $candidate = self::probes()[0]['POST /n6/{invoice}'] ?? null;
        self::assertNotNull($candidate);
        self::assertNotContains(Category::Idor, $candidate->categories);
    }

    /** @return array{0: array<string, Candidate>, 1: list<Exclusion>} */
    private static function probes(): array
    {
        if (self::$probes !== null) {
            return self::$probes;
        }
        $m = static fn (string $n, string $body = ''): string => "<?php namespace App\\Models; class $n extends \\Illuminate\\Database\\Eloquent\\Model { $body }";
        $sources = [
            'app/Models/User.php' => <<<'PHP'
            <?php
            namespace App\Models;
            class User extends \Illuminate\Foundation\Auth\User
            {
                protected $fillable = ['name'];
                public function posts(): \Illuminate\Database\Eloquent\Relations\HasMany { return $this->hasMany(Post::class); }
                public function invoices(): \Illuminate\Database\Eloquent\Relations\HasMany { return $this->hasMany(Invoice::class); }
                public function team(): \Illuminate\Database\Eloquent\Relations\BelongsTo { return $this->belongsTo(Team::class); }
            }
            PHP,
            'app/Models/Post.php' => $m('Post', "protected \$fillable = ['title'];"),
            'app/Models/Invoice.php' => $m('Invoice', "protected \$fillable = ['total'];"),
            'app/Models/Order.php' => $m('Order', "protected \$fillable = ['total'];"),
            'app/Models/Team.php' => $m('Team', "protected \$fillable = ['name', 'owner_id']; public function members(): \\Illuminate\\Database\\Eloquent\\Relations\\HasMany { return \$this->hasMany(User::class); }"),
            'app/Policies/OrderPolicy.php' => '<?php namespace App\Policies; use App\Models\{Order,User}; class OrderPolicy { public function view(User $u, Order $p): bool { return $u->id === $p->user_id; } }',
            'app/Services/Svc.php' => <<<'PHP'
            <?php
            namespace App\Services;
            use App\Models\{Order,Invoice};
            class Svc
            {
                public function ensurePaid(Order $o): void { abort_unless($o->status === 'paid', 422); }
                public function refund(Invoice $order): void { $order->update(['status' => 'refunded']); }
            }
            PHP,
            'app/Http/Controllers/Controller.php' => '<?php namespace App\Http\Controllers; abstract class Controller { use \Illuminate\Foundation\Auth\Access\AuthorizesRequests; }',
            'app/Http/Controllers/Q.php' => <<<'PHP'
            <?php
            namespace App\Http\Controllers;
            use App\Models\{Invoice,Order,Post,Team,User};
            use App\Services\Svc;
            use Illuminate\Http\Request;
            class Q extends Controller
            {
                public function __construct(private Svc $svc, private $mystery) {}
                public function n1(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); return Invoice::find($id); }
                public function n2(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $ids = [$id]; Invoice::whereIn('id', $ids)->get(); }
                public function n3(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $k = $id + 0; return Invoice::find($k); }
                public function n3b(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $k = "{$id}"; return Invoice::find($k); }
                public function n4(Request $r, $id) { return auth()->user()->invoices()->first()->find($id); }
                public function n4b(Request $r, $id) { return Invoice::where('user_id', auth()->id())->first()->find($id); }
                public function n5(Invoice $invoice) { auth()->user()->invoices()->find($invoice->id); return $invoice; }
                public function n6(Request $r, Invoice $invoice) { auth()->user()->invoices()->findOrFail($invoice->id); $invoice->delete(); }
                public function n6b(Invoice $invoice) { $k = $invoice->getKey(); auth()->user()->invoices()->findOrFail($k); return $invoice; }
                public function n15(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); return collect([1])->map(fn () => Invoice::find($id)); }
                public function n15b(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); return collect([1])->map(function () use ($id) { return Invoice::find($id); }); }
                public function n16(Request $r) { $id = $r->input('invoice_id'); auth()->user()->invoices()->findOrFail($id); return Invoice::where(compact('id'))->first(); }
                public function n16b(Request $r) { auth()->user()->invoices()->findOrFail($r->invoice_id); return Invoice::find($r->input('invoice_id')); }
                // missing_authorization self-scope
                public function n7(Request $r) { $r->user()->team->members()->first()->update(['name' => 'x']); }
                public function n7b(Request $r) { $r->user()->team()->first()->members()->first()->delete(); }
                public function n8(Request $r) { $r->user()->posts()->first()->find($r->input('target'))->delete(); }
                public function n9(Request $r) { $r->user()->posts()->create($r->validated()); app('purger')->purge(); }
                public function n9b(Request $r) { $r->user()->posts()->create($r->validated()); optional($this->mystery)->purge(); }
                public function n9c(Request $r) { $r->user()->posts()->create($r->validated()); call_user_func([$this->mystery, 'purge']); }
                public function n9d(Request $r) { $r->user()->posts()->create($r->validated()); resolve('purger')->purge(); }
                public function n9e(Request $r) { $r->user()->posts()->create($r->validated()); event('purge'); }
                public function n9f(Request $r) { $r->user()->posts()->create($r->validated()); tap($this->mystery)->purge(); }
                public function n9g(Request $r, \Illuminate\Contracts\Bus\Dispatcher $bus) { $r->user()->posts()->create($r->validated()); $bus->dispatch(new \App\Jobs\Purge()); }
                public function n9h(Request $r) { $u = $r->user(); $u->posts()->create($r->validated()); $u->purgeOthers(); }
                public function w1(Request $r) { Invoice::where('user_id', auth()->id())->first()->find($r->input('target'))->delete(); }
                public function w2(Request $r) { $i = Invoice::where('user_id', auth()->id())->firstOrFail(); $i->replicate()->save(); Order::where('user_id', auth()->id())->first()->user->update(['name' => 'x']); }
                // workflow
                public function n10(Request $r, Order $order) { $this->authorize('view', $order); abort_unless($order->status === 'paid', 422); $order = Order::findOrFail($r->input('other')); $order->update(['status' => 'refunded']); }
                public function n11(Order $order) { $this->authorize('view', $order); $this->svc->ensurePaid($order); $order->update(['status' => 'refunded']); }
                public function n11b(Order $order, Invoice $invoice) { $this->authorize('view', $order); $this->authorize('view', $invoice); abort_unless($order->status === 'paid', 422); $this->svc->refund($invoice); }
                public function n10b(Order $order) { $this->authorize('view', $order); abort_unless($order->status === 'paid' || true, 422); $order->update(['status' => 'refunded']); }
                // mass
                public function n12(Request $r) { $this->authorize('create', Team::class); return Team::create(json_decode($r->getContent(), true)); }
                public function n12b(Request $r) { $this->authorize('create', Team::class); return Team::create($r->query()); }
                public function n12c(Request $r) { $this->authorize('create', Team::class); return Team::create($r->except('x')); }
                public function n12d(Request $r) { $this->authorize('create', Team::class); return Team::create($r->safe()->merge($r->all())->all()); }
            }
            PHP,
            'routes/web.php' => <<<'PHP'
            <?php
            use App\Http\Controllers\Q;
            use Illuminate\Support\Facades\Route;
            Route::middleware('auth')->group(function () {
                foreach (['n1','n2','n3','n3b','n4','n4b','n15','n15b'] as $n) {}
                Route::get('n1/{id}', [Q::class, 'n1']);
                Route::get('n2/{id}', [Q::class, 'n2']);
                Route::get('n3/{id}', [Q::class, 'n3']);
                Route::get('n3b/{id}', [Q::class, 'n3b']);
                Route::get('n4/{id}', [Q::class, 'n4']);
                Route::get('n4b/{id}', [Q::class, 'n4b']);
                Route::get('n5/{invoice}', [Q::class, 'n5']);
                Route::post('n6/{invoice}', [Q::class, 'n6']);
                Route::get('n6b/{invoice}', [Q::class, 'n6b']);
                Route::get('n15/{id}', [Q::class, 'n15']);
                Route::get('n15b/{id}', [Q::class, 'n15b']);
                Route::get('n16', [Q::class, 'n16']);
                Route::get('n16b', [Q::class, 'n16b']);
                Route::post('n7', [Q::class, 'n7']);
                Route::post('n7b', [Q::class, 'n7b']);
                Route::post('n8', [Q::class, 'n8']);
                Route::post('n9', [Q::class, 'n9']);
                Route::post('n9b', [Q::class, 'n9b']);
                Route::post('n9c', [Q::class, 'n9c']);
                Route::post('n9d', [Q::class, 'n9d']);
                Route::post('n9e', [Q::class, 'n9e']);
                Route::post('n9f', [Q::class, 'n9f']);
                Route::post('n9g', [Q::class, 'n9g']);
                Route::post('n9h', [Q::class, 'n9h']);
                Route::post('n10/{order}', [Q::class, 'n10']);
                Route::post('n10b/{order}', [Q::class, 'n10b']);
                Route::post('n11/{order}', [Q::class, 'n11']);
                Route::post('n11b/{order}/{invoice}', [Q::class, 'n11b']);
                Route::post('w1', [Q::class, 'w1']);
                Route::post('w2', [Q::class, 'w2']);
                Route::post('n12', [Q::class, 'n12']);
                Route::post('n12b', [Q::class, 'n12b']);
                Route::post('n12c', [Q::class, 'n12c']);
                Route::post('n12d', [Q::class, 'n12d']);
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

        return self::$probes = [$byKey, $selector->exclusions()];
    }
}
