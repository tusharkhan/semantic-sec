<?php

declare(strict_types=1);

// Review round 3 probes (p: id carry and materialisers, q: self-scope harmless set, r: workflow guards).
$m = fn ($n, $body = '') => "<?php namespace App\\Models; class $n extends \\Illuminate\\Database\\Eloquent\\Model { $body }";
$routes = ['p1/{id}','p2/{id}','p3/{id}','p4/{id}','p5/{id}','p6/{id}','p7/{invoice}','p8/{id}','p9/{id}','p10/{id}','p11/{id}'];
$posts = ['q1','q2','q3','q4','q5','q6','q7'];
$wf = ['r1/{order}','r2/{order}'];
$r = "<?php\nuse App\\Http\\Controllers\\Q;\nuse Illuminate\\Support\\Facades\\Route;\nRoute::middleware('auth')->group(function () {\n";
foreach ($routes as $u) {
    $a = explode('/', $u)[0];
    $r .= "Route::get('$u', [Q::class, '$a']);\n";
}
foreach ($posts as $a) {
    $r .= "Route::post('$a', [Q::class, '$a']);\n";
}
foreach ($wf as $u) {
    $a = explode('/', $u)[0];
    $r .= "Route::post('$u', [Q::class, '$a']);\n";
}
$r .= "});\n";
return [
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
class Svc
{
    public function load($id) { return $id; }
    public function decode($hash) { return (int) $hash; }
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
    private function norm($id) { return $id; }
    // item 3 narrowing: call result carrying the id
    public function p1(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $x = $this->svc->load($id); return Invoice::find($x); }
    public function p2(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $x = $this->norm($id); return Invoice::find($x); }
    public function p3(Request $r, $id) { $x = $this->svc->decode($id); return Invoice::find($x); }
    public function p4(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $x = session('k', $id); return Invoice::find($x); }
    public function p5(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $x = max($id, 1); return Invoice::find($x); }
    public function p6(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $x = $id ?: 1; return Invoice::find($x); }
    // item 1
    public function p7(Invoice $invoice) { auth()->user()->invoices()->findOrFail($invoice->id)->touch(); return $invoice; }
    public function p8(Request $r, $id) { return auth()->user()->invoices()->firstWhere('total', '>', 0)->find($id); }
    public function p9(Request $r, $id) { return Invoice::where('user_id', auth()->id())->firstOr(fn () => null)->find($id); }
    public function p10(Request $r, $id) { return auth()->user()->invoices()->latest()->first()?->find($id); }
    public function p11(Request $r, $id) { return auth()->user()->invoices()->findOrFail($id)->delete(); }
    // item 2 harmless set
    public function q1(Request $r) { $r->user()->posts()->create($r->validated()); $r->user()->team->purgeOthers(); }
    public function q2(Request $r) { $r->user()->posts()->create($r->validated()); preg_replace_callback('/x/', [$this->mystery, 'purge'], 'x'); }
    public function q3(Request $r) { $r->user()->posts()->create($r->validated()); auth()->user()->team->purgeOthers(); }
    public function q4(Request $r) { $r->user()->team()->first()->update(['name' => 'x']); }
    public function q5(Request $r) { $t = $r->user()->team; $t->members()->delete(); }
    public function q6(Request $r) { $r->user()->posts()->create($r->validated()); \Illuminate\Support\Facades\Auth::user()->team->purgeOthers(); }
    public function q7(Request $r) { $r->user()->posts()->create($r->validated()); $r->user()->posts->each->forceDelete(); }
    // item 4
    public function r1(Order $order) { $this->authorize('view', $order); abort_if($order->status !== 'paid' && $order->status !== 'open', 422); $order->update(['status' => 'refunded']); }
    public function r2(Request $r, Order $order) { $this->authorize('view', $order); foreach ([1] as $_) { abort_unless($order->status === 'paid', 422); $order->update(['status' => 'refunded']); } }
}
PHP,
'routes/web.php' => $r,
];
