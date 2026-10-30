<?php

declare(strict_types=1);

// Review round 4 probes (i: lookup-named app calls, m: materialisers, s: user-chain methods, c: callable strings, k: controls).
$m = fn ($n, $body = '') => "<?php namespace App\\Models; class $n extends \\Illuminate\\Database\\Eloquent\\Model { $body }";
$gets = ['i1','i2','i3','i4','i5','i6','i7','i8','m1','m2','m3'];
$posts = ['s1','s2','s3','s4','s5','s6','s7','s8','s9','s10','s11','s12','c1','c2','c3','c4','c5','c6','k1','k2','k3','i9'];
$r = "<?php\nuse App\\Http\\Controllers\\Q;\nuse Illuminate\\Support\\Facades\\Route;\nRoute::middleware('auth')->group(function () {\n";
foreach ($gets as $a) {
    $r .= "Route::get('$a/{id}', [Q::class, '$a']);\n";
}
foreach ($posts as $a) {
    $r .= "Route::post('$a', [Q::class, '$a']);\n";
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
'app/Models/Team.php' => $m('Team', "protected \$fillable = ['name', 'owner_id']; public function members(): \\Illuminate\\Database\\Eloquent\\Relations\\HasMany { return \$this->hasMany(User::class); }"),
'app/helpers.php' => '<?php function app_purge() { \App\Models\Team::query()->delete(); }',
'app/Services/Svc.php' => <<<'PHP'
<?php
namespace App\Services;
class Svc
{
    public function findKey($h) { return $h; }
}
PHP,
'app/Http/Controllers/Controller.php' => '<?php namespace App\Http\Controllers; abstract class Controller { use \Illuminate\Foundation\Auth\Access\AuthorizesRequests; }',
'app/Http/Controllers/Q.php' => <<<'PHP'
<?php
namespace App\Http\Controllers;
use App\Models\{Invoice,Post,Team,User};
use App\Services\Svc;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Auth;
class Q extends Controller
{
    public function __construct(private Svc $svc, private $mystery) {}
    private function findId($h) { return $h; }
    private function findCopy($h) { $y = $h; return $y; }
    // item 3: consuming call named like a lookup but not a model lookup
    public function i1(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $x = $this->findId($id); return Invoice::find($x); }
    public function i2(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $x = $this->svc->findKey($id); return Invoice::find($x); }
    public function i3(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $x = Arr::first(explode('-', $id)); return Invoice::find($x); }
    public function i4(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $x = collect(explode('-', $id))->first(); return Invoice::find($x); }
    public function i5(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $x = $this->mystery->whereabouts($id); return Invoice::find($x); }
    public function i6(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $x = \Hashids::decodeFirst($id); return Invoice::find($x); }
    public function i7(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $x = $this->svc->findKey(h: $id); return Invoice::find($x); }
    public function i8(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $x = $this->findCopy($id); return Invoice::find($x); }
    public function i9(Request $r) { auth()->user()->invoices()->findOrFail($r->input('invoice_id')); $x = $this->findId($r->input('invoice_id')); return Invoice::find($x); }
    // item 1
    public function m1(Request $r, $id) { return auth()->user()->invoices()->getResults()->first()->find($id); }
    public function m2(Request $r, $id) { return auth()->user()->invoices()->firstOrNew(['total' => 1])->find($id); }
    public function m3(Request $r, $id) { return auth()->user()->invoices()->findMany([1])->find($id); }
    // item 2 q1-style
    public function s1(Request $r) { $r->user()->posts()->create($r->validated()); $t = $r->user()->team; $t->purgeOthers(); }
    public function s2(Request $r) { $r->user()->posts()->create($r->validated()); $u = auth()->user(); $u->team->purgeOthers(); }
    public function s3(Request $r) { $r->user()->posts()->create($r->validated()); auth()->user()?->team?->purgeOthers(); }
    public function s4(Request $r) { $r->user()->posts()->create($r->validated()); auth('api')->user()->team->purgeOthers(); }
    public function s5(Request $r) { $r->user()->posts()->create($r->validated()); Auth::guard('api')->user()->team->purgeOthers(); }
    public function s6(Request $r) { $r->user()->posts()->create($r->validated()); auth()->guard()->user()->team->purgeOthers(); }
    public function s7(Request $r) { $r->user()->posts()->create($r->validated()); request()->user()->team->purgeOthers(); }
    public function s8(Request $r) { $r->user()->posts()->create($r->validated()); auth()->user()->purgeOthers(); }
    public function s9(Request $r) { $r->user()->posts()->create($r->validated()); auth()->user()->team()->purgeOthers(); }
    public function s10(Request $r) { $r->user()->posts()->create($r->validated()); auth()->user()->team->members()->first()->purgeOthers(); }
    public function s11(Request $r) { $r->user()->posts()->create($r->validated()); $t = auth()->user()->team; $t->purgeOthers(); }
    public function s12(Request $r) { $r->user()->posts()->create($r->validated()); $r->user('api')->team->purgeOthers(); }
    // item 2 q2 callable-shaped
    public function c1(Request $r) { $r->user()->posts()->create($r->validated()); ob_start('app_purge'); }
    public function c2(Request $r) { $r->user()->posts()->create($r->validated()); ob_start([$this->mystery, 'purge']); }
    public function c3(Request $r) { $r->user()->posts()->create($r->validated()); ob_start(fn () => 1); }
    public function c4(Request $r) { $r->user()->posts()->create($r->validated()); ob_start($this->mystery->purge(...)); }
    public function c5(Request $r) { $r->user()->posts()->create($r->validated()); set_error_handler('App\Support\purge'); }
    public function c6(Request $r) { $r->user()->posts()->create($r->validated()); ob_start(...); }
    // control: auth()->id() scoped write stays excluded
    public function k1(Request $r) { Post::where('user_id', auth()->id())->update(['title' => 'x']); }
    // controls: a write on one relation hop held in a variable, and compact() strings, stay self-scoped
    public function k2(Request $r) { $t = $r->user()->team; $t->update(['name' => 'x']); }
    public function k3(Request $r) { $r->user()->posts()->create($r->validated()); $x = compact('r'); }
}
PHP,
'routes/web.php' => $r,
];
