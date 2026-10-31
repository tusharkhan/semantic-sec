<?php

declare(strict_types=1);

// Review round 5 probes (j/i: callee taint walk, c: callable arguments, s/v: default-deny self-scope, k: controls).
$m = fn ($n, $body = '') => "<?php namespace App\\Models; class $n extends \\Illuminate\\Database\\Eloquent\\Model { $body }";
$gets = ['j7','j8','j1','j2','j3','j4','j5','j6','i10','i11','i12','i13','i14','i15','i16','i18','i19','i20','i21','i22','i23','i24','i25','i26','i27','i28','i29'];
$posts = ['c7','c8','c9','c10','c11','c12','c13','c14','c15','c16','c18','c19','c20','s13','s14','s15','s16','s17','s18','s19','s20','s21','s22','s23','s25','s29','s30','s31','s32','k4','k5','k6','k7','v1','v2','v3','v4','v5','v6','v7'];
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
    public function findTwo($a, $b) { return $b; }
    public function findRef($h, &$out) { $out = $h; return null; }
    public function findAll(...$hs) { return $hs[0]; }
    public function copyRef($h, &$out) { $out = $h; return null; }
    public function copyAll(...$hs) { return $hs[0]; }
}
PHP,
'app/Repos/InvoiceRepo.php' => <<<'PHP'
<?php
namespace App\Repos;
class InvoiceRepo
{
    public function find($id) { return \App\Models\Invoice::find($id); }
}
PHP,
'app/Http/Controllers/Controller.php' => '<?php namespace App\Http\Controllers; abstract class Controller { use \Illuminate\Foundation\Auth\Access\AuthorizesRequests; protected function findParent($h) { return $h; } }',
'app/Http/Controllers/Q.php' => <<<'PHP'
<?php
namespace App\Http\Controllers;
use App\Models\{Invoice,Post,Team,User};
use App\Services\Svc;
use App\Repos\InvoiceRepo;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
class Q extends Controller
{
    public function __construct(private Svc $svc, private InvoiceRepo $repo, private $mystery) {}
    private function findId($h) { return $h; }
    private static function findStatic($h) { return $h; }
    private function findVia($h) { return $this->findId($h); }
    private function findArr($h) { return [$h]; }
    private function findCast($h) { return (int) ($h ?? 0); }
    private function findDeep($h) { $a = $h; $b = $a; $c = $b; $d = $c; $e = $d; $f = $e; return $f; }
    private function findMatch($h) { return match (true) { default => $h }; }
    private function findList($h) { [$a] = [$h]; return $a; }
    private function findLoop($h) { foreach ([$h] as $v) { return $v; } }
    private function findInvoice($h) { return Invoice::find($h); }
    private function findProp($h) { $this->k = $h; return $this->k; }
    private function findGen($h) { yield $h; }
    private function copyLoop($h) { foreach ([$h] as $v) { return $v; } }
    private function copyGen($h) { yield $h; }
    private function copyId($h) { return $h; }
    public function j7(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); preg_match('/(\d+)/', $id, $m); return Invoice::find($m[1]); }
    public function j8(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); foreach ([$id] as $k => $v) { return Invoice::find($v); } }
    public function j1(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $this->svc->copyRef($id, $out); return Invoice::find($out); }
    public function j2(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $x = $this->copyLoop($id); return Invoice::find($x); }
    public function j3(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); foreach ($this->copyGen($id) as $x) { return Invoice::find($x); } }
    public function j4(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $x = $this->copyId($id); return Invoice::find($x); }
    public function j5(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $this->mystery->copyRef($id, $out); return Invoice::find($out); }
    public function j6(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $x = $this->svc->copyAll($id); return Invoice::find($x); }
    public function i10(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $x = $this->findId(h: $id); return Invoice::find($x); }
    public function i11(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $x = self::findStatic($id); return Invoice::find($x); }
    public function i12(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $x = $this->findVia($id); return Invoice::find($x); }
    public function i13(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $x = $this->findArr($id); return Invoice::find($x[0]); }
    public function i14(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $x = $this->findCast($id); return Invoice::find($x); }
    public function i15(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $x = $this->svc->findTwo(b: $id, a: 1); return Invoice::find($x); }
    public function i16(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $x = $this->findProp($id); return Invoice::find($x); }
    public function i18(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $this->svc->findRef($id, $out); return Invoice::find($out); }
    public function i19(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $x = $this->svc->findAll($id); return Invoice::find($x); }
    public function i20(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $x = $this->findId(...[$id]); return Invoice::find($x); }
    public function i21(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $x = $this->findDeep($id); return Invoice::find($x); }
    public function i22(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $x = $this->findParent($id); return Invoice::find($x); }
    public function i23(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $x = $this->findMatch($id); return Invoice::find($x); }
    public function i24(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $x = $this->findList($id); return Invoice::find($x); }
    public function i25(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $x = $this->findLoop($id); return Invoice::find($x); }
    public function i26(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); return $this->findInvoice($id); }
    public function i27(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); return $this->repo->find($id); }
    public function i28(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); foreach ($this->findGen($id) as $x) { return Invoice::find($x); } }
    public function i29(Request $r, $id) { auth()->user()->invoices()->findOrFail($id); $x = static::findStatic($id); return Invoice::find($x); }
    // callable strings
    public function c7(Request $r) { $r->user()->posts()->create($r->validated()); register_shutdown_function('app_purge'); }
    public function c8(Request $r) { $r->user()->posts()->create($r->validated()); array_map('app_purge', [1]); }
    public function c9(Request $r) { $r->user()->posts()->create($r->validated()); call_user_func('App\Support\purge'); }
    public function c10(Request $r) { $r->user()->posts()->create($r->validated()); $f = 'app_purge'; ob_start($f); }
    public function c11(Request $r) { $r->user()->posts()->create($r->validated()); ob_start("app_purge"); }
    public function c12(Request $r) { $r->user()->posts()->create($r->validated()); ob_start('\app_purge'); }
    public function c13(Request $r) { $r->user()->posts()->create($r->validated()); $f = 'app_purge'; $f(); }
    public function c14(Request $r) { $r->user()->posts()->create($r->validated()); ob_start('App\Support\Purger::run'); }
    public function c15(Request $r) { $r->user()->posts()->create($r->validated()); ob_start(['App\Support\Purger', 'run']); }
    public function c16(Request $r) { $r->user()->posts()->create($r->validated()); app()->call('App\Support\Purger@run'); }
    public function c18(Request $r) { $r->user()->posts()->create($r->validated()); ob_start('app_' . 'purge'); }
    public function c19(Request $r) { $r->user()->posts()->create($r->validated()); $a = [2, 1]; usort($a, 'app_purge'); }
    public function c20(Request $r) { $r->user()->posts()->create($r->validated()); ob_start(callback: 'app_purge'); }
    // relation hops / models in variables
    public function s13(Request $r) { $r->user()->posts()->create($r->validated()); $t = $r->user()->team; $t?->purgeOthers(); }
    public function s14(Request $r) { $r->user()->posts()->create($r->validated()); $t = auth()->user()->team()->first(); $t->purgeOthers(); }
    public function s15(Request $r) { $r->user()->posts()->create($r->validated()); $t = Team::first(); $t->purgeOthers(); }
    public function s16(Request $r) { $r->user()->posts()->create($r->validated()); Team::find(1)->purgeOthers(); }
    public function s17(Request $r) { $r->user()->posts()->create($r->validated()); $u = $r->user(); $t = $u->team; $t->purgeOthers(); }
    public function s18(Request $r) { $r->user()->posts()->create($r->validated()); $t = $r->user()->team; $t->members()->first()->purgeOthers(); }
    public function s19(Request $r) { $r->user()->posts()->create($r->validated()); $t = $r->user()->team; $m = $t->members()->first(); $m->purgeOthers(); }
    public function s20(Request $r) { $r->user()->posts()->create($r->validated()); $t = $r->user()->team; $t->{$r->input('m')}(); }
    public function s21(Request $r) { $r->user()->posts()->create($r->validated()); $t = Team::query()->where('owner_id', 1)->first(); $t->purgeOthers(); }
    public function s22(Request $r) { $r->user()->posts()->create($r->validated()); $t = $r->user()->team; $f = $t->purgeOthers(...); $f(); }
    public function s23(Request $r) { $r->user()->posts()->create($r->validated()); foreach ($r->user()->posts as $p) { $p->purgeOthers(); } }
    public function s25(Request $r) { $r->user()->posts()->create($r->validated()); Team::first()->purgeOthers(); }
    public function s29(Request $r) { $r->user()->posts()->create($r->validated()); (new Team)->purgeOthers(); }
    public function s30(Request $r) { $r->user()->posts()->create($r->validated()); $t = Team::all(); $t->each->delete(); }
    public function s31(Request $r) { $r->user()->posts()->create($r->validated()); $t = Team::first(); $t->delete(); }
    public function s32(Request $r) { $r->user()->posts()->create($r->validated()); $t = Team::first(); $t->update(['owner_id' => 1]); }
    public function v1(Request $r) { $r->user()->posts()->create($r->validated()); Team::first()->restore(); }
    public function v2(Request $r) { $r->user()->posts()->create($r->validated()); Team::find(1)->syncRoles(['admin']); }
    public function v3(Request $r) { $r->user()->posts()->create($r->validated()); Team::first()->touch(); }
    public function v4(Request $r) { $r->user()->posts()->create($r->validated()); Team::first()->increment('name'); }
    public function v5(Request $r) { $r->user()->posts()->create($r->validated()); $t = $r->user()->team()->first(); $t->purgeOthers(); }
    public function v6(Request $r) { $r->user()->posts()->create($r->validated()); $t = Team::find($r->input('team')); $t->purgeOthers(); }
    public function v7(Request $r) { $r->user()->posts()->create($r->validated()); $t = Team::first(); $t->members()->first()->purgeOthers(); }
    // controls: should stay excluded
    public function k4(Request $r) { $r->user()->posts()->create($r->validated()); $t = $r->user()->team; $t->update(['name' => 'x']); }
    public function k5(Request $r) { $r->user()->posts()->create($r->validated()); $t = $r->user()->team; $t->members()->get(); }
    public function k6(Request $r) { $r->user()->posts()->create(compact('r')); }
    public function k7(Request $r) { $n = $r->user()->posts()->count(); $r->user()->posts()->create($r->validated()); return response()->json(['n' => $n]); }
}
PHP,
'routes/web.php' => $r,
];
