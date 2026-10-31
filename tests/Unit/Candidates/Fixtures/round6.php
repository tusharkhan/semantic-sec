<?php

declare(strict_types=1);

// Final-review probes (C1 pivot writes, I1 state changes, I2 request arrays, I3 widened builders, k: controls).
$m = fn ($n, $body = '') => "<?php namespace App\\Models; class $n extends \\Illuminate\\Database\\Eloquent\\Model { $body }";
$gets = ['p1', 'p2', 'p3', 'p4', 'p7', 'p9', 'p14', 'p15', 'p16', 'p17', 'p18', 'p19', 'p20', 'p21', 'p22', 'r1', 'r2', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11'];
$ids = ['p5', 'p5b', 'p5c', 'k4', 'k5'];
$posts = ['q1', 'q2', 'q6', 'q7', 'q8', 'q9', 'k1', 'k2', 'k3'];
$r = "<?php\nuse App\\Http\\Controllers\\F;\nuse App\\Http\\Controllers\\D;\nuse Illuminate\\Support\\Facades\\Route;\nRoute::middleware('auth')->group(function () {\n";
foreach ($gets as $a) {
    $r .= "Route::get('$a', [F::class, '$a']);\n";
}
foreach ($ids as $a) {
    $r .= "Route::get('$a/{id}', [F::class, '$a']);\n";
}
foreach ($posts as $a) {
    $r .= "Route::post('$a', [F::class, '$a']);\n";
}
foreach (['destroy', 'deleteAll', 'removeOld', 'purgeCache', 'truncateLogs', 'show'] as $a) {
    $r .= "Route::get('d/$a', [D::class, '$a']);\n";
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
    public function roles(): \Illuminate\Database\Eloquent\Relations\BelongsToMany { return $this->belongsToMany(Role::class); }
    public function tags(): \Illuminate\Database\Eloquent\Relations\BelongsToMany { return $this->belongsToMany(Tag::class); }
}
PHP,
'app/Models/Post.php' => $m('Post', "protected \$fillable = ['title'];"),
'app/Models/Role.php' => $m('Role', "protected \$fillable = ['name'];"),
'app/Models/Tag.php' => $m('Tag', "protected \$fillable = ['name'];"),
'app/Models/Setting.php' => $m('Setting', "protected \$fillable = ['value'];"),
'app/helpers.php' => <<<'PHP'
<?php
use App\Models\Post;
use Illuminate\Support\Facades\DB;
function wipe_posts() { Post::query()->delete(); }
function cron_outer() { return cron_inner(); }
function cron_inner() { DB::table('attendances')->insert(['a' => 1]); }
if (! function_exists('guarded_helper')) {
    function guarded_helper() { DB::table('notifications')->truncate(); }
}
PHP,
'app/Support/functions.php' => <<<'PHP'
<?php
namespace App\Support;
function ns_purge() { \Illuminate\Support\Facades\DB::table('logs')->delete(); }
PHP,
'app/Services/Svc.php' => '<?php namespace App\Services; class Svc { public function zap() { return 1; } }',
'app/Http/Controllers/Controller.php' => '<?php namespace App\Http\Controllers; abstract class Controller { use \Illuminate\Foundation\Auth\Access\AuthorizesRequests; }',
'app/Http/Controllers/F.php' => <<<'PHP'
<?php
namespace App\Http\Controllers;
use App\Models\Post;
use App\Models\Setting;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
class F extends Controller
{
    // I1(c): a write hidden in an app global function, one or two calls deep
    public function p1() { wipe_posts(); return response()->json([]); }
    public function p20() { return cron_outer(); }
    public function p21() { guarded_helper(); return 1; }
    public function p22() { \App\Support\ns_purge(); return 1; }
    // I1(b): DB facade writes
    public function p2() { return DB::table('posts')->truncate(); }
    public function p9() { DB::delete('delete from posts'); return 1; }
    public function p14() { DB::insert('insert into posts (title) values (?)', ['x']); return 1; }
    public function p15() { DB::statement('drop table posts'); return 1; }
    public function p16() { DB::unprepared('delete from posts'); return 1; }
    public function p17() { DB::table('posts')->insert(['title' => 'x']); return 1; }
    public function p18() { DB::table('posts')->upsert([['id' => 1]], ['id']); return 1; }
    public function p19() { DB::table('settings')->where('k', 'hits')->decrement('v'); return 1; }
    // I1(a): writes STATE_CALLS used to miss
    public function p3() { Setting::first()->increment('hits'); return 1; }
    public function p7(Request $request) { Setting::updateOrCreate(['k' => 'x'], ['v' => $request->v]); return 1; }
    // C1 on GET
    public function p4(Request $request) { $request->user()->roles()->sync($request->input('roles')); return 1; }
    // I3: a scoped builder widened through an app method
    public function p5($id) {
        $q = Post::where('id', $id)->where('user_id', auth()->id());
        $q = $this->widen($q);
        return $q->first();
    }
    public function p5b($id) {
        $q = Post::where('id', $id)->where('user_id', auth()->id());
        $this->widenInPlace($q);
        return $q->first();
    }
    public function p5c($id) {
        $q = Post::where('id', $id)->where('user_id', auth()->id());
        $q->orWhere('status', 'public');
        return $q->first();
    }
    private function widen($q) { return $q->orWhere('status', 'public'); }
    private function widenInPlace($q): void { $q->orWhere('status', 'public'); }
    // I2: ids read through a request-array variable
    public function r1(Request $request) { $query = $request->all(); return Post::where('user_id', $query['user_id'])->get(); }
    public function r2(Request $request) { $query = $request->all(); return Post::whereHas('comments', function ($q) use ($query) { $q->where('user_id', $query['user_id']); })->get(); }
    public function r4(Request $request) { $data = $request->all(); return Post::find($data['post_id']); }
    public function r5(Request $request) { $data = $request->validated(); return Post::find($data['post_id']); }
    public function r6(Request $request) { $data = $request->only(['post_id']); return Post::find($data['post_id']); }
    public function r7(Request $request) { $data = $request->input(); return Post::find($data['post_id']); }
    public function r8(Request $request) { $data = $request->except(['title']); return Post::find($data['post_id']); }
    public function r9() { $data = request()->all(); return Post::find($data['post_id']); }
    public function r10(Request $request) { return Post::find($request->all()['post_id']); }
    public function r11(Request $request) { $data = $request->all(); return $this->load($data); }
    private function load(array $data) { return Post::find($data['post_id']); }
    // C1: pivot writes from input on the auth user
    public function q1(Request $request) { $request->user()->roles()->sync($request->input('roles')); return 1; }
    public function q2(Request $request) { auth()->user()->roles()->attach($request->role_id); return 1; }
    public function q6(Request $request) { $request->user()->roles()->syncWithoutDetaching($request->roles); return 1; }
    public function q7(Request $request) { $request->user()->tags()->toggle($request->input('tags')); return 1; }
    public function q8(Request $request) { $request->user()->roles()->updateExistingPivot($request->role, ['active' => true]); return 1; }
    public function q9(Request $request) { $ids = $request->input('roles'); auth()->user()->roles()->sync($ids); return 1; }
    // Controls: these stay self-scoped or covered
    public function k1(Request $request) { $request->user()->roles()->detach(); return 1; }
    public function k2(Request $request) { $request->user()->tags()->sync([1, 2]); return 1; }
    public function k3(Request $request) { $request->user()->posts()->create($request->validated()); return 1; }
    public function k4($id) { $q = Post::where('id', $id)->where('user_id', auth()->id()); return $q->firstOrFail(); }
    public function k5($id) { $q = Post::where('id', $id)->where('user_id', auth()->id()); $q = $q->latest(); return $q->firstOrFail(); }
}
PHP,
'app/Http/Controllers/D.php' => <<<'PHP'
<?php
namespace App\Http\Controllers;
class D extends Controller
{
    public function __construct(private $svc) {}
    // I1(d): destroy-style actions whose write is out of sight
    public function destroy() { $this->svc->zap(); return 1; }
    public function deleteAll() { $this->svc->zap(); return 1; }
    public function removeOld() { $this->svc->zap(); return 1; }
    public function purgeCache() { $this->svc->zap(); return 1; }
    public function truncateLogs() { $this->svc->zap(); return 1; }
    public function show() { return 1; }
}
PHP,
'routes/web.php' => $r,
];
