<?php

declare(strict_types=1);

// List-endpoint probes: a GET with no identifier that reads an owned collection without a user scope is an idor candidate.
return [
'app/Models/User.php' => <<<'PHP'
<?php
namespace App\Models;
class User extends \Illuminate\Foundation\Auth\User
{
    public function tickets() { return $this->hasMany(Ticket::class); }
    public function invoices() { return $this->hasMany(Invoice::class); }
}
PHP,
'app/Models/Ticket.php' => <<<'PHP'
<?php
namespace App\Models;
class Ticket extends \Illuminate\Database\Eloquent\Model
{
    protected $fillable = ['subject'];
    public function author() { return $this->belongsTo(User::class); }
}
PHP,
'app/Models/Note.php' => "<?php namespace App\\Models; class Note extends \\Illuminate\\Database\\Eloquent\\Model { protected \$fillable = ['team_id', 'body']; }",
'app/Models/Invoice.php' => "<?php namespace App\\Models; class Invoice extends \\Illuminate\\Database\\Eloquent\\Model { protected \$fillable = ['total']; }",
'app/Models/Widget.php' => "<?php namespace App\\Models; class Widget extends \\Illuminate\\Database\\Eloquent\\Model { protected \$guarded = ['id']; }",
'app/Models/Tag.php' => "<?php namespace App\\Models; class Tag extends \\Illuminate\\Database\\Eloquent\\Model { protected \$fillable = ['name']; }",
'app/Http/Controllers/L.php' => <<<'PHP'
<?php
namespace App\Http\Controllers;
use App\Models\Invoice;
use App\Models\Note;
use App\Models\Tag;
use App\Models\Ticket;
use App\Models\Widget;
use Illuminate\Http\Request;
class L
{
    public function belongsToUser() { return Ticket::all(); }
    public function teamKey() { return Note::query()->latest()->paginate(20); }
    public function inverseRelation() { return Invoice::where('total', '>', 0)->get(); }
    public function unknownColumns() { return Widget::get(); }
    public function notOwned() { return Tag::orderBy('name')->get(); }
    public function relationScoped(Request $request) { return $request->user()->tickets()->latest()->get(); }
    public function whereScoped() { return Ticket::where('author_id', auth()->id())->get(); }
    public function gated() { return Ticket::all(); }
    public function viaCallee() { return $this->load(); }
    private function load() { return Note::pluck('body'); }
    public function store() { return Ticket::all(); }
    public function count() { return Ticket::count(); }
    public function varBuilt(Request $request)
    {
        $q = Note::query();
        if ($request->filled('s')) {
            $q = $q->where('body', 'like', $request->input('s'));
        }
        return $q->orderBy('id')->paginate(10);
    }
    public function varScoped() { $q = Ticket::where('author_id', auth()->id()); $q = $q->latest(); return $q->get(); }
    public function varWidened() { $q = Ticket::where('author_id', auth()->id()); return $q->orWhere('subject', 'x')->get(); }
    public function viaBuilder() { $q = $this->base(); return $q->paginate(); }
    private function base() { return Note::query()->latest(); }
}
PHP,
'routes/web.php' => <<<'PHP'
<?php
use App\Http\Controllers\L;
use Illuminate\Support\Facades\Route;
Route::middleware('auth')->group(function () {
    Route::get('owned-by-user', [L::class, 'belongsToUser']);
    Route::get('team-key', [L::class, 'teamKey']);
    Route::get('inverse', [L::class, 'inverseRelation']);
    Route::get('unknown-columns', [L::class, 'unknownColumns']);
    Route::get('not-owned', [L::class, 'notOwned']);
    Route::get('relation-scoped', [L::class, 'relationScoped']);
    Route::get('where-scoped', [L::class, 'whereScoped']);
    Route::get('gated', [L::class, 'gated'])->middleware('can:viewAny,App\Models\Ticket');
    Route::get('via-callee', [L::class, 'viaCallee']);
    Route::post('store', [L::class, 'store']);
    Route::get('count', [L::class, 'count']);
    Route::get('var-built', [L::class, 'varBuilt']);
    Route::get('var-scoped', [L::class, 'varScoped']);
    Route::get('var-widened', [L::class, 'varWidened']);
    Route::get('via-builder', [L::class, 'viaBuilder']);
});
PHP,
];
