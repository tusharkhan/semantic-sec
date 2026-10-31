<?php

declare(strict_types=1);

// authorization_middleware probes: a listed middleware authorizes the route but covers no identifier.
return [
'bootstrap/app.php' => <<<'PHP'
<?php
return \Illuminate\Foundation\Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function ($middleware) {
        $middleware->alias(['permission' => \App\Http\Middleware\CheckPermission::class]);
    })
    ->create();
PHP,
'app/Http/Middleware/CheckPermission.php' => '<?php namespace App\Http\Middleware; class CheckPermission {}',
'app/Http/Middleware/ClassListed.php' => '<?php namespace App\Http\Middleware; class ClassListed {}',
'app/Models/Post.php' => "<?php namespace App\\Models; class Post extends \\Illuminate\\Database\\Eloquent\\Model { protected \$fillable = ['title']; }",
'app/Http/Controllers/X.php' => <<<'PHP'
<?php
namespace App\Http\Controllers;
use App\Models\Post;
use Illuminate\Http\Request;
class X
{
    public function update(Request $request, $id) { Post::findOrFail($id)->update(['title' => 'x']); return 1; }
}
PHP,
'app/Http/Controllers/C.php' => <<<'PHP'
<?php
namespace App\Http\Controllers;
use App\Models\Post;
class C extends Controller
{
    public function __construct() { $this->middleware('permission:manage'); }
    public function update($id) { Post::findOrFail($id)->update(['title' => 'x']); return 1; }
}
PHP,
'app/Http/Controllers/Controller.php' => '<?php namespace App\Http\Controllers; abstract class Controller {}',
'routes/web.php' => <<<'PHP'
<?php
use App\Http\Controllers\X;
use App\Http\Controllers\C;
use Illuminate\Support\Facades\Route;
Route::middleware('auth')->group(function () {
    Route::put('x/{id}', [X::class, 'update'])->middleware('permission:manage');
    Route::put('y/{id}', [X::class, 'update']);
    Route::put('f/{id}', [X::class, 'update'])->middleware(\App\Http\Middleware\ClassListed::class);
    Route::middleware('permission')->group(function () {
        Route::put('g/{id}', [X::class, 'update']);
        Route::put('w/{id}', [X::class, 'update'])->withoutMiddleware($dynamic);
    });
    Route::put('c/{id}', [C::class, 'update']);
});
PHP,
];
