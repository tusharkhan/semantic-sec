<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Since;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Analysis\Confidence;
use TusharKhan\SemanticSec\Analysis\Severity;
use TusharKhan\SemanticSec\Candidates\Candidate;
use TusharKhan\SemanticSec\Config\Config;
use TusharKhan\SemanticSec\Framework\DetectedFramework;
use TusharKhan\SemanticSec\Framework\Laravel\LaravelContext;
use TusharKhan\SemanticSec\Parsing\AstGenerator;
use TusharKhan\SemanticSec\Parsing\ParseFailure;
use TusharKhan\SemanticSec\Parsing\ParseResult;
use TusharKhan\SemanticSec\Parsing\SourceFile;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTableBuilder;
use TusharKhan\SemanticSec\Since\ImpactAnalyzer;

final class ImpactAnalyzerTest extends TestCase
{
    private const POSTS = 'PUT /posts/{post}';

    private const TAGS = 'GET /api/tags/{id}';

    private const ADMIN = 'GET /admin/users/{id}';

    private const FILES = [
        'routes/web.php' => <<<'PHP'
            <?php

            use App\Http\Controllers\PostController;
            use Illuminate\Support\Facades\Route;

            Route::middleware(['auth', 'owner'])->group(function () {
                Route::put('posts/{post}', [PostController::class, 'update']);
            });

            require __DIR__.'/admin.php';
            PHP,
        'routes/admin.php' => <<<'PHP'
            <?php

            use App\Http\Controllers\AdminController;
            use Illuminate\Support\Facades\Route;

            Route::get('admin/users/{id}', [AdminController::class, 'user']);
            PHP,
        'routes/api.php' => <<<'PHP'
            <?php

            use App\Http\Controllers\TagController;
            use Illuminate\Support\Facades\Route;

            Route::get('tags/{id}', [TagController::class, 'show']);
            PHP,
        'app/Http/Kernel.php' => <<<'PHP'
            <?php
            namespace App\Http;

            class Kernel extends \Illuminate\Foundation\Http\Kernel
            {
                protected $middlewareAliases = [
                    'auth' => \Illuminate\Auth\Middleware\Authenticate::class,
                    'owner' => \App\Http\Middleware\EnsureOwner::class,
                ];
            }
            PHP,
        'app/Http/Middleware/EnsureOwner.php' => <<<'PHP'
            <?php
            namespace App\Http\Middleware;

            class EnsureOwner extends BaseMiddleware
            {
                public function handle($request, \Closure $next)
                {
                    return $next($request);
                }
            }
            PHP,
        'app/Http/Middleware/BaseMiddleware.php' => '<?php namespace App\Http\Middleware; abstract class BaseMiddleware { }',
        'app/Providers/AppServiceProvider.php' => <<<'PHP'
            <?php
            namespace App\Providers;

            class AppServiceProvider extends \Illuminate\Support\ServiceProvider
            {
                public function boot(): void
                {
                }
            }
            PHP,
        'app/Models/User.php' => "<?php\nnamespace App\\Models;\n\nclass User extends \\Illuminate\\Foundation\\Auth\\User\n{\n}\n",
        'app/Models/Post.php' => <<<'PHP'
            <?php
            namespace App\Models;

            class Post extends \Illuminate\Database\Eloquent\Model
            {
                use HasOwner;

                protected $fillable = ['title', 'user_id'];
            }
            PHP,
        'app/Models/HasOwner.php' => '<?php namespace App\Models; trait HasOwner { }',
        'app/Models/Tag.php' => <<<'PHP'
            <?php
            namespace App\Models;

            class Tag extends \Illuminate\Database\Eloquent\Model
            {
            }
            PHP,
        'app/Policies/PostPolicy.php' => <<<'PHP'
            <?php
            namespace App\Policies;

            use App\Models\Post;
            use App\Models\User;

            class PostPolicy
            {
                public function update(User $user, Post $post): bool
                {
                    return $user->id === $post->user_id;
                }
            }
            PHP,
        'app/Http/Requests/UpdatePostRequest.php' => <<<'PHP'
            <?php
            namespace App\Http\Requests;

            class UpdatePostRequest extends \Illuminate\Foundation\Http\FormRequest
            {
                public function authorize(): bool
                {
                    return true;
                }

                public function rules(): array
                {
                    return ['title' => 'required|string'];
                }
            }
            PHP,
        'app/Http/Controllers/Controller.php' => '<?php namespace App\Http\Controllers; abstract class Controller { use \Illuminate\Foundation\Auth\Access\AuthorizesRequests; }',
        'app/Http/Controllers/PostController.php' => <<<'PHP'
            <?php
            namespace App\Http\Controllers;

            use App\Http\Requests\UpdatePostRequest;
            use App\Models\Post;
            use App\Services\PostService;

            class PostController extends Controller
            {
                public function __construct(private PostService $service)
                {
                }

                public function update(UpdatePostRequest $request, Post $post)
                {
                    $this->authorize('update', $post);
                    $this->service->save($post, $request->all());

                    return $post;
                }
            }
            PHP,
        'app/Http/Controllers/TagController.php' => <<<'PHP'
            <?php
            namespace App\Http\Controllers;

            use App\Models\Tag;

            class TagController extends Controller
            {
                public function show(int $id)
                {
                    return Tag::findOrFail($id);
                }
            }
            PHP,
        'app/Http/Controllers/AdminController.php' => <<<'PHP'
            <?php
            namespace App\Http\Controllers;

            use App\Models\User;

            class AdminController extends Controller
            {
                public function user(int $id)
                {
                    return User::findOrFail($id);
                }
            }
            PHP,
        'app/Services/PostService.php' => <<<'PHP'
            <?php
            namespace App\Services;

            use App\Models\Post;

            class PostService
            {
                public function save(Post $post, array $data): void
                {
                    $post->update($data);
                }
            }
            PHP,
        'app/Services/Unrelated.php' => '<?php namespace App\Services; class Unrelated { public function run(): int { return 1; } }',
        'config/app.php' => "<?php\n\nreturn ['name' => 'demo'];\n",
        'config/auth.php' => "<?php\n\nreturn ['defaults' => ['guard' => 'web']];\n",
    ];

    public function testFixtureHasEveryCandidate(): void
    {
        self::assertSame([self::ADMIN, self::TAGS, self::POSTS], $this->affected(['routes/web.php']));
    }

    public function testExecutionPathNodeChanged(): void
    {
        self::assertSame([self::POSTS], $this->affected(['app/Services/PostService.php']));
        self::assertSame([self::TAGS], $this->affected(['app/Http/Controllers/TagController.php']));
    }

    public function testRouteFileChanged(): void
    {
        self::assertSame([self::TAGS], $this->affected(['routes/api.php']));
        self::assertSame([self::ADMIN], $this->affected(['routes/admin.php']));
    }

    public function testRouteFileThatLoadsOthersWidensToAll(): void
    {
        self::assertSame([self::ADMIN, self::TAGS, self::POSTS], $this->affected(['routes/web.php']));
    }

    public function testMiddlewareChanged(): void
    {
        self::assertSame([self::POSTS], $this->affected(['app/Http/Middleware/EnsureOwner.php']));
        self::assertSame([self::POSTS], $this->affected(['app/Http/Middleware/BaseMiddleware.php']), 'a middleware parent class');
    }

    public function testPolicyChanged(): void
    {
        self::assertSame([self::POSTS], $this->affected(['app/Policies/PostPolicy.php']));
    }

    public function testFormRequestChanged(): void
    {
        self::assertSame([self::POSTS], $this->affected(['app/Http/Requests/UpdatePostRequest.php']));
    }

    public function testModelChanged(): void
    {
        self::assertSame([self::TAGS], $this->affected(['app/Models/Tag.php']));
        self::assertSame([self::POSTS], $this->affected(['app/Models/HasOwner.php']), 'a trait the bound model uses');
    }

    public function testControllerBaseClassChanged(): void
    {
        self::assertSame([self::ADMIN, self::TAGS, self::POSTS], $this->affected(['app/Http/Controllers/Controller.php']));
    }

    public function testGlobalFileWidensToAll(): void
    {
        foreach (['app/Http/Kernel.php', 'bootstrap/app.php', 'app/Providers/AuthServiceProvider.php', 'app/Providers/RouteServiceProvider.php', 'modules/Billing/BillingAuthServiceProvider.php', 'src/ShopRouteServiceProvider.php'] as $file) {
            self::assertSame([self::ADMIN, self::TAGS, self::POSTS], $this->affected([$file]), $file);
        }
    }

    public function testAnyServiceProviderWidensToAll(): void
    {
        self::assertSame([self::ADMIN, self::TAGS, self::POSTS], $this->affected(['app/Providers/AppServiceProvider.php']));
    }

    public function testDeletedPhpFileWidensToAll(): void
    {
        self::assertSame([self::ADMIN, self::TAGS, self::POSTS], $this->affected(['app/Policies/TagPolicy.php']));
    }

    public function testChangedFileThatFailedToParseWidensToAll(): void
    {
        self::assertSame([self::ADMIN, self::TAGS, self::POSTS], $this->affected(['app/Broken.php'], [new ParseFailure('app/Broken.php', 'Syntax error', 3)]));
    }

    public function testUnrelatedChangeAffectsNothing(): void
    {
        self::assertSame([], $this->affected(['app/Services/Unrelated.php', 'README.md', 'config/app.php', 'composer.lock', 'vendor/acme/lib/Gone.php', 'resources/views/post.blade.php', '.github/workflows/ci.yml']));
        self::assertSame([], $this->affected([]));
    }

    public function testConfigAuthWidensToAll(): void
    {
        self::assertSame([self::ADMIN, self::TAGS, self::POSTS], $this->affected(['config/auth.php']));
    }

    public function testUntypedServiceCallReachesTheService(): void
    {
        self::assertSame(['GET /notes/{id}'], $this->unresolved(['app/Services/NoteService.php']));
    }

    public function testOverridingSubclassIsReachable(): void
    {
        self::assertSame(['GET /reports/{id}'], $this->unresolved(['app/Repos/ChildRepo.php']));
    }

    public function testDepthLimitLooksOneLevelDeeper(): void
    {
        self::assertSame(['GET /deep/{id}'], $this->unresolved(['app/Deep/S4.php']));
    }

    public function testUnresolvedFixtureLeavesUnrelatedOut(): void
    {
        self::assertSame([], $this->unresolved(['app/Services/Unrelated.php']));
    }

    public function testDotSlashPathsNormalised(): void
    {
        self::assertSame([self::TAGS], $this->affected(['./app/Models/Tag.php']));
    }

    private const UNRESOLVED = [
        'routes/web.php' => <<<'PHP'
            <?php

            use App\Http\Controllers\NoteController;
            use App\Http\Controllers\ReportController;
            use App\Http\Controllers\DeepController;
            use Illuminate\Support\Facades\Route;

            Route::get('notes/{id}', [NoteController::class, 'show']);
            Route::get('reports/{id}', [ReportController::class, 'show']);
            Route::get('deep/{id}', [DeepController::class, 'show']);
            PHP,
        'app/Models/Note.php' => '<?php namespace App\Models; class Note extends \Illuminate\Database\Eloquent\Model { }',
        'app/Http/Controllers/NoteController.php' => <<<'PHP'
            <?php
            namespace App\Http\Controllers;

            class NoteController
            {
                private $service;

                public function show(int $id)
                {
                    return $this->service->find($id);
                }
            }
            PHP,
        'app/Services/NoteService.php' => <<<'PHP'
            <?php
            namespace App\Services;

            class NoteService
            {
                public function find(int $id)
                {
                    return \App\Models\Note::query()->whereKey($id)->first();
                }
            }
            PHP,
        'app/Http/Controllers/ReportController.php' => <<<'PHP'
            <?php
            namespace App\Http\Controllers;

            use App\Repos\BaseRepo;

            class ReportController
            {
                public function __construct(private BaseRepo $repo)
                {
                }

                public function show(int $id)
                {
                    return $this->repo->load($id);
                }
            }
            PHP,
        'app/Repos/BaseRepo.php' => <<<'PHP'
            <?php
            namespace App\Repos;

            class BaseRepo
            {
                public function load(int $id)
                {
                    return \App\Models\Note::query()->findOrFail($id);
                }
            }
            PHP,
        'app/Repos/ChildRepo.php' => <<<'PHP'
            <?php
            namespace App\Repos;

            class ChildRepo extends BaseRepo
            {
                public function load(int $id)
                {
                    return \App\Models\Note::query()->find($id);
                }
            }
            PHP,
        'app/Http/Controllers/DeepController.php' => <<<'PHP'
            <?php
            namespace App\Http\Controllers;

            use App\Deep\S1;

            class DeepController
            {
                public function __construct(private S1 $s1)
                {
                }

                public function show(int $id)
                {
                    return $this->s1->one($id);
                }
            }
            PHP,
        'app/Deep/S1.php' => '<?php namespace App\Deep; class S1 { public function __construct(private S2 $s2) { } public function one(int $id) { return $this->s2->two($id); } }',
        'app/Deep/S2.php' => '<?php namespace App\Deep; class S2 { public function __construct(private S3 $s3) { } public function two(int $id) { return $this->s3->three($id); } }',
        'app/Deep/S3.php' => '<?php namespace App\Deep; class S3 { public function __construct(private S4 $s4) { } public function three(int $id) { return $this->s4->fourDeep($id); } }',
        'app/Deep/S4.php' => '<?php namespace App\Deep; class S4 { public function fourDeep(int $id) { return \App\Models\Note::query()->find($id); } }',
        'app/Services/Unrelated.php' => '<?php namespace App\Services; class Unrelated { public function run(): int { return 1; } }',
    ];

    /**
     * @param  list<string>  $changed
     * @return list<string> affected route keys over the unresolved-call fixture, sorted
     */
    private function unresolved(array $changed): array
    {
        return $this->affected($changed, [], self::UNRESOLVED, ['GET /deep/{id}', 'GET /notes/{id}', 'GET /reports/{id}']);
    }

    /**
     * @param  list<string>  $changed
     * @param  list<ParseFailure>  $failures
     * @param  array<string, string>|null  $fixture  path => code; null is FILES
     * @param  list<string>|null  $expected  the fixture's sorted candidate keys
     * @return list<string> the affected candidates' route keys, sorted
     */
    private function affected(array $changed, array $failures = [], ?array $fixture = null, ?array $expected = null): array
    {
        $files = [];
        foreach ($fixture ?? self::FILES as $path => $code) {
            $files[] = (new AstGenerator())->parse(new SourceFile($path, '/nonexistent/'.$path, $code));
        }
        $parsed = new ParseResult($files, $failures);
        $symbols = (new SymbolTableBuilder())->build($parsed);
        $config = new Config('/nonexistent', 'anthropic', null, null, null, 5, null, 20000, 3, Severity::High, Confidence::Medium, [], [], [], Config::DEFAULT_SENSITIVE_FIELDS, [], []);
        $framework = new DetectedFramework('laravel', 10);
        $context = new LaravelContext();
        $map = $context->buildAuthorizationMap($parsed, $symbols, $config, $framework);
        [$candidates] = $context->candidateSelector($parsed, $symbols, $config, $framework)->select($map, true);
        $keys = array_map(static fn (Candidate $c): string => $c->route->key(), $candidates);
        sort($keys);
        self::assertSame($expected ?? [self::ADMIN, self::TAGS, self::POSTS], $keys, 'fixture candidates');

        $affected = array_map(static fn (Candidate $c): string => $c->route->key(), (new ImpactAnalyzer($parsed, $symbols, $config))->affected($candidates, $changed));
        sort($affected);

        return $affected;
    }
}
