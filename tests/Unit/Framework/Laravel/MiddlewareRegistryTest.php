<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Framework\Laravel;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Framework\DetectedFramework;
use TusharKhan\SemanticSec\Framework\Laravel\ConstantEvaluator;
use TusharKhan\SemanticSec\Framework\Laravel\MiddlewareKind;
use TusharKhan\SemanticSec\Framework\Laravel\MiddlewareRegistry;
use TusharKhan\SemanticSec\Parsing\AstGenerator;
use TusharKhan\SemanticSec\Parsing\FileFinder;
use TusharKhan\SemanticSec\Parsing\ParseResult;
use TusharKhan\SemanticSec\Parsing\ProjectParser;
use TusharKhan\SemanticSec\Parsing\SourceFile;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTableBuilder;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;

final class MiddlewareRegistryTest extends TestCase
{
    /**
     * @param  array<string, string>  $files  path => php code
     * @return array{0: ParseResult, 1: SymbolTable}
     */
    private function project(array $files): array
    {
        $parsed = [];
        foreach ($files as $path => $code) {
            $parsed[] = (new AstGenerator())->parse(new SourceFile($path, '/nonexistent/'.$path, $code));
        }
        $result = new ParseResult($parsed, []);

        return [$result, (new SymbolTableBuilder())->build($result)];
    }

    /**
     * @param  array<string, string>  $files
     * @return array{0: MiddlewareRegistry, 1: list<string>}
     */
    private function registry(array $files, int $major = 11): array
    {
        [$result, $symbols] = $this->project($files);

        return MiddlewareRegistry::fromProject($result, $symbols, new DetectedFramework('laravel', $major), new ConstantEvaluator());
    }

    private function empty(): MiddlewareRegistry
    {
        return new MiddlewareRegistry(MiddlewareRegistry::DEFAULT_ALIASES, MiddlewareRegistry::DEFAULT_GROUPS, new SymbolTable([]));
    }

    public function testDefaultAliasesCanonicaliseClassForms(): void
    {
        $r = $this->empty();
        self::assertSame('can:view,invoice', $r->canonical('Illuminate\Auth\Middleware\Authorize:view,invoice'));
        self::assertSame('can:view,invoice', $r->canonical('\Illuminate\Auth\Middleware\Authorize:view,invoice'));
        self::assertSame('auth', $r->canonical('Illuminate\Auth\Middleware\Authenticate'));
        self::assertSame('auth:web', $r->canonical('auth:web'));
        self::assertSame('Some\Unknown:x', $r->canonical('Some\Unknown:x'));
    }

    public function testClassAndSubclassMiddlewareNormaliseToAliases(): void
    {
        [$result, $symbols] = $this->project([
            'app/Http/Middleware/Authenticate.php' => '<?php namespace App\Http\Middleware; class Authenticate extends \Illuminate\Auth\Middleware\Authenticate {}',
        ]);
        $r = new MiddlewareRegistry(MiddlewareRegistry::DEFAULT_ALIASES, [], $symbols);
        self::assertSame('auth:sanctum', $r->canonical('App\Http\Middleware\Authenticate:sanctum'));
    }

    public function testKernelAliasesAndGroupsAreRead(): void
    {
        $root = BenchmarkCorpus::root().'/laravel10-app';
        $parsed = (new ProjectParser(new FileFinder(), new AstGenerator()))->parse($root);
        $symbols = (new SymbolTableBuilder())->build($parsed);
        [$r, $warnings] = MiddlewareRegistry::fromProject($parsed, $symbols, new DetectedFramework('laravel', 10), new ConstantEvaluator());

        self::assertSame([], $warnings);
        self::assertSame('can:x', $r->canonical('Illuminate\Auth\Middleware\Authorize:x'));
        self::assertSame('Illuminate\Routing\Middleware\SubstituteBindings', $r->expand(['api'])[1]);
        self::assertContains('throttle:api', $r->expand(['api']));
        self::assertContains('Illuminate\Session\Middleware\StartSession', $r->expand(['web']));
    }

    public function testKernelRouteMiddlewareAndConstConcat(): void
    {
        [$r, $w] = $this->registry([
            'app/Http/Kernel.php' => '<?php namespace App\Http; use Illuminate\Foundation\Http\Kernel as K; class Kernel extends K {
                protected $routeMiddleware = ["owner" => \App\Mw\Owner::class, "dyn" => foo()];
                protected $middlewareGroups = ["admin" => ["auth", \App\Mw\Owner::class.":x"]];
            }',
        ], 10);
        self::assertSame('owner:x', $r->canonical('App\Mw\Owner:x'));
        self::assertSame(['auth', 'owner:x'], $r->expand(['admin']));
        self::assertSame(['app/Http/Kernel.php:2: middleware entry could not be resolved'], $w);
    }

    public function testKernelFoundThroughIntermediateParent(): void
    {
        [$r] = $this->registry([
            'app/Base.php' => '<?php namespace App; class Base extends \Illuminate\Foundation\Http\Kernel {}',
            'app/Http/Kernel.php' => '<?php namespace App\Http; class Kernel extends \App\Base { protected $middlewareAliases = ["owner" => \App\Mw\Owner::class]; }',
        ], 10);
        self::assertSame('owner', $r->canonical('App\Mw\Owner'));
    }

    public function testBootstrapWithMiddlewareIsRead(): void
    {
        [$r, $w] = $this->registry([
            'bootstrap/app.php' => '<?php return Application::configure(basePath: "x")->withMiddleware(function (Middleware $middleware) {
                $middleware->alias(["owner" => \App\Http\Middleware\EnsureOwner::class]);
                $middleware->group("admin", ["auth", "can:admin"]);
            })->create();',
        ]);
        self::assertSame([], $w);
        self::assertSame(['auth', 'can:admin'], $r->expand(['admin']));
        self::assertSame('owner', $r->canonical('App\Http\Middleware\EnsureOwner'));
    }

    public function testBootstrapAcceptsArrowFnOtherVarAndGroupAppends(): void
    {
        [$r, $w] = $this->registry([
            'bootstrap/app.php' => '<?php return Application::configure(basePath: "x")->withMiddleware(function ($m) {
                $m->trustProxies(at: "*");
                $m->web(append: ["a"], prepend: ["p"]);
                $m->api(["b"]);
                $m->appendToGroup("web", "c");
                $m->prependToGroup("api", ["z"]);
                $m->alias(["k" => foo()]);
            })->create();',
        ]);
        self::assertSame(['p', 'a', 'c'], $r->expand(['web']));
        self::assertSame(['z', 'b'], $r->expand(['api']));
        self::assertSame(['bootstrap/app.php:7: middleware entry could not be resolved'], $w);

        [$r2] = $this->registry([
            'bootstrap/app.php' => '<?php return A::configure()->withMiddleware(fn ($mw) => $mw->alias(["q" => \App\Q::class]))->create();',
        ]);
        self::assertSame('q', $r2->canonical('App\Q'));
    }

    public function testExpandIsCycleSafe(): void
    {
        $r = new MiddlewareRegistry([], ['a' => ['b'], 'b' => ['a', 'auth']], new SymbolTable([]));
        self::assertSame(['auth'], $r->expand(['a']));
        self::assertSame(['auth'], $r->expand(['a', 'b', 'auth']));
    }

    public function testNestedGroupsExpandAndCanonicalise(): void
    {
        $r = new MiddlewareRegistry(MiddlewareRegistry::DEFAULT_ALIASES, ['outer' => ['inner', 'Illuminate\Auth\Middleware\Authorize:x'], 'inner' => ['guest']], new SymbolTable([]));
        self::assertSame(['guest', 'can:x'], $r->expand(['outer']));
    }

    public function testKindAndAbility(): void
    {
        $r = $this->empty();
        self::assertSame(MiddlewareKind::Authentication, $r->kind('auth:sanctum'));
        self::assertSame(MiddlewareKind::Authentication, $r->kind('verified'));
        self::assertSame(MiddlewareKind::Authentication, $r->kind('signed'));
        self::assertSame(MiddlewareKind::Ability, $r->kind('can:update,post'));
        self::assertSame(MiddlewareKind::Other, $r->kind('throttle:60,1'));
        self::assertSame(MiddlewareKind::Other, $r->kind('authx'));
        self::assertSame(['ability' => 'update', 'arguments' => ['post']], $r->ability('can:update,post'));
        self::assertNull($r->ability('auth'));
    }

    public function testLaravel11BenchmarkHasDefaults(): void
    {
        $parsed = (new ProjectParser(new FileFinder(), new AstGenerator()))->parse(BenchmarkCorpus::root().'/laravel11-app');
        $symbols = (new SymbolTableBuilder())->build($parsed);
        [$r, $w] = MiddlewareRegistry::fromProject($parsed, $symbols, new DetectedFramework('laravel', 11), new ConstantEvaluator());
        self::assertSame([], $w);
        self::assertSame('auth', $r->canonical('Illuminate\Auth\Middleware\Authenticate'));
        self::assertSame([], $r->expand(['web']));
    }

    /** @return array<string, string> */
    private function subclasses(): array
    {
        return [
            'app/Owner.php' => '<?php namespace App\Http\Middleware; class EnsureOwner extends \Illuminate\Auth\Middleware\Authorize {}',
            'app/ApiAuth.php' => '<?php namespace App\Http\Middleware; class ApiAuth extends \Illuminate\Auth\Middleware\Authenticate {}',
            'app/Authenticate.php' => '<?php namespace App\Http\Middleware; class Authenticate extends \Illuminate\Auth\Middleware\Authenticate {}',
        ];
    }

    /** @param array<string, string> $aliases */
    private function withAliases(array $aliases): MiddlewareRegistry
    {
        [, $symbols] = $this->project($this->subclasses());

        return new MiddlewareRegistry($aliases + MiddlewareRegistry::DEFAULT_ALIASES, MiddlewareRegistry::DEFAULT_GROUPS, $symbols);
    }

    public function testAliasToAuthorizeSubclassIsAbility(): void
    {
        $r = $this->withAliases(['owner' => 'App\Http\Middleware\EnsureOwner']);
        self::assertSame(MiddlewareKind::Ability, $r->kind('owner:update,post'));
        self::assertSame(['ability' => 'update', 'arguments' => ['post']], $r->ability('owner:update,post'));
        self::assertSame(MiddlewareKind::Other, $r->kind('owner'));
        self::assertNull($r->ability('owner'));
    }

    public function testAliasToAuthenticateSubclassIsAuthentication(): void
    {
        $r = $this->withAliases(['api.auth' => 'App\Http\Middleware\ApiAuth']);
        self::assertSame(MiddlewareKind::Authentication, $r->kind('api.auth'));
    }

    public function testSameTargetAppAliasDoesNotShadowDefault(): void
    {
        $r = $this->withAliases(['admin.auth' => 'Illuminate\Auth\Middleware\Authenticate']);
        self::assertSame('auth', $r->canonical('Illuminate\Auth\Middleware\Authenticate'));
        self::assertSame('admin.auth', $r->canonical('admin.auth'));
    }

    public function testAppAuthOverrideStaysAuthentication(): void
    {
        $r = $this->withAliases(['auth' => 'App\Http\Middleware\Authenticate']);
        self::assertSame('auth:web', $r->canonical('App\Http\Middleware\Authenticate:web'));
        self::assertSame(MiddlewareKind::Authentication, $r->kind('auth:web'));
    }

    public function testBareCanIsOtherWithNoAbility(): void
    {
        self::assertSame(MiddlewareKind::Other, $this->empty()->kind('can'));
        self::assertNull($this->empty()->ability('can'));
    }
}
