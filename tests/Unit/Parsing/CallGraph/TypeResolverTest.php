<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Parsing\CallGraph;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use PhpParser\NodeFinder;
use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Parsing\AstGenerator;
use TusharKhan\SemanticSec\Parsing\CallGraph\PathNode;
use TusharKhan\SemanticSec\Parsing\CallGraph\TypeResolver;
use TusharKhan\SemanticSec\Parsing\FileFinder;
use TusharKhan\SemanticSec\Parsing\ParseResult;
use TusharKhan\SemanticSec\Parsing\ProjectParser;
use TusharKhan\SemanticSec\Parsing\SourceFile;
use TusharKhan\SemanticSec\Parsing\Symbols\RelationResolver;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTableBuilder;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;

final class TypeResolverTest extends TestCase
{
    private const CONTROLLER = 'App\Http\Controllers\InvoiceController';

    private const FILES = [
        'app/Models/User.php' => <<<'PHP'
            <?php
            namespace App\Models;

            /** @property-read Profile $profile */
            class User extends \Illuminate\Foundation\Auth\User
            {
                public function invoices() { return $this->hasMany(Invoice::class); }
                public function account() { return $this->hasOne(Account::class); }
            }
            PHP,
        'app/Models/Invoice.php' => <<<'PHP'
            <?php
            namespace App\Models;

            class Invoice extends \Illuminate\Database\Eloquent\Model
            {
                public function scopePaid($query) { return $query->where('paid', true); }
            }
            PHP,
        'app/Models/Account.php' => '<?php namespace App\Models; class Account extends \Illuminate\Database\Eloquent\Model {}',
        'app/Models/Profile.php' => '<?php namespace App\Models; class Profile extends \Illuminate\Database\Eloquent\Model {}',
        'app/Services/Plain.php' => '<?php namespace App\Services; class Plain {}',
        'app/Services/Repo.php' => '<?php namespace App\Services; class Repo {}',
        'app/Services/Mailer.php' => '<?php namespace App\Services; interface Mailer {}',
        'app/Services/Billing.php' => <<<'PHP'
            <?php
            namespace App\Services;

            use App\Models\Account;
            use App\Models\Invoice;

            /** @method Account primary() */
            class Billing
            {
                public function invoice(int $id): Invoice { return Invoice::findOrFail($id); }
                public function total(): int { return 1; }
                public static function instance(): self { return new self(); }
            }
            PHP,
        'app/Http/Controllers/InvoiceController.php' => <<<'PHP'
            <?php
            namespace App\Http\Controllers;

            use App\Models\Invoice;
            use App\Services\Billing;
            use App\Services\Mailer;
            use App\Services\Plain;
            use App\Services\Repo;
            use Illuminate\Http\Request;
            use Illuminate\Support\Facades\App;
            use Illuminate\Support\Facades\Auth;
            use Illuminate\Support\Facades\Cache;
            use Illuminate\Support\Facades\DB;
            use Illuminate\Support\Facades\Validator;

            /** @property \App\Models\Account $extra */
            class InvoiceController
            {
                private $repo;

                /** @var Mailer */
                protected $mailer;

                public function __construct(private Billing $billing, Repo $repo)
                {
                    $this->repo = $repo;
                }

                public function thisRef() { return $this; }
                public function promoted() { return $this->billing; }
                public function ctorAssigned() { return $this->repo; }
                public function docVarProperty() { return $this->mailer; }
                public function classDocProperty() { return $this->extra; }
                public function param(Invoice $invoice) { return $invoice; }
                public function newVar() { $x = new Billing(); return $x; }
                public function newDirect() { return new Repo(); }
                public function findVar($id) { $i = Invoice::findOrFail($id); return $i; }
                public function whereFirstVar() { $i = Invoice::where('a', 1)->latest()->first(); return $i; }
                public function queryScopeFirst() { return Invoice::query()->paid()->whereKey(1)->firstOrFail(); }
                public function appVar() { $b = app(Billing::class); return $b; }
                public function resolveVar() { $b = resolve(Billing::class); return $b; }
                public function appMake() { return App::make(Billing::class); }
                public function docVarLocal() { /** @var Billing $b */ $b = $this->container->get('billing'); return $b; }
                public function authHelper() { return auth()->user(); }
                public function authRequest(Request $request) { return $request->user(); }
                public function authFacade() { return Auth::user(); }
                public function authRequestHelper() { return request()->user(); }
                public function authVar() { $u = auth()->user(); return $u; }
                public function relationProperty(Request $request) { return $request->user()->account; }
                public function relationDocProperty() { return auth()->user()->profile; }
                public function relationCall() { return auth()->user()->invoices(); }
                public function relationFirst() { return auth()->user()->invoices()->where('x', 1)->first(); }
                public function methodReturn() { return $this->billing->invoice(1); }
                public function methodReturnVar() { $i = $this->billing->invoice(1); return $i; }
                public function docMethod() { return $this->billing->primary(); }
                public function staticReturn() { return Billing::instance(); }
                public function finderMake() { return Invoice::make([]); }
                public function finderCreate() { return Invoice::create([]); }
                public function finderFirstOrCreate() { return Invoice::firstOrCreate([]); }
                public function finderUpdateOrCreate() { return Invoice::updateOrCreate([], []); }
                public function finderFind() { return Invoice::find(1); }
                public function finderFirst() { return Invoice::first(); }
                public function agreeingIf($c) { $x = new Billing(); if ($c) { $x = new Billing(); } return $x; }
                public function closureThis() { return function () { return $this; }; }

                public function collectionGet() { return Invoice::where('a', 1)->get(); }
                public function collectionAll() { return Invoice::all(); }
                public function collectionPaginate() { return Invoice::query()->paginate(); }
                public function findArray() { return Invoice::find([1, 2]); }
                public function pluckFirst() { return Invoice::where('a', 1)->pluck('id')->first(); }
                public function twoTypes() { $x = new Billing(); $x = new Repo(); return $x; }
                public function ifOnly($c) { if ($c) { $x = new Billing(); } return $x; }
                public function foreachTaint($xs) { $x = new Billing(); foreach ($xs as $x) {} return $x; }
                public function byRef() { $x = new Billing(); $y = &$x; return $x; }
                public function extractTaint($data) { $x = new Billing(); extract($data); return $x; }
                public function unknownMethod() { return $this->billing->nope(); }
                public function builtinReturn() { return $this->billing->total(); }
                public function unknownVar() { return $nothing; }
                public function untypedParam($thing) { return $thing; }
                public function nonModelFind() { return Plain::find(1); }
                public function facadeMake() { return Validator::make([], []); }
                public function facadeCache() { return Cache::get('k'); }
                public function facadeDb() { return DB::table('x'); }
                public function facadeGlobal() { return \Storage::disk('s3'); }
                public function facadeAuthGuard() { return Auth::guard('web'); }
            }
            PHP,
        'routes/web.php' => <<<'PHP'
            <?php
            use App\Models\Invoice;
            Route::get('/i/{invoice}', function (Invoice $invoice) { return $invoice; });
            Route::get('/this', function () { return $this; });
            PHP,
    ];

    private static ?SymbolTable $symbols = null;

    /** @var array<string, \TusharKhan\SemanticSec\Parsing\ParsedFile> */
    private static array $parsed = [];

    public function testThisIsTheCurrentClass(): void
    {
        self::assertSame(self::CONTROLLER, self::typeOfReturn('thisRef'));
    }

    public function testPromotedConstructorProperty(): void
    {
        self::assertSame('App\Services\Billing', self::typeOfReturn('promoted'));
    }

    public function testConstructorAssignedProperty(): void
    {
        self::assertSame('App\Services\Repo', self::typeOfReturn('ctorAssigned'));
    }

    public function testDocVarProperty(): void
    {
        self::assertSame('App\Services\Mailer', self::typeOfReturn('docVarProperty'));
    }

    public function testClassDocProperty(): void
    {
        self::assertSame('App\Models\Account', self::typeOfReturn('classDocProperty'));
    }

    public function testTypedParameter(): void
    {
        self::assertSame('App\Models\Invoice', self::typeOfReturn('param'));
    }

    public function testNewAssignedToVariable(): void
    {
        self::assertSame('App\Services\Billing', self::typeOfReturn('newVar'));
        self::assertSame('App\Services\Repo', self::typeOfReturn('newDirect'));
    }

    public function testStaticFinderAssignedToVariable(): void
    {
        self::assertSame('App\Models\Invoice', self::typeOfReturn('findVar'));
    }

    public function testWhereChainEndingInFirst(): void
    {
        self::assertSame('App\Models\Invoice', self::typeOfReturn('whereFirstVar'));
        self::assertSame('App\Models\Invoice', self::typeOfReturn('queryScopeFirst'));
    }

    public function testContainerResolution(): void
    {
        self::assertSame('App\Services\Billing', self::typeOfReturn('appVar'));
        self::assertSame('App\Services\Billing', self::typeOfReturn('resolveVar'));
        self::assertSame('App\Services\Billing', self::typeOfReturn('appMake'));
    }

    public function testLocalVarDocTag(): void
    {
        self::assertSame('App\Services\Billing', self::typeOfReturn('docVarLocal'));
    }

    public function testAuthUserExpressions(): void
    {
        foreach (['authHelper', 'authRequest', 'authFacade', 'authRequestHelper', 'authVar'] as $method) {
            self::assertSame('App\Models\User', self::typeOfReturn($method), $method);
        }
    }

    public function testAuthUserUnknownWithoutModel(): void
    {
        self::assertNull(self::typeOfReturn('authHelper', null));
    }

    public function testRelationPropertyAndCall(): void
    {
        self::assertSame('App\Models\Account', self::typeOfReturn('relationProperty'));
        self::assertSame('App\Models\Profile', self::typeOfReturn('relationDocProperty'));
        self::assertSame('App\Models\Invoice', self::typeOfReturn('relationCall'));
        self::assertSame('App\Models\Invoice', self::typeOfReturn('relationFirst'));
    }

    public function testMethodReturnType(): void
    {
        self::assertSame('App\Models\Invoice', self::typeOfReturn('methodReturn'));
        self::assertSame('App\Models\Invoice', self::typeOfReturn('methodReturnVar'));
        self::assertSame('App\Models\Account', self::typeOfReturn('docMethod'));
        self::assertSame('App\Services\Billing', self::typeOfReturn('staticReturn'));
    }

    public function testEloquentStaticFinders(): void
    {
        foreach (['finderMake', 'finderCreate', 'finderFirstOrCreate', 'finderUpdateOrCreate', 'finderFind', 'finderFirst'] as $method) {
            self::assertSame('App\Models\Invoice', self::typeOfReturn($method), $method);
        }
    }

    public function testAgreeingConditionalReassignmentKeepsType(): void
    {
        self::assertSame('App\Services\Billing', self::typeOfReturn('agreeingIf'));
    }

    public function testClosureThisIsTheEnclosingClassWhenKnown(): void
    {
        $method = self::symbols()->findMethod(self::CONTROLLER, 'closureThis');
        self::assertNotNull($method);
        $closure = (new NodeFinder())->findFirstInstanceOf($method->node->stmts ?? [], Expr\Closure::class);
        self::assertInstanceOf(Expr\Closure::class, $closure);
        $expr = self::lastReturn($closure->stmts);
        $known = new PathNode('closure@x:1', null, $closure, 'x', 1, 1, 1, null, null, self::CONTROLLER);
        $unknown = new PathNode('closure@x:1', null, $closure, 'x', 1, 1, 1, null, null);
        self::assertSame(self::CONTROLLER, self::resolver()->typeOf($expr, $known));
        self::assertNull(self::resolver()->typeOf($expr, $unknown));
    }

    public function testRouteClosureParameter(): void
    {
        $closures = (new NodeFinder())->findInstanceOf(self::parsed('routes/web.php'), Expr\Closure::class);
        self::assertCount(2, $closures);
        $types = [];
        foreach ($closures as $closure) {
            $node = new PathNode('closure@routes/web.php:'.$closure->getStartLine(), null, $closure, 'routes/web.php', $closure->getStartLine(), $closure->getEndLine(), 0, null, null);
            $types[] = self::resolver()->typeOf(self::lastReturn($closure->stmts), $node);
        }
        self::assertSame(['App\Models\Invoice', null], $types);
    }

    public function testCollectionCallsAreNull(): void
    {
        foreach (['collectionGet', 'collectionAll', 'collectionPaginate', 'findArray', 'pluckFirst'] as $method) {
            self::assertNull(self::typeOfReturn($method), $method);
        }
    }

    public function testVariableReassignedFromTwoTypesIsNull(): void
    {
        self::assertNull(self::typeOfReturn('twoTypes'));
    }

    public function testVariableAssignedOnlyInsideIfIsNull(): void
    {
        self::assertNull(self::typeOfReturn('ifOnly'));
    }

    public function testTaintedVariablesAreNull(): void
    {
        foreach (['foreachTaint', 'byRef', 'extractTaint', 'unknownVar', 'untypedParam'] as $method) {
            self::assertNull(self::typeOfReturn($method), $method);
        }
    }

    public function testUnknownMethodIsNull(): void
    {
        self::assertNull(self::typeOfReturn('unknownMethod'));
        self::assertNull(self::typeOfReturn('builtinReturn'));
    }

    public function testNonModelFindIsNull(): void
    {
        self::assertNull(self::typeOfReturn('nonModelFind'));
    }

    public function testFacadeStaticCallIsNotTypedAsTheFacade(): void
    {
        foreach (['facadeMake', 'facadeCache', 'facadeDb', 'facadeGlobal', 'facadeAuthGuard'] as $method) {
            self::assertNull(self::typeOfReturn($method), $method);
        }
    }

    public function testBenchmarkDownloadControllerProperty(): void
    {
        $root = BenchmarkCorpus::root().'/laravel11-app';
        $parsed = (new ProjectParser(new FileFinder(), new AstGenerator()))->parse($root);
        $symbols = (new SymbolTableBuilder())->build($parsed);
        $resolver = new TypeResolver($symbols, new RelationResolver($symbols), 'App\Models\User');
        foreach (['Vuln' => 'App\Services\DownloadService', 'Safe' => 'App\Services\DownloadRepository'] as $ns => $service) {
            $method = $symbols->findMethod('App\Http\Controllers\\'.$ns.'\DownloadController', 'show');
            self::assertNotNull($method);
            $node = new PathNode($method->id(), $method, null, $method->file, $method->startLine, $method->endLine, 0, null, null);
            $fetch = (new NodeFinder())->findFirstInstanceOf($method->node->stmts ?? [], Expr\PropertyFetch::class);
            self::assertInstanceOf(Expr\PropertyFetch::class, $fetch);
            self::assertSame($service, $resolver->typeOf($fetch, $node), $ns);
            $download = self::lastVariable($method->node->stmts ?? [], 'download');
            self::assertSame('App\Models\Download', $resolver->typeOf($download, $node), $ns);
        }
    }

    private static function typeOfReturn(string $method, ?string $authUser = 'App\Models\User'): ?string
    {
        $symbol = self::symbols()->findMethod(self::CONTROLLER, $method);
        self::assertNotNull($symbol, $method);
        $node = new PathNode($symbol->id(), $symbol, null, $symbol->file, $symbol->startLine, $symbol->endLine, 0, null, null);

        return (new TypeResolver(self::symbols(), new RelationResolver(self::symbols()), $authUser))->typeOf(self::lastReturn($symbol->node->stmts ?? []), $node);
    }

    private static function resolver(): TypeResolver
    {
        return new TypeResolver(self::symbols(), new RelationResolver(self::symbols()), 'App\Models\User');
    }

    /** @param array<Node> $stmts */
    private static function lastReturn(array $stmts): Expr
    {
        $last = $stmts[count($stmts) - 1] ?? null;
        self::assertInstanceOf(Stmt\Return_::class, $last);
        self::assertNotNull($last->expr);

        return $last->expr;
    }

    /** @param array<Node> $stmts */
    private static function lastVariable(array $stmts, string $name): Expr\Variable
    {
        $vars = (new NodeFinder())->find($stmts, static fn (Node $n): bool => $n instanceof Expr\Variable && $n->name === $name);
        $var = $vars[count($vars) - 1] ?? null;
        self::assertInstanceOf(Expr\Variable::class, $var);

        return $var;
    }

    /** @return array<Stmt> */
    private static function parsed(string $path): array
    {
        self::symbols();

        return self::$parsed[$path]->ast;
    }

    private static function symbols(): SymbolTable
    {
        if (self::$symbols === null) {
            $files = [];
            foreach (self::FILES as $path => $code) {
                $files[] = self::$parsed[$path] = (new AstGenerator())->parse(new SourceFile($path, '/nonexistent/'.$path, $code));
            }
            self::$symbols = (new SymbolTableBuilder())->build(new ParseResult($files, []));
        }

        return self::$symbols;
    }
}
