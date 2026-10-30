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
                public function owner() { return $this->belongsTo(User::class); }
                public function lines() { return $this->morphMany(Account::class, 'x'); }
                public function tags() { return $this->belongsToMany(Profile::class); }
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
        'app/Services/Fluent.php' => <<<'PHP'
            <?php
            namespace App\Services;

            class Fluent
            {
                public function fluent(): static { return $this; }
                public function me(): self { return $this; }
                public function maybeMe(): ?self { return $this; }
                /** @return $this */
                public function docThis() { return $this; }
                /** @return static */
                public function docStatic() { return $this; }
                /** @return self */
                public function docSelf() { return $this; }
                public static function make(): static { return new static(); }
                public function plain(): Repo { return new Repo(); }
            }
            PHP,
        'app/Services/FluentChild.php' => <<<'PHP'
            <?php
            namespace App\Services;

            class FluentChild extends Fluent
            {
                public function viaSelf() { return self::plain(); }
                public function viaParent() { return parent::plain(); }
                public function selfFluent() { return self::fluent(); }
                public function selfMake() { return self::make(); }
            }
            PHP,
        'app/Services/Either.php' => <<<'PHP'
            <?php
            namespace App\Services;

            class Either
            {
                public function native(): Plain|Repo { return new Plain(); }
                public function nativeNull(): Plain|Repo|null { return null; }
                /** @return Plain|Repo */
                public function docUnion() { return new Plain(); }
                /** @return Plain|Repo|null */
                public function docUnionNull() { return null; }
                public function nullable(): ?Plain { return null; }
                /** @return Plain|null */
                public function docNullable() { return null; }
                public function scalarOr(): Plain|int { return 1; }
            }
            PHP,
        'app/Services/HelperTrait.php' => <<<'PHP'
            <?php
            namespace App\Services;

            trait HelperTrait
            {
                public function helper(): Plain { return new Plain(); }
                public function go() { return $this->helper(); }
                public function selfRef() { return $this; }
            }
            PHP,
        'app/Services/UsesHelper.php' => '<?php namespace App\Services; class UsesHelper { use HelperTrait; public function helper(): Repo { return new Repo(); } }',
        'app/Http/Controllers/InvoiceController.php' => <<<'PHP'
            <?php
            namespace App\Http\Controllers;

            use App\Models\Invoice;
            use App\Services\Billing;
            use App\Services\Either;
            use App\Services\Fluent;
            use App\Services\FluentChild;
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
                public function findVar(int $id) { $i = Invoice::findOrFail($id); return $i; }
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

                public function loopWhile($c) { $x = new Billing(); while ($c) { $x->total(); $x = new Repo(); } return 1; }
                public function loopForeach($xs) { $x = new Billing(); foreach ($xs as $i) { $x->total(); $x = new Repo(); } return 1; }
                public function loopFor() { $x = new Billing(); for ($i = 0; $i < 3; $i++) { $x->total(); $x = new Repo(); } return 1; }
                public function loopDo($c) { $x = new Billing(); do { $x->total(); $x = new Repo(); } while ($c); return 1; }
                public function loopNested($c) { $x = new Billing(); while ($c) { if ($c) { $x->total(); } while ($c) { $x = new Repo(); } } return 1; }
                public function loopFresh($c) { while ($c) { $x = new Billing(); $x->total(); } return 1; }

                public function staticReturnChild() { return (new FluentChild())->fluent(); }
                public function selfReturnChild() { return (new FluentChild())->me(); }
                public function nullableSelfReturnChild() { return (new FluentChild())->maybeMe(); }
                public function selfReturnSame() { return (new Fluent())->me(); }
                public function docThisChild() { return (new FluentChild())->docThis(); }
                public function docStaticChild() { return (new FluentChild())->docStatic(); }
                public function docSelfChild() { return (new FluentChild())->docSelf(); }
                public function docSelfSame() { return (new Fluent())->docSelf(); }
                public function staticMakeChild() { return FluentChild::make(); }
                public function staticMakeBase() { return Fluent::make(); }

                public function unionNative() { return (new Either())->native(); }
                public function unionNativeNull() { return (new Either())->nativeNull(); }
                public function unionDoc() { return (new Either())->docUnion(); }
                public function unionDocNull() { return (new Either())->docUnionNull(); }
                public function nullableNative() { return (new Either())->nullable(); }
                public function nullableDoc() { return (new Either())->docNullable(); }
                public function unionScalar() { return (new Either())->scalarOr(); }

                public function toManyProperty() { return auth()->user()->invoices; }
                public function morphManyProperty(Invoice $i) { return $i->lines; }
                public function belongsToManyProperty(Invoice $i) { return $i->tags; }
                public function belongsToProperty(Invoice $i) { return $i->owner; }
                public function toOneCall(Invoice $i) { return $i->owner(); }
                public function relationFindOrFail(int $id) { return auth()->user()->invoices()->findOrFail($id); }

                public function findArrayParam(array $ids) { return Invoice::find($ids); }
                public function findOrFailArrayParam(array $ids) { return Invoice::findOrFail($ids); }
                public function findArrayVar() { $ids = [1, 2]; return Invoice::find($ids); }
                public function findArrayCast($ids) { return Invoice::find((array) $ids); }
                public function findRequestInput(Request $r) { return Invoice::find($r->input('ids')); }
                public function findUntyped($id) { return Invoice::find($id); }
                public function findUnionParam(int|array $id) { return Invoice::find($id); }
                public function findMixedParam(mixed $id) { return Invoice::find($id); }
                public function findIntParam(int $id) { return Invoice::find($id); }
                public function findStringParam(?string $id) { return Invoice::findOrFail($id); }
                public function findIntCast($id) { return Invoice::find((int) $id); }
                public function findIntVar($id) { $key = (int) $id; return Invoice::find($key); }
                public function findAuthId() { return Invoice::find(auth()->id()); }
                public function findWhereChain(array $ids) { return Invoice::where('a', 1)->find($ids); }

                public function guardHelper() { return auth('admin')->user(); }
                public function guardFacade() { return Auth::guard('admin')->user(); }
                public function guardChain() { return auth()->guard('admin')->user(); }
                public function guardRequest(Request $r) { return $r->user('admin'); }
                public function guardRequestHelper() { return request()->user('admin'); }
                public function guardOptional() { return optional(auth('admin')->user()); }
                public function guardDefaultFacade() { return Auth::guard()->user(); }
                public function guardDefaultChain() { return auth()->guard()->user(); }
                public function guardDefaultOptional() { return optional(auth()->user()); }
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
        self::assertSame('App\Models\Invoice', self::typeOfReturn('relationFirst'));
    }

    public function testLoopCarriedAssignmentsCount(): void
    {
        foreach (['loopWhile', 'loopForeach', 'loopFor', 'loopDo', 'loopNested'] as $method) {
            self::assertNull(self::typeOfVariable($method, 'x', 1), $method);
            self::assertSame('App\Services\Billing', self::typeOfVariable($method, 'x', 0), $method);
        }
        self::assertSame('App\Services\Billing', self::typeOfVariable('loopFresh', 'x', 1));
    }

    public function testThisInATraitMethodIsUnknown(): void
    {
        foreach (['go', 'selfRef'] as $name) {
            $method = self::symbols()->findMethod('App\Services\HelperTrait', $name);
            self::assertNotNull($method);
            $node = new PathNode($method->id(), $method, null, $method->file, 1, 1, 0, null, null);
            self::assertNull(self::resolver()->typeOf(self::lastReturn($method->node->stmts ?? []), $node), $name);
        }
    }

    public function testThisInATraitMethodUsesTheKnownUsingClass(): void
    {
        $method = self::symbols()->findMethod('App\Services\HelperTrait', 'go');
        self::assertNotNull($method);
        $node = new PathNode($method->id(), $method, null, $method->file, 1, 1, 0, null, null, 'App\Services\UsesHelper');
        self::assertSame('App\Services\Repo', self::resolver()->typeOf(self::lastReturn($method->node->stmts ?? []), $node));
    }

    public function testStaticAndThisReturnsGiveTheReceiver(): void
    {
        foreach (['staticReturnChild', 'docThisChild', 'docStaticChild', 'staticMakeChild'] as $method) {
            self::assertSame('App\Services\FluentChild', self::typeOfReturn($method), $method);
        }
        self::assertSame('App\Services\Fluent', self::typeOfReturn('staticMakeBase'));
    }

    public function testSelfReturnIsTheDeclaringClassOnlyForThatReceiver(): void
    {
        foreach (['selfReturnChild', 'nullableSelfReturnChild', 'docSelfChild'] as $method) {
            self::assertNull(self::typeOfReturn($method), $method);
        }
        self::assertSame('App\Services\Fluent', self::typeOfReturn('selfReturnSame'));
        self::assertSame('App\Services\Fluent', self::typeOfReturn('docSelfSame'));
    }

    public function testSelfAndParentCallsToInstanceMethods(): void
    {
        self::assertSame('App\Services\Repo', self::typeOfReturn('viaSelf', class: 'App\Services\FluentChild'));
        self::assertSame('App\Services\Repo', self::typeOfReturn('viaParent', class: 'App\Services\FluentChild'));
        self::assertNull(self::typeOfReturn('selfFluent', class: 'App\Services\FluentChild'));
        self::assertNull(self::typeOfReturn('selfMake', class: 'App\Services\FluentChild'));
    }

    public function testUnionReturnsWithTwoClassesAreNull(): void
    {
        foreach (['unionNative', 'unionNativeNull', 'unionDoc', 'unionDocNull'] as $method) {
            self::assertNull(self::typeOfReturn($method), $method);
        }
        foreach (['nullableNative', 'nullableDoc', 'unionScalar'] as $method) {
            self::assertSame('App\Services\Plain', self::typeOfReturn($method), $method);
        }
    }

    public function testToManyRelationsAndRelationCallsAreNotModels(): void
    {
        foreach (['toManyProperty', 'morphManyProperty', 'belongsToManyProperty', 'relationCall', 'toOneCall'] as $method) {
            self::assertNull(self::typeOfReturn($method), $method);
        }
        self::assertSame('App\Models\User', self::typeOfReturn('belongsToProperty'));
        self::assertSame('App\Models\Invoice', self::typeOfReturn('relationFindOrFail'));
    }

    public function testFindWithANonScalarArgumentIsNull(): void
    {
        foreach (['findArrayParam', 'findOrFailArrayParam', 'findArrayVar', 'findArrayCast', 'findRequestInput', 'findUntyped', 'findUnionParam', 'findMixedParam', 'findWhereChain'] as $method) {
            self::assertNull(self::typeOfReturn($method), $method);
        }
        foreach (['findIntParam', 'findStringParam', 'findIntCast', 'findIntVar', 'findAuthId'] as $method) {
            self::assertSame('App\Models\Invoice', self::typeOfReturn($method), $method);
        }
    }

    public function testNamedGuardsAreNotTheAuthUserModel(): void
    {
        foreach (['guardHelper', 'guardFacade', 'guardChain', 'guardRequest', 'guardRequestHelper', 'guardOptional'] as $method) {
            self::assertNull(self::typeOfReturn($method), $method);
        }
        foreach (['guardDefaultFacade', 'guardDefaultChain', 'guardDefaultOptional'] as $method) {
            self::assertSame('App\Models\User', self::typeOfReturn($method), $method);
        }
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

    private static function typeOfVariable(string $method, string $name, int $index): ?string
    {
        $symbol = self::symbols()->findMethod(self::CONTROLLER, $method);
        self::assertNotNull($symbol, $method);
        $node = new PathNode($symbol->id(), $symbol, null, $symbol->file, $symbol->startLine, $symbol->endLine, 0, null, null);
        $reads = (new NodeFinder())->find($symbol->node->stmts ?? [], static fn (Node $n): bool => $n instanceof Expr\MethodCall && $n->var instanceof Expr\Variable && $n->var->name === $name);
        self::assertInstanceOf(Expr\MethodCall::class, $reads[0] ?? null, $method);
        $assign = (new NodeFinder())->findFirst($symbol->node->stmts ?? [], static fn (Node $n): bool => $n instanceof Expr\Assign && $n->var instanceof Expr\Variable && $n->var->name === $name);
        self::assertInstanceOf(Expr\Assign::class, $assign);

        // index 0: the first assigned value; index 1: the read inside the loop
        return self::resolver()->typeOf($index === 0 ? $assign->expr : $reads[0]->var, $node);
    }

    private static function typeOfReturn(string $method, ?string $authUser = 'App\Models\User', string $class = self::CONTROLLER): ?string
    {
        $symbol = self::symbols()->findMethod($class, $method);
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
