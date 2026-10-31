<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Parsing\Symbols;

use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Param;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Stmt\ClassMethod;
use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Parsing\AstGenerator;
use TusharKhan\SemanticSec\Parsing\FileFinder;
use TusharKhan\SemanticSec\Parsing\ParsedFile;
use TusharKhan\SemanticSec\Parsing\ParseResult;
use TusharKhan\SemanticSec\Parsing\ProjectParser;
use TusharKhan\SemanticSec\Parsing\SourceFile;
use TusharKhan\SemanticSec\Parsing\SuppressionSet;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTableBuilder;

final class SymbolTableBuilderTest extends TestCase
{
    private string $root;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir().'/ss-st-'.bin2hex(random_bytes(6));
        mkdir($this->root.'/app', 0777, true);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->root.'/app/*') ?: [] as $f) {
            unlink($f);
        }
        rmdir($this->root.'/app');
        rmdir($this->root);
    }

    public function testIndexesClassesMethodsAndLines(): void
    {
        $table = $this->build(['C.php' => "<?php\nnamespace App\\Http;\n\nclass C\n{\n    public function show()\n    {\n    }\n}\n"]);

        $class = $table->getClass('App\Http\C');
        self::assertNotNull($class);
        self::assertSame('app/C.php', $class->file);
        self::assertSame('class', $class->kind);
        self::assertSame(4, $class->startLine);
        self::assertSame(9, $class->endLine);
        self::assertSame(6, $class->methods['show']->startLine);
        self::assertSame(8, $class->methods['show']->endLine);
        self::assertSame('App\Http\C::show', $class->methods['show']->id());
        self::assertCount(1, $table->classesInFile('app/C.php'));
    }

    public function testPromotedConstructorPropertyTypeIsResolved(): void
    {
        $table = $this->build(['C.php' => '<?php
namespace App\Http;
use App\Services\InvoiceService;
class C { public function __construct(private InvoiceService $invoices) {} }']);

        self::assertSame('App\Services\InvoiceService', $table->getClass('App\Http\C')?->properties['invoices']->type);
    }

    public function testDocblockVarUsedWhenNoNativeType(): void
    {
        $table = $this->build(['C.php' => '<?php
namespace App;
use App\Repos\Repo;
class C { /** @var Repo */ private $repo; }']);

        self::assertSame('App\Repos\Repo', $table->getClass('App\C')?->properties['repo']->type);
    }

    public function testNativeTypeWinsOverDocblock(): void
    {
        $table = $this->build(['C.php' => '<?php
namespace App;
use App\Repos\Repo;
class C { /** @var Repo */ private string $repo; 
  /** @param Repo $a @return Repo */ public function m(int $a): bool {} }']);

        $c = $table->getClass('App\C');
        self::assertSame('string', $c?->properties['repo']->type);
        self::assertSame('int', $c->methods['m']->params['a']);
        self::assertSame('bool', $c->methods['m']->returnType);
    }

    public function testNullableAndUnionParamTypes(): void
    {
        $table = $this->build(['C.php' => '<?php
namespace App;
use App\Models\Invoice;
class C { public function m(?Invoice $a, Invoice|int $b, int $c, $d) {} }']);

        $params = $table->getClass('App\C')?->methods['m']->params;
        self::assertSame(['a' => 'App\Models\Invoice', 'b' => 'App\Models\Invoice', 'c' => 'int', 'd' => null], $params);
        self::assertSame(['a', 'b', 'c', 'd'], array_keys($params));
    }

    public function testGenericDocblockKeepsBaseType(): void
    {
        $table = $this->build(['C.php' => '<?php
namespace App;
use Illuminate\Support\Collection;
use App\Models\Invoice;
class C {
    /** @return Collection<int, Invoice> */
    public function all() {}
    /** @return static */
    public function me() {}
    /** @return array{a: int} */
    public function shape() {}
    /** @return ?Invoice */
    public function one() {}
    /** @return null|\Other\Thing|int */
    public function u() {}
}']);

        $class = $table->getClass('App\C');
        self::assertNotNull($class);
        $m = $class->methods;
        self::assertSame('Illuminate\Support\Collection', $m['all']->returnType);
        self::assertSame('App\C', $m['me']->returnType);
        self::assertNull($m['shape']->returnType);
        self::assertSame('App\Models\Invoice', $m['one']->returnType);
        self::assertSame('Other\Thing', $m['u']->returnType);
    }

    public function testFindMethodWalksParentAndTraits(): void
    {
        $table = $this->build([
            'Base.php' => '<?php namespace App; class Base { public function baseMethod() {} }',
            'T.php' => '<?php namespace App; trait T { public function traitMethod() {} public static function st() {} }',
            'Child.php' => '<?php namespace App; class Child extends Base { use T; public function show() {} }',
        ]);

        self::assertSame('App\Base', $table->findMethod('App\Child', 'baseMethod')?->class);
        self::assertSame('App\T', $table->findMethod('App\Child', 'traitMethod')?->class);
        self::assertSame('App\Child', $table->findMethod('App\Child', 'SHOW')?->class);
        self::assertSame('show', $table->findMethod('App\Child', 'SHOW')->name);
        self::assertTrue($table->findMethod('App\Child', 'st')?->static);
        self::assertNull($table->findMethod('App\Child', 'nope'));
        self::assertNull($table->findMethod('App\Missing', 'show'));
        self::assertSame('App\Base', $table->getClass('App\Child')?->parent);
        self::assertSame(['App\T'], $table->getClass('App\Child')->traits);
    }

    public function testFindMethodSurvivesInheritanceCycle(): void
    {
        $table = $this->build([
            'A.php' => '<?php namespace App; class A extends B {}',
            'B.php' => '<?php namespace App; class B extends A {}',
        ]);

        self::assertNull($table->findMethod('App\A', 'x'));
    }

    public function testKindsDuplicatesAndAnonymousClasses(): void
    {
        $table = $this->build([
            'A.php' => '<?php namespace App; interface I {} enum E {} trait T {} class D {} $x = new class { public function f() {} };',
            'B.php' => '<?php namespace App; class D { public function second() {} }',
        ]);

        self::assertSame('interface', $table->getClass('App\I')?->kind);
        self::assertSame('enum', $table->getClass('App\E')?->kind);
        self::assertSame('trait', $table->getClass('App\T')?->kind);
        self::assertSame('app/A.php', $table->getClass('App\D')?->file);
        self::assertCount(0, $table->classesInFile('app/B.php'));
        self::assertCount(4, $table->all());
    }

    public function testDuplicateClassesAreReportedInDiscoveryOrder(): void
    {
        $table = $this->build([
            'A.php' => '<?php namespace App; class D {}',
            'B.php' => '<?php namespace App; class D {}',
        ]);

        self::assertSame(['App\D declared in app/A.php and app/B.php'], $table->duplicates());
        self::assertSame('app/A.php', $table->getClass('App\D')?->file);
    }

    public function testLegacyDocblockScalarsMapToBuiltins(): void
    {
        $table = $this->build(['C.php' => '<?php
namespace App;
class C {
    /** @var integer */ public $a;
    /** @var boolean */ public $b;
    /** @var double */ public $c;
    /** @var real */ public $d;
    /** @var long */ public $e;
    /** @var number */ public $f;
    /** @var callback */ public $g;
    /** @var Scalar */ public $h;
    /** @var resource */ public $i;
    /** @var numeric */ public $j;
}']);

        $types = array_map(static fn ($p) => $p->type, $table->getClass('App\C')->properties ?? []);
        self::assertSame(['a' => 'int', 'b' => 'bool', 'c' => 'float', 'd' => 'float', 'e' => 'int', 'f' => 'float', 'g' => 'callable', 'h' => 'scalar', 'i' => 'resource', 'j' => 'numeric'], $types);
    }

    public function testNamespaceRelativeDocblockNameResolvesAgainstCurrentNamespace(): void
    {
        $table = $this->build(['C.php' => '<?php
namespace App;
class C { /** @var namespace\Bar */ public $bar; }']);

        self::assertSame('App\Bar', $table->getClass('App\C')?->properties['bar']->type);
    }

    public function testExposesClassNodeAndPropertyDefaults(): void
    {
        $table = $this->build(['C.php' => '<?php
namespace App;
class C {
    protected $policies = [\'a\' => 1];
    public $none;
    public function __construct(private int $promoted = 5) {}
}']);

        $class = $table->getClass('App\C');
        self::assertNotNull($class);
        self::assertInstanceOf(Class_::class, $class->node);
        self::assertInstanceOf(Array_::class, $class->properties['policies']->default);
        self::assertNull($class->properties['none']->default);
        self::assertNull($class->properties['promoted']->default);
    }

    public function testBuildContainsPerFileThrowable(): void
    {
        $good = $this->parsedFile('app/Good.php', '<?php namespace App; class Good {}');
        $wrongType = unserialize(serialize(new String_('not-a-type')));
        $badMethod = new ClassMethod('m', ['params' => [new Param(new Variable('x'), null, $wrongType)]]);
        $bad = new ParsedFile(
            new SourceFile('app/Bad.php', '/abs/app/Bad.php', ''),
            [new Class_('Bad', ['stmts' => [$badMethod]])],
            new SuppressionSet([], []),
        );

        $table = (new SymbolTableBuilder())->build(new ParseResult([$bad, $good], []));

        self::assertNotNull($table->getClass('App\Good'));
        self::assertNull($table->getClass('Bad'));
        self::assertCount(1, $table->failures());
        self::assertStringStartsWith('app/Bad.php: TypeError: ', $table->failures()[0]);
    }

    public function testReturnGenericIsTheFirstClassLikeArgument(): void
    {
        $table = $this->build(['C.php' => '<?php
namespace App\Models;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Collection;
class C {
    /** @return HasMany<Invoice> */
    public function invoices(): HasMany {}
    /** @return BelongsTo<\Other\Account, $this> */
    public function account() {}
    /** @return Collection<int, Invoice> */
    public function all() {}
    /**
     * @return HasMany
     * @phpstan-return HasMany<Order>
     */
    public function orders() {}
    /**
     * @psalm-return HasMany<Receipt>
     * @return HasMany<Invoice>
     */
    public function receipts() {}
    /** @return HasMany<int, string>|null */
    public function scalars() {}
    /** @return HasMany */
    public function plain() {}
    /** @return ?HasMany<Invoice> */
    public function nullable() {}
    /**
     * @template T
     * @return Collection<T>
     */
    public function templated() {}
}']);

        $class = $table->getClass('App\Models\C');
        self::assertNotNull($class);
        $m = $class->methods;
        self::assertSame('App\Models\Invoice', $m['invoices']->returnGeneric);
        self::assertSame('Illuminate\Database\Eloquent\Relations\HasMany', $m['invoices']->returnType);
        self::assertSame('Other\Account', $m['account']->returnGeneric);
        self::assertSame('App\Models\Invoice', $m['all']->returnGeneric);
        self::assertSame('App\Models\Order', $m['orders']->returnGeneric);
        self::assertSame('App\Models\Receipt', $m['receipts']->returnGeneric);
        self::assertNull($m['scalars']->returnGeneric);
        self::assertNull($m['plain']->returnGeneric);
        self::assertSame('App\Models\Invoice', $m['nullable']->returnGeneric);
        self::assertNull($m['templated']->returnGeneric);
    }

    public function testClassLevelPropertyAndMethodTags(): void
    {
        $table = $this->build(['C.php' => '<?php
namespace App\Models;
use Illuminate\Database\Eloquent\Collection;
/**
 * @property int $id
 * @property-read Account $account
 * @property-read Collection<int, Invoice> $invoices
 * @phpstan-property \Other\Team $team
 * @psalm-property ?Member $member
 * @property-write Secret $secret
 * @method Invoice latestInvoice()
 * @method static Builder|C active()
 * @method noType()
 */
class C {}']);

        $class = $table->getClass('App\Models\C');
        self::assertNotNull($class);
        self::assertSame([
            'id' => 'int',
            'account' => 'App\Models\Account',
            'invoices' => 'Illuminate\Database\Eloquent\Collection',
            'member' => 'App\Models\Member',
            'team' => 'Other\Team',
        ], $class->docProperties);
        // A two-class union (Builder|C) is ambiguous, so it is not recorded.
        self::assertSame(['latestinvoice' => 'App\Models\Invoice'], $class->docMethods);
    }

    public function testReturnShapeMarkers(): void
    {
        $table = $this->build(['C.php' => '<?php
namespace App;
class C {
    public function a(): static {}
    public function b(): ?self {}
    /** @return $this */
    public function c() {}
    public function d(): A|B|null {}
    /** @return A|B */
    public function e() {}
    /** @return A|null */
    public function f() {}
    public function g(): parent {}
}']);

        $shapes = [];
        foreach (['a', 'b', 'c', 'd', 'e', 'f', 'g'] as $name) {
            $method = $table->findMethod('App\C', $name);
            self::assertNotNull($method);
            $shapes[$name] = [$method->returnsStatic, $method->returnsSelf, $method->returnAmbiguous];
        }
        self::assertSame([
            'a' => [true, false, false],
            'b' => [false, true, false],
            'c' => [true, false, false],
            'd' => [false, false, true],
            'e' => [false, false, true],
            'f' => [false, false, false],
            'g' => [false, false, true],
        ], $shapes);
    }

    public function testConstructorAssignedPropertyTakesTheParameterType(): void
    {
        $table = $this->build(['C.php' => '<?php
namespace App\Http;
use App\Services\Repo;
use App\Services\Other;
class C {
    private $repo;
    private $fallback;
    private $branch;
    private $reassigned;
    private $twice;
    /** @var Other */
    private $documented;
    private $untypedParam;
    private $overwritten;
    private $nullFallback;
    private $otherFallback;
    private $callFallback;
    public function __construct(Repo $repo, ?Repo $maybe, Repo $b, Repo $r2, Other $o, Repo $d, $u, Repo $w, ?Repo $n1, ?Repo $n2, ?Repo $n3)
    {
        $this->repo = $repo;
        $this->fallback = $maybe ?? new Repo();
        $this->nullFallback = $n1 ?? null;
        $this->otherFallback = $n2 ?? new Other();
        $this->callFallback = $n3 ?? app(Repo::class);
        if ($b) {
            $this->branch = $b;
        }
        $r2 = new Other();
        $this->reassigned = $r2;
        $this->twice = $b;
        $this->twice = $o;
        $this->documented = $d;
        $this->untypedParam = $u;
        $this->overwritten = $w;
        foreach ([1] as $x) {
            $this->overwritten = $x;
        }
    }
}']);

        $class = $table->getClass('App\Http\C');
        self::assertNotNull($class);
        $p = $class->properties;
        self::assertSame('App\Services\Repo', $p['repo']->type);
        self::assertSame('App\Services\Repo', $p['fallback']->type);
        self::assertNull($p['branch']->type);
        self::assertNull($p['reassigned']->type);
        self::assertNull($p['twice']->type);
        self::assertSame('App\Services\Other', $p['documented']->type);
        self::assertNull($p['untypedParam']->type);
        self::assertNull($p['overwritten']->type);
        self::assertSame('App\Services\Repo', $p['nullFallback']->type);
        self::assertNull($p['otherFallback']->type);
        self::assertNull($p['callFallback']->type);
    }

    private function parsedFile(string $path, string $code): ParsedFile
    {
        return (new AstGenerator())->parse(new SourceFile($path, '/abs/'.$path, $code));
    }

    /** @param array<string, string> $files */
    private function build(array $files): SymbolTable
    {
        foreach ($files as $name => $code) {
            file_put_contents($this->root.'/app/'.$name, $code);
        }
        $result = (new ProjectParser(new FileFinder(), new AstGenerator()))->parse($this->root);
        self::assertSame([], $result->failures);

        return (new SymbolTableBuilder())->build($result);
    }
}
