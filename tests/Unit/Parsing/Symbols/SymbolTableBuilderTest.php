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
