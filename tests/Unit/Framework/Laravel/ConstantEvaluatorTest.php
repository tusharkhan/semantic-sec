<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Framework\Laravel;

use PhpParser\Node;
use PhpParser\Node\Stmt\Expression;
use PhpParser\NodeFinder;
use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Framework\Laravel\ConstantEvaluator;
use TusharKhan\SemanticSec\Parsing\AstGenerator;
use TusharKhan\SemanticSec\Parsing\ParseResult;
use TusharKhan\SemanticSec\Parsing\SourceFile;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTableBuilder;

final class ConstantEvaluatorTest extends TestCase
{
    private ConstantEvaluator $eval;

    protected function setUp(): void
    {
        $this->eval = new ConstantEvaluator();
    }

    /** Parses `$code` and returns the first expression statement's expression. */
    private function expr(string $code, string $file = 'bootstrap/app.php'): Node\Expr
    {
        $dir = sys_get_temp_dir().'/ss-ce-'.bin2hex(random_bytes(4));
        mkdir($dir);
        $abs = $dir.'/snippet.php';
        file_put_contents($abs, $code);
        $parsed = (new AstGenerator())->parse(new SourceFile($file, $abs, $code));
        unlink($abs);
        rmdir($dir);
        $stmt = (new NodeFinder())->findFirst($parsed->ast, fn (Node $n): bool => $n instanceof Expression);
        self::assertInstanceOf(Expression::class, $stmt);

        return $stmt->expr;
    }

    public function testConcat(): void
    {
        self::assertSame('ab', $this->eval->string($this->expr("<?php 'a'.'b';"), 'x.php'));
    }

    public function testClassConstantResolvesThroughUse(): void
    {
        $e = $this->expr('<?php use App\\Foo; Foo::class;');
        self::assertSame('App\\Foo', $this->eval->string($e, 'x.php'));
    }

    public function testDirConcatPath(): void
    {
        $e = $this->expr("<?php __DIR__.'/../routes/web.php';");
        self::assertSame('routes/web.php', $this->eval->path($e, 'bootstrap/app.php'));
    }

    public function testStringOfDirIsRelativeDirectory(): void
    {
        self::assertSame('bootstrap', $this->eval->string($this->expr('<?php __DIR__;'), 'bootstrap/app.php'));
        self::assertSame('.', $this->eval->string($this->expr('<?php __DIR__;'), 'index.php'));
    }

    public function testBasePath(): void
    {
        self::assertSame('routes/api.php', $this->eval->path($this->expr("<?php base_path('routes/api.php');"), 'bootstrap/app.php'));
        self::assertSame('', $this->eval->path($this->expr('<?php base_path();'), 'bootstrap/app.php'));
    }

    public function testAppPath(): void
    {
        self::assertSame('app/Http', $this->eval->path($this->expr("<?php app_path('Http');"), 'bootstrap/app.php'));
    }

    public function testDirnameOfDirIsRoot(): void
    {
        self::assertSame('', $this->eval->path($this->expr('<?php dirname(__DIR__);'), 'bootstrap/app.php'));
    }

    public function testDirnameWithLevels(): void
    {
        self::assertSame('', $this->eval->path($this->expr('<?php dirname(__DIR__, 2);'), 'a/b/c.php'));
    }

    public function testThisPropertyDefault(): void
    {
        $code = "<?php class RSP { protected \$namespace = 'App\\\\Http\\\\Controllers'; function f() { \$this->namespace; } }";
        $dir = sys_get_temp_dir().'/ss-ce-'.bin2hex(random_bytes(4));
        mkdir($dir);
        file_put_contents($dir.'/p.php', $code);
        $parsed = (new AstGenerator())->parse(new SourceFile('app/P.php', $dir.'/p.php', $code));
        unlink($dir.'/p.php');
        rmdir($dir);
        $symbols = (new SymbolTableBuilder())->build(new ParseResult([$parsed], []));
        $class = $symbols->getClass('RSP');
        self::assertNotNull($class);
        $fetch = (new NodeFinder())->findFirstInstanceOf($parsed->ast, Node\Expr\PropertyFetch::class);
        self::assertNotNull($fetch);

        self::assertSame('App\\Http\\Controllers', $this->eval->string($fetch, 'app/P.php', $class));
    }

    public function testVariableIsNull(): void
    {
        self::assertNull($this->eval->string($this->expr('<?php $var;'), 'x.php'));
    }

    public function testPathEscapingRootIsNull(): void
    {
        $e = $this->expr("<?php __DIR__.'/../../x';");
        self::assertNull($this->eval->path($e, 'bootstrap/app.php'));
    }

    public function testNormalisePath(): void
    {
        self::assertSame('a/c', ConstantEvaluator::normalisePath('./a//b/../c/'));
        self::assertSame('a/b', ConstantEvaluator::normalisePath('/a\\b'));
        self::assertSame('', ConstantEvaluator::normalisePath('.'));
        self::assertNull(ConstantEvaluator::normalisePath('../x'));
    }
}
