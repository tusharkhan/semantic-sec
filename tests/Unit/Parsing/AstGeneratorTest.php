<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Parsing;

use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Name\FullyQualified;
use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Stmt\Function_;
use PhpParser\NodeFinder;
use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Parsing\AstGenerator;
use TusharKhan\SemanticSec\Parsing\ParseFailure;
use TusharKhan\SemanticSec\Parsing\SourceFile;

final class AstGeneratorTest extends TestCase
{
    private string $root;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir().'/ss-ast-'.bin2hex(random_bytes(6));
        mkdir($this->root, 0777, true);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->root.'/*') ?: [] as $f) {
            unlink($f);
        }
        rmdir($this->root);
    }

    public function testParsesModernSyntax(): void
    {
        $parsed = $this->parse("<?php\nreadonly class R {}\nclass C { const string X = 'a'; }\n\$f = fn (int \$x) => \$x;\n");

        self::assertCount(2, (new NodeFinder())->findInstanceOf($parsed->ast, Class_::class));
    }

    public function testNamesAreFullyQualified(): void
    {
        $parsed = $this->parse('<?php namespace App\Http; use App\Models\Invoice; class C { function f() { return Invoice::find(1); } }');

        $call = (new NodeFinder())->findFirstInstanceOf($parsed->ast, StaticCall::class);
        self::assertNotNull($call);
        self::assertInstanceOf(FullyQualified::class, $call->class);
        self::assertSame('App\Models\Invoice', $call->class->toString());
    }

    public function testCrlfLineNumbersMatchEditor(): void
    {
        $parsed = $this->parse("<?php\r\n\r\nfunction a() {}\r\n");

        self::assertSame(3, $this->first($parsed->ast, Function_::class)->getStartLine());
    }

    public function testCrOnlyLineNumbersMatchEditor(): void
    {
        $parsed = $this->parse("<?php\r\rfunction a() {}\r");

        self::assertSame(3, $this->first($parsed->ast, Function_::class)->getStartLine());
        self::assertSame("<?php\r\rfunction a() {}\r", $parsed->file->code);
    }

    public function testBomIsStrippedAndLinesUnchanged(): void
    {
        $parsed = $this->parse("\xEF\xBB\xBF<?php\n\nclass A {}\n");

        self::assertStringStartsNotWith("\xEF\xBB\xBF", $parsed->file->code);
        self::assertSame(3, $this->first($parsed->ast, Class_::class)->getStartLine());
    }

    public function testSyntaxErrorThrowsParseFailureWithLine(): void
    {
        try {
            $this->parse("<?php\nclass {");
            self::fail('Expected ParseFailure');
        } catch (ParseFailure $e) {
            self::assertSame('x.php', $e->path);
            self::assertNotNull($e->sourceLine);
        }
    }

    private function parse(string $code): \TusharKhan\SemanticSec\Parsing\ParsedFile
    {
        file_put_contents($this->root.'/x.php', $code);

        return (new AstGenerator())->parse(SourceFile::fromPath($this->root, 'x.php'));
    }

    /**
     * @template T of \PhpParser\Node
     *
     * @param  array<\PhpParser\Node\Stmt>  $ast
     * @param  class-string<T>  $class
     * @return T
     */
    private function first(array $ast, string $class): \PhpParser\Node
    {
        $node = (new NodeFinder())->findFirstInstanceOf($ast, $class);
        self::assertNotNull($node);

        return $node;
    }
}
