<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Payload;

use PhpParser\Node\Expr\Closure;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\NodeFinder;
use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Parsing\AstGenerator;
use TusharKhan\SemanticSec\Parsing\CallGraph\PathNode;
use TusharKhan\SemanticSec\Parsing\ParseResult;
use TusharKhan\SemanticSec\Parsing\SourceFile;
use TusharKhan\SemanticSec\Parsing\Symbols\MethodSymbol;
use TusharKhan\SemanticSec\Payload\PrunedMethod;
use TusharKhan\SemanticSec\Payload\Pruner;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;

final class PrunerTest extends TestCase
{
    private const FILE = 'app/Http/Controllers/FooController.php';

    private const CLASS_NAME = 'App\Http\Controllers\FooController';

    /** @param list<string> $helpers */
    private function pruneMethod(string $code, string $method, array $helpers = []): PrunedMethod
    {
        [$parsed, $ast] = $this->parse($code);
        $node = (new NodeFinder())->findFirst($ast, static fn ($n): bool => $n instanceof ClassMethod && $n->name->toString() === $method);
        self::assertInstanceOf(ClassMethod::class, $node);
        $symbol = new MethodSymbol(self::CLASS_NAME, $method, self::FILE, $node->getStartLine(), $node->getEndLine(), [], null, false, $node);
        $path = new PathNode($symbol->id(), $symbol, null, self::FILE, $node->getStartLine(), $node->getEndLine(), 0, null, null);

        return (new Pruner($parsed))->prune($path, $helpers);
    }

    /** @return array{ParseResult, array<\PhpParser\Node\Stmt>} */
    private function parse(string $code): array
    {
        $parsedFile = (new AstGenerator())->parse(new SourceFile(self::FILE, '/x/'.self::FILE, $code));

        return [new ParseResult([$parsedFile], []), $parsedFile->ast];
    }

    private function wrap(string $body, string $head = ''): string
    {
        return "<?php\nnamespace App\\Http\\Controllers;\n\nclass FooController\n{\n{$head}{$body}\n}\n";
    }

    /** @return list<int> */
    private static function lineNumbers(PrunedMethod $p): array
    {
        return array_map(static fn (array $l): int => $l['line'], $p->lines);
    }

    /** @return list<string> */
    private static function texts(PrunedMethod $p): array
    {
        return array_map(static fn (array $l): string => trim($l['text']), $p->lines);
    }

    public function testLineNumbersPreserved(): void
    {
        $p = $this->pruneMethod($this->wrap("    public function show(int \$id)\n    {\n        \$a = 1;\n\n        return \$a;\n    }"), 'show');

        self::assertSame([6, 7, 8, 10, 11], self::lineNumbers($p));
        self::assertSame('return $a;', trim($p->lines[3]['text']));
        self::assertSame(6, $p->startLine);
        self::assertSame(11, $p->endLine);
    }

    public function testCommentAndBlankLinesRemoved(): void
    {
        $code = $this->wrap("    public function f()\n    {\n        // note\n\n        # hash\n        /* block\n           more */\n        \$a = 1; // trailing stays\n        return \$a;\n    }");
        $p = $this->pruneMethod($code, 'f');

        self::assertSame(['public function f()', '{', '$a = 1; // trailing stays', 'return $a;', '}'], self::texts($p));
    }

    public function testStringContentLookingLikeCommentIsKept(): void
    {
        $code = $this->wrap("    public function f()\n    {\n        \$s = <<<TXT\n// not a comment\n\nTXT;\n        return \$s;\n    }");

        self::assertContains('// not a comment', self::texts($this->pruneMethod($code, 'f')));
    }

    public function testDebugStatementRemoved(): void
    {
        $body = "    public function f()\n    {\n        dd(\$x);\n        dump(1);\n        var_dump(2);\n        print_r(3);\n        ray(4);\n        logger('a');\n        info('b');\n        Log::info('c');\n        Log::channel('x')->warning('d');\n        \$real = 1;\n        return \$real;\n    }";
        $p = $this->pruneMethod($this->wrap($body), 'f');

        self::assertSame(['public function f()', '{', '$real = 1;', 'return $real;', '}'], self::texts($p));
    }

    public function testDebugNestedInsideNonProtectedBlockIsRemoved(): void
    {
        $body = "    public function f(\$x)\n    {\n        if (\$x) {\n            dd(\$x);\n            \$y = 1;\n        }\n    }";
        $p = $this->pruneMethod($this->wrap($body), 'f');

        self::assertNotContains('dd($x);', self::texts($p));
        self::assertContains('$y = 1;', self::texts($p));
    }

    public function testDebugOnSameLineAsOtherCodeIsKept(): void
    {
        $p = $this->pruneMethod($this->wrap("    public function f(\$x)\n    {\n        if (\$x) dd(\$x);\n    }"), 'f');

        self::assertContains('if ($x) dd($x);', self::texts($p));
    }

    public function testDebugSharingALineWithAnAssignmentKeepsTheAssignment(): void
    {
        $p = $this->pruneMethod($this->wrap("    public function f()\n    {\n        \$a = 1; dump(\$a);\n        return \$a;\n    }"), 'f');

        self::assertContains('$a = 1; dump($a);', self::texts($p));
    }

    public function testDebugAfterMultiLineStatementKeepsItsClosingLine(): void
    {
        $p = $this->pruneMethod($this->wrap("    public function f()\n    {\n        \$q = [\n            'a' => 1,\n        ]; dump(1);\n    }"), 'f');

        self::assertContains(']; dump(1);', self::texts($p));
    }

    public function testDebugWithSideEffectingArgumentsIsKept(): void
    {
        $p = $this->pruneMethod($this->wrap("    public function f()\n    {\n        dump(\$this->save());\n        dd(\$i++);\n        Log::info('x', [\$o->touch()]);\n    }"), 'f');

        self::assertContains('dump($this->save());', self::texts($p));
        self::assertContains('dd($i++);', self::texts($p));
        self::assertContains("Log::info('x', [\$o->touch()]);", self::texts($p));
    }

    public function testDocblockLinesPrecedeStartLine(): void
    {
        $p = $this->pruneMethod($this->wrap("    public function f(\$id)\n    {\n        return 1;\n    }", "    /** @param int \$id */\n"), 'f');

        self::assertSame(6, $p->lines[0]['line']);
        self::assertSame(7, $p->startLine);
    }

    public function testProtectedHelpersKept(): void
    {
        $calls = [
            '$this->authorize("view", $o);', 'Gate::allows("x");', 'Auth::id();', 'auth()->id();', 'abort_if($a, 403);',
            'abort_unless($a, 403);', 'abort(403);', 'throw_if($a, E::class);', 'throw_unless($a, E::class);',
            '$u->can("x");', '$u->cannot("x");', '$u->cant("x");', 'policy($o)->view($u, $o);', '$r->user()->id;',
            '$this->denyAccessUnlessGranted("x");', '$this->isGranted("x");', '$this->authorizeResource(O::class);', '$this->authorizeForUser($u, "x");',
        ];
        foreach ($calls as $call) {
            $p = $this->pruneMethod($this->wrap("    public function f()\n    {\n        {$call}\n    }"), 'f');
            self::assertContains($call, self::texts($p), $call);
        }
    }

    public function testDebugNestedInsideProtectedStatementIsKept(): void
    {
        $body = "    public function f(\$u)\n    {\n        if (\$u->cannot('x')) {\n            dd(\$u);\n            abort(403);\n        }\n    }";
        $p = $this->pruneMethod($this->wrap($body), 'f');

        self::assertContains('dd($u);', self::texts($p));
    }

    public function testDebugWrappingProtectedCallIsKept(): void
    {
        $p = $this->pruneMethod($this->wrap("    public function f()\n    {\n        dd(auth()->id());\n    }"), 'f');

        self::assertContains('dd(auth()->id());', self::texts($p));
    }

    public function testMultiLineProtectedStatementKeepsEveryLine(): void
    {
        $body = "    public function f(\$o)\n    {\n        \$this->authorize(\n            // why\n            'view',\n\n            \$o\n        );\n    }";
        $p = $this->pruneMethod($this->wrap($body), 'f');

        self::assertSame([8, 9, 10, 11, 12, 13], array_slice(self::lineNumbers($p), 2, 6));
    }

    public function testAuthHelpersMatchByMethodAndFqn(): void
    {
        $code = $this->wrap("    public function f(\$o)\n    {\n        \$this->ensureOwner(\$o);\n        Guard::verify(\$o);\n        \$this->other();\n    }");
        $p = $this->pruneMethod($code, 'f', ['EnsureOwner', 'App\\Guard::VERIFY']);
        $t = self::texts($p);

        self::assertContains('$this->ensureOwner($o);', $t);
        self::assertContains('Guard::verify($o);', $t);
        self::assertContains('$this->other();', $t);
    }

    public function testAuthHelperProtectsCommentInsideItsStatement(): void
    {
        $code = $this->wrap("    public function f(\$o)\n    {\n        \$x = [\n            // c\n            \$this->ensureOwner(\$o),\n        ];\n    }");

        self::assertContains('// c', self::texts($this->pruneMethod($code, 'f', ['ensureOwner'])));
        self::assertNotContains('// c', self::texts($this->pruneMethod($code, 'f')));
    }

    public function testGetterCollapsed(): void
    {
        $p = $this->pruneMethod($this->wrap("    public function name()\n    {\n        return \$this->name;\n    }"), 'name');

        self::assertSame([['line' => 6, 'text' => '// App\Http\Controllers\FooController::name: trivial accessor omitted']], $p->lines);
    }

    public function testSetterAndEmptyConstructorCollapsed(): void
    {
        $setter = $this->pruneMethod($this->wrap("    public function setName(\$name)\n    {\n        \$this->name = \$name;\n        return \$this;\n    }"), 'setName');
        $plain = $this->pruneMethod($this->wrap("    public function setAge(\$age)\n    {\n        \$this->age = \$age;\n    }"), 'setAge');
        $ctor = $this->pruneMethod($this->wrap("    public function __construct(private Foo \$foo)\n    {\n        // nothing\n    }"), '__construct');

        foreach ([$setter, $plain, $ctor] as $p) {
            self::assertCount(1, $p->lines);
            self::assertStringEndsWith(': trivial accessor omitted', $p->lines[0]['text']);
            self::assertSame($p->startLine, $p->lines[0]['line']);
        }
    }

    public function testNonTrivialSettersAndConstructorsAreNotCollapsed(): void
    {
        $a = $this->pruneMethod($this->wrap("    public function setName(\$name)\n    {\n        \$this->name = trim(\$name);\n    }"), 'setName');
        $b = $this->pruneMethod($this->wrap("    public function __construct(private Foo \$foo)\n    {\n        \$this->foo->boot();\n    }"), '__construct');

        self::assertGreaterThan(1, count($a->lines));
        self::assertGreaterThan(1, count($b->lines));
    }

    public function testDocblockKeepsOnlyTypeTags(): void
    {
        $head = "    /**\n     * Show it.\n     *\n     * @param int \$id the id\n     * @throws X\n     * @return Foo\n     */\n";
        $p = $this->pruneMethod($this->wrap("    public function f(\$id)\n    {\n        return 1;\n    }", $head), 'f');

        self::assertSame([6, 9, 11, 12, 13, 14, 15, 16], self::lineNumbers($p));
        self::assertSame(['/**', '* @param int $id the id', '* @return Foo', '*/'], array_slice(self::texts($p), 0, 4));
    }

    public function testDocblockWithoutKeptTagsVanishes(): void
    {
        $head = "    /**\n     * Show it.\n     */\n";
        $p = $this->pruneMethod($this->wrap("    public function f(\$id)\n    {\n        return 1;\n    }", $head), 'f');

        self::assertSame('public function f($id)', self::texts($p)[0]);
    }

    public function testInlineVarDocblockKept(): void
    {
        $p = $this->pruneMethod($this->wrap("    public function f()\n    {\n        /** @var Foo \$x */\n        \$x = make();\n    }"), 'f');

        self::assertContains('/** @var Foo $x */', self::texts($p));
    }

    public function testClosureEntry(): void
    {
        $code = "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::get('/x', function (\$r) {\n    // c\n    dd(1);\n    \$o = 1;\n\n    abort_if(!\$r->user(), 403);\n});\n";
        [$parsed, $ast] = $this->parse($code);
        $closure = (new NodeFinder())->findFirstInstanceOf($ast, Closure::class);
        self::assertInstanceOf(Closure::class, $closure);
        $node = new PathNode('closure@'.self::FILE.':5', null, $closure, self::FILE, $closure->getStartLine(), $closure->getEndLine(), 0, null, null);
        $p = (new Pruner($parsed))->prune($node, []);

        self::assertSame([5, 8, 10, 11], self::lineNumbers($p));
        self::assertSame('closure@'.self::FILE.':5', $p->id);
        self::assertSame("Route::get('/x', function (\$r) {", $p->lines[0]['text']);
        self::assertSame('abort_if(!$r->user(), 403);', trim($p->lines[2]['text']));
        self::assertSame('});', $p->lines[3]['text']);
    }

    public function testCrlfAndBomKeepExactLineNumbers(): void
    {
        $raw = "\xEF\xBB\xBF".str_replace("\n", "\r\n", $this->wrap("    public function f()\n    {\n        // c\n\n        return 1;\n    }"));
        $dir = sys_get_temp_dir().'/pruner-'.uniqid();
        mkdir($dir);
        file_put_contents($dir.'/f.php', $raw);
        $file = SourceFile::fromPath($dir, 'f.php');
        unlink($dir.'/f.php');
        rmdir($dir);
        $p = $this->pruneMethod($file->code, 'f');
        self::assertStringStartsWith('<?php', $file->code);

        self::assertSame([6, 7, 10, 11], self::lineNumbers($p));
        self::assertSame('        return 1;', $p->lines[2]['text']);
    }

    public function testLoneCrIsALineBreakLikeTheParser(): void
    {
        $code = str_replace("\n", "\r", $this->wrap("    public function f()\n    {\n        return 1;\n    }"));
        $p = $this->pruneMethod($code, 'f');

        self::assertSame([6, 7, 8, 9], self::lineNumbers($p));
    }

    public function testBenchmarkInvoiceShowLinesMatchTheFile(): void
    {
        $relative = 'app/Http/Controllers/Vuln/InvoiceController.php';
        $absolute = BenchmarkCorpus::root().'/laravel11-app/'.$relative;
        $code = (string) file_get_contents($absolute);
        $parsedFile = (new AstGenerator())->parse(new SourceFile($relative, $absolute, $code));
        $found = (new NodeFinder())->findFirst($parsedFile->ast, static fn ($n): bool => $n instanceof ClassMethod && $n->name->toString() === 'show');
        self::assertInstanceOf(ClassMethod::class, $found);
        $class = 'App\Http\Controllers\Vuln\InvoiceController';
        $symbol = new MethodSymbol($class, 'show', $relative, $found->getStartLine(), $found->getEndLine(), [], null, false, $found);
        $path = new PathNode($symbol->id(), $symbol, null, $relative, $found->getStartLine(), $found->getEndLine(), 0, null, null);

        $p = (new Pruner(new ParseResult([$parsedFile], [])))->prune($path, []);

        $source = explode("\n", $code);
        self::assertNotEmpty($p->lines);
        foreach ($p->lines as $l) {
            self::assertSame(rtrim($source[$l['line'] - 1]), $l['text']);
        }
        self::assertSame(17, $p->startLine);
        self::assertContains('$invoice = Invoice::findOrFail($id);', self::texts($p));
        self::assertNotContains('', self::texts($p));
    }
}
