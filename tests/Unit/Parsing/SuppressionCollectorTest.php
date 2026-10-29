<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Parsing;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Analysis\Category;
use TusharKhan\SemanticSec\Parsing\AstGenerator;
use TusharKhan\SemanticSec\Parsing\SourceFile;
use TusharKhan\SemanticSec\Parsing\SuppressionSet;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;

final class SuppressionCollectorTest extends TestCase
{
    private function collect(string $code): SuppressionSet
    {
        $file = new SourceFile('app/Foo.php', '/abs/app/Foo.php', $code);

        return (new AstGenerator())->parse($file)->suppressions;
    }

    private function method(string $directive): string
    {
        return "<?php\nclass Foo\n{\n    // {$directive}\n    public function show()\n    {\n        \$a = 1;\n        return \$a;\n    }\n}\n";
    }

    public function testMethodLevelSuppressionCoversWholeMethod(): void
    {
        $set = $this->collect($this->method('@semantic-sec-ignore idor: ok'));

        self::assertNotNull($set->find(8, Category::Idor));
        self::assertSame(4, $set->suppressions[0]->commentLine);
        self::assertSame('app/Foo.php', $set->suppressions[0]->file);
    }

    public function testDocblockSuppressionCoversMethod(): void
    {
        $code = "<?php\nclass Foo\n{\n    /**\n     * Show.\n     * @semantic-sec-ignore idor: ok\n     */\n    public function show()\n    {\n        return 1;\n    }\n}\n";
        $set = $this->collect($code);

        self::assertNotNull($set->find(10, Category::Idor));
        self::assertNotNull($set->find(8, Category::Idor));
    }

    public function testStatementSuppressionCoversOnlyNextStatement(): void
    {
        $code = "<?php\nfunction f()\n{\n    \$x = 1;\n\n    // @semantic-sec-ignore idor: ok\n    \$a = 2;\n    \$b = 3;\n}\n";
        $set = $this->collect($code);

        self::assertNotNull($set->find(7, Category::Idor));
        self::assertNull($set->find(8, Category::Idor));
    }

    public function testCweTokenMatches(): void
    {
        $set = $this->collect($this->method('@semantic-sec-ignore CWE-639'));

        self::assertNotNull($set->find(8, Category::Idor));
    }

    public function testAllMatchesAnyCategory(): void
    {
        $set = $this->collect($this->method('@semantic-sec-ignore all'));

        self::assertNotNull($set->find(8, Category::MassAssignment));
    }

    public function testCategoryMismatchDoesNotSuppress(): void
    {
        $set = $this->collect($this->method('@semantic-sec-ignore idor'));

        self::assertNull($set->find(8, Category::MassAssignment));
    }

    public function testReasonIsParsedAndMissingReasonIsReported(): void
    {
        $with = $this->collect($this->method('@semantic-sec-ignore idor: shared invoices are public'));
        self::assertSame('shared invoices are public', $with->suppressions[0]->reason);
        self::assertSame([], $with->withoutReason());

        $without = $this->collect($this->method('@semantic-sec-ignore idor'));
        self::assertCount(1, $without->withoutReason());
    }

    public function testUnknownTokenIsInvalidAndNotApplied(): void
    {
        $set = $this->collect($this->method('@semantic-sec-ignore sqli'));

        self::assertCount(1, $set->invalid);
        self::assertSame('app/Foo.php:4: unknown category "sqli"', $set->invalid[0]);
        self::assertSame([], $set->suppressions);
    }

    public function testMultipleDirectivesInOneCommentAreCollectedOnce(): void
    {
        $code = "<?php\nclass Foo\n{\n    /**\n     * @semantic-sec-ignore idor: a\n     * @semantic-sec-ignore mass_assignment: b\n     */\n    public function show()\n    {\n        return 1;\n    }\n}\n";
        $set = $this->collect($code);

        self::assertCount(2, $set->suppressions);
        self::assertNotNull($set->find(10, Category::MassAssignment));
    }

    public function testPropertyAndExpressionComments(): void
    {
        $code = "<?php\nclass Foo\n{\n    // @semantic-sec-ignore idor: p\n    public \$p = 1;\n\n    public function m()\n    {\n        return foo(/* @semantic-sec-ignore idor: e */ 1);\n    }\n}\n";
        $set = $this->collect($code);

        self::assertCount(1, $set->suppressions);
        self::assertNotNull($set->find(5, Category::Idor));
        self::assertNull($set->find(9, Category::Idor));
    }

    public function testNamespaceLevelDirectiveIsRejected(): void
    {
        $code = "<?php\n// @semantic-sec-ignore all: whole file\nnamespace App;\n\nclass Foo\n{\n    public function show()\n    {\n        return 1;\n    }\n}\n";
        $set = $this->collect($code);

        self::assertSame([], $set->suppressions);
        self::assertSame(['app/Foo.php:2: file-level suppression is not supported; put it above the method or statement'], $set->invalid);
        self::assertNull($set->find(9, Category::Idor));
    }

    public function testClassLevelDirectiveIsRejected(): void
    {
        $code = "<?php\nnamespace App;\n\n/**\n * @semantic-sec-ignore idor: whole class\n */\nclass Foo\n{\n    public function show()\n    {\n        return 1;\n    }\n}\n";
        $set = $this->collect($code);

        self::assertSame([], $set->suppressions);
        self::assertSame(['app/Foo.php:4: class-level suppression is not supported; put it above the method or statement'], $set->invalid);
    }

    public function testTraitInterfaceAndEnumDirectivesAreRejected(): void
    {
        $code = "<?php\n// @semantic-sec-ignore idor\ntrait T {}\n// @semantic-sec-ignore idor\ninterface I {}\n// @semantic-sec-ignore idor\nenum E {}\n";
        $set = $this->collect($code);

        self::assertSame([], $set->suppressions);
        self::assertCount(3, $set->invalid);
    }

    public function testMethodLevelStillWorksInsideDocumentedClass(): void
    {
        $code = "<?php\n/** Class doc. */\nclass Foo\n{\n    /** @semantic-sec-ignore idor: ok */\n    public function show()\n    {\n        return 1;\n    }\n}\n";
        $set = $this->collect($code);

        self::assertCount(1, $set->suppressions);
        self::assertSame([], $set->invalid);
        self::assertNotNull($set->find(8, Category::Idor));
    }

    public function testEmptyReasonAfterColonIsValidAndReasonless(): void
    {
        $set = $this->collect($this->method('@semantic-sec-ignore idor:'));

        self::assertCount(1, $set->suppressions);
        self::assertNull($set->suppressions[0]->reason);
        self::assertCount(1, $set->withoutReason());
        self::assertSame([], $set->invalid);
    }

    public function testMalformedDirectivesAreReported(): void
    {
        $expected = 'app/Foo.php:4: malformed directive; expected "@semantic-sec-ignore <category>[: reason]"';

        $words = $this->collect($this->method('@semantic-sec-ignore idor because x'));
        self::assertSame([], $words->suppressions);
        self::assertSame([$expected], $words->invalid);

        $bare = $this->collect($this->method('@semantic-sec-ignore'));
        self::assertSame([], $bare->suppressions);
        self::assertSame([$expected], $bare->invalid);
    }

    public function testCrlfCommentWithValidDirective(): void
    {
        $code = str_replace("\n", "\r\n", "<?php\nclass Foo\n{\n    /**\n     * @semantic-sec-ignore idor: ok\n     */\n    public function show()\n    {\n        return 1;\n    }\n}\n");
        $set = $this->collect($code);

        self::assertCount(1, $set->suppressions);
        self::assertSame('ok', $set->suppressions[0]->reason);
        self::assertSame([], $set->invalid);
    }

    public function testBenchmarkSuppressedCaseIsCollected(): void
    {
        $case = null;
        foreach (BenchmarkCorpus::cases() as $c) {
            if ($c['id'] === 'suppressed-idor') {
                $case = $c;
            }
        }
        self::assertNotNull($case);
        /** @var array{app: string, vulnerable: array{symbol: string, line: int}} $case */
        $path = BenchmarkCorpus::fileForSymbol($case['app'], $case['vulnerable']['symbol']);
        $root = dirname($path);
        $parsed = (new AstGenerator())->parse(SourceFile::fromPath($root, basename($path)));

        self::assertNotNull($parsed->suppressions->find($case['vulnerable']['line'], Category::Idor));
    }
}
