<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Framework\Laravel;

use PhpParser\Node\Expr;
use PhpParser\NodeFinder;
use PhpParser\ParserFactory;
use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Framework\Laravel\AuthExpressions;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;

final class AuthExpressionsTest extends TestCase
{
    public function testLoopCarriedAssignmentBreaksTheAuthUserVariable(): void
    {
        [$context, $reads] = self::context('$u = auth()->user(); foreach ($xs as $x) { $u->id; $u = $other; }', 'u');
        self::assertFalse($context->isAuthUser($reads[0]));
        self::assertCount(2, $context->assignedValues($reads[0]) ?? []);
    }

    public function testLoopCarriedAssignmentCountsForEveryLoopKind(): void
    {
        foreach (['while ($c) { $u->id; $u = $o; }', 'for (;;) { $u->id; $u = $o; }', 'do { $u->id; $u = $o; } while ($c);'] as $loop) {
            [$context, $reads] = self::context('$u = auth()->user(); '.$loop, 'u');
            self::assertFalse($context->isAuthUser($reads[0]), $loop);
        }
    }

    public function testAssignmentAfterTheLoopDoesNotCount(): void
    {
        [$context, $reads] = self::context('$u = auth()->user(); while ($c) { $u->id; } $u = $other;', 'u');
        self::assertTrue($context->isAuthUser($reads[0]));
    }

    public function testLoopCarriedAssignmentTaintsTheVariableWithInput(): void
    {
        [$context, $reads] = self::context('$v = 1; while ($c) { $v->id; $v = request(\'x\'); }', 'v');
        self::assertTrue($context->isRequestInput($reads[0]));
    }

    public function testLoopCarriedReassignmentTouchesTheParameter(): void
    {
        [$context, $reads] = self::context('while ($c) { $p->id; $p = $o; }', 'p', ['p' => 'App\Models\User']);
        self::assertFalse($context->isUntouchedParam('p', $reads[0]->getStartFilePos()));
    }

    /**
     * @param  array<string, ?string>  $params
     * @return array{AuthExpressions, list<Expr\Variable>}
     */
    private static function context(string $code, string $name, array $params = []): array
    {
        $body = (new ParserFactory())->createForNewestSupportedVersion()->parse('<?php '.$code) ?? [];
        $reads = [];
        foreach ((new NodeFinder())->findInstanceOf($body, Expr\PropertyFetch::class) as $fetch) {
            if ($fetch->var instanceof Expr\Variable && $fetch->var->name === $name) {
                $reads[] = $fetch->var;
            }
        }
        self::assertNotSame([], $reads);

        return [new AuthExpressions(new SymbolTable([]), $params, $body), $reads];
    }
}
