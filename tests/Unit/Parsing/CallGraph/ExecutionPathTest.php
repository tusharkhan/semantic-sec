<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Parsing\CallGraph;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Parsing\CallGraph\CallSite;
use TusharKhan\SemanticSec\Parsing\CallGraph\ExecutionPath;
use TusharKhan\SemanticSec\Parsing\CallGraph\PathNode;

final class ExecutionPathTest extends TestCase
{
    public function testEntryIsTheFirstNode(): void
    {
        $entry = new PathNode('App\A::show', null, null, 'app/A.php', 3, 9, 0, null, null);
        $callee = new PathNode('App\B::find', null, null, 'app/B.php', 5, 7, 1, new CallSite('app/A.php', 4, true), 'App\A::show');
        $path = new ExecutionPath([$entry, $callee], ['app/A.php:6: $x->y()']);

        self::assertSame($entry, $path->entry());
        self::assertTrue($callee->calledFrom?->conditional);
        self::assertNull($entry->closureClass);
    }

    public function testEmptyPathIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new ExecutionPath([], []);
    }
}
