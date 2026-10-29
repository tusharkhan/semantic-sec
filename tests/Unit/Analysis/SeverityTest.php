<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Analysis;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Analysis\Severity;

final class SeverityTest extends TestCase
{
    public function testAtLeastComparesRanks(): void
    {
        self::assertTrue(Severity::High->atLeast(Severity::Medium));
        self::assertTrue(Severity::High->atLeast(Severity::High));
        self::assertFalse(Severity::Low->atLeast(Severity::High));
    }

    public function testRankRunsFromOneToFour(): void
    {
        self::assertSame(1, Severity::Low->rank());
        self::assertSame(2, Severity::Medium->rank());
        self::assertSame(3, Severity::High->rank());
        self::assertSame(4, Severity::Critical->rank());
    }
}
