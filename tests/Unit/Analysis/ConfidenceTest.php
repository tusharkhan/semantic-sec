<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Analysis;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Analysis\Confidence;

final class ConfidenceTest extends TestCase
{
    public function testAtLeastComparesRanks(): void
    {
        self::assertTrue(Confidence::Medium->atLeast(Confidence::Low));
        self::assertTrue(Confidence::Medium->atLeast(Confidence::Medium));
        self::assertFalse(Confidence::Low->atLeast(Confidence::Medium));
    }

    public function testRankRunsFromOneToThree(): void
    {
        self::assertSame(1, Confidence::Low->rank());
        self::assertSame(2, Confidence::Medium->rank());
        self::assertSame(3, Confidence::High->rank());
    }
}
