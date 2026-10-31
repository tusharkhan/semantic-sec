<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Payload;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Payload\TokenEstimator;

final class TokenEstimatorTest extends TestCase
{
    public function testEmptyStringIsZero(): void
    {
        self::assertSame(0, TokenEstimator::estimate(''));
    }

    public function testRoundsUp(): void
    {
        self::assertSame(1, TokenEstimator::estimate('a'));
        self::assertSame(1, TokenEstimator::estimate('abc'));
        self::assertSame(2, TokenEstimator::estimate('abcd'));
    }

    public function testExactMultipleDoesNotOvercount(): void
    {
        self::assertSame(2, TokenEstimator::estimate(str_repeat('x', 7)));
        self::assertSame(3, TokenEstimator::estimate(str_repeat('x', 8)));
    }

    public function testCountsBytesNotCharacters(): void
    {
        self::assertSame((int) ceil(strlen('é') / 3.5), TokenEstimator::estimate('é'));
    }
}
