<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Console;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Console\MemoryLimit;

final class MemoryLimitTest extends TestCase
{
    private string $original = '';

    protected function setUp(): void
    {
        $this->original = (string) ini_get('memory_limit');
    }

    protected function tearDown(): void
    {
        ini_set('memory_limit', $this->original);
    }

    public function testShouldRaiseBelowOneGigabyte(): void
    {
        foreach (['128M', '128m', '512M', '1048575K', '134217728', '1023M'] as $value) {
            self::assertTrue(MemoryLimit::shouldRaise($value), $value);
        }
        foreach (['-1', '1G', '1g', '2G', '1024M', '1073741824', '4096M', ' 2G '] as $value) {
            self::assertFalse(MemoryLimit::shouldRaise($value), $value);
        }
    }

    public function testUnparseableLimitIsLeftAlone(): void
    {
        self::assertFalse(MemoryLimit::shouldRaise(''));
        self::assertFalse(MemoryLimit::shouldRaise('lots'));
    }

    public function testApplyRaisesTheDefaultLimit(): void
    {
        ini_set('memory_limit', '128M');
        MemoryLimit::apply(null);
        self::assertSame('1G', ini_get('memory_limit'));
    }

    public function testApplyKeepsAHigherLimit(): void
    {
        ini_set('memory_limit', '2G');
        MemoryLimit::apply('');
        self::assertSame('2G', ini_get('memory_limit'));
    }

    public function testEnvironmentOverrides(): void
    {
        ini_set('memory_limit', '2G');
        MemoryLimit::apply('1536M');
        self::assertSame('1536M', ini_get('memory_limit'));
        MemoryLimit::apply('-1');
        self::assertSame('-1', ini_get('memory_limit'));
    }
}
