<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Console;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Formatter\OutputFormatter;
use TusharKhan\SemanticSec\Console\Terminal;

final class TerminalTest extends TestCase
{
    public function testCleanStripsC0DelAndC1(): void
    {
        self::assertSame('a ]0;x b c d', Terminal::clean("a\x1b]0;x\x07b\x7fc\u{9b}d"));
        self::assertSame('one two', Terminal::clean("one\ntwo"));
    }

    public function testSafeIsCleanThenTagEscaped(): void
    {
        $safe = Terminal::safe("<error>x</error>\x1b[2J");

        self::assertSame('<error>x</error> [2J', (new OutputFormatter(false))->format($safe));
    }

    public function testSafeLinesKeepsLineBreaks(): void
    {
        self::assertSame("a\nb [1m", (new OutputFormatter(false))->format(Terminal::safeLines("a\nb\x1b[1m")));
    }
}
