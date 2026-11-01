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

    public function testWorkflowCommandPrefixDefused(): void
    {
        self::assertSame(': :error file=x::boom', Terminal::safe('::error file=x::boom'));
        self::assertSame(': :warning::w', Terminal::safe("  \t::warning::w"));
        self::assertSame('    : :set-output name=a::b', Terminal::safeLine("\t::set-output name=a::b"));
        self::assertSame("a\n: :error::x", Terminal::safeLines("a\n::error::x"));
        self::assertSame('a ::error::x', Terminal::safe('a ::error::x'), 'only a line-leading :: is a command');
        self::assertSame('Foo::bar()', Terminal::safe('Foo::bar()'));
    }

    public function testSafeLinesKeepsLineBreaks(): void
    {
        self::assertSame("a\nb [1m", (new OutputFormatter(false))->format(Terminal::safeLines("a\nb\x1b[1m")));
    }

    public function testBidiControlsStripped(): void
    {
        $bidi = "a\u{202A}\u{202B}\u{202C}\u{202D}\u{202E}b\u{2066}\u{2067}\u{2068}\u{2069}c\u{200E}\u{200F}\u{061C}d";

        self::assertSame('abcd', Terminal::clean($bidi));
        self::assertSame('  abcd', Terminal::safeLine('  '.$bidi));
    }

    public function testInvalidUtf8BecomesReplacementCharacter(): void
    {
        foreach (["a\x9b31mb", "a\xC3b", "a\xE0\xA6b", "a\xFFb", "a\xED\xA0\x80b"] as $bad) {
            foreach ([Terminal::clean($bad), Terminal::safe($bad), Terminal::safeLine($bad)] as $out) {
                self::assertTrue(mb_check_encoding($out, 'UTF-8'), bin2hex($bad));
                self::assertStringStartsWith("a\u{FFFD}", $out);
                self::assertStringNotContainsString("\x9b", $out);
            }
        }
    }

    public function testMultibyteTextKeptWhole(): void
    {
        $text = 'Å Ӆ naïve অ …';

        self::assertSame($text, Terminal::clean($text));
        self::assertSame('    '.$text, Terminal::safeLine("\t".$text));
    }
}
