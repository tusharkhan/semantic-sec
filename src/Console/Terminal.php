<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Console;

use Symfony\Component\Console\Formatter\OutputFormatter;
use TusharKhan\SemanticSec\Llm\LlmResponse;

/** Text from the scanned project or the model, made safe for a terminal: no control characters, no console tags. */
final class Terminal
{
    // One line: C0, DEL and C1 controls become spaces.
    public static function clean(string $text): string
    {
        return (string) LlmResponse::clean($text);
    }

    // clean(), then `<tags>` escaped so the formatter prints them literally.
    public static function safe(string $text): string
    {
        return OutputFormatter::escape(self::clean($text));
    }

    // One line of code or diff: tabs become four spaces, other controls spaces, indentation kept, tags escaped.
    public static function safeLine(string $line): string
    {
        return OutputFormatter::escape(rtrim((string) preg_replace('/(?:[\x00-\x1F\x7F]|\xC2[\x80-\x9F])+/', ' ', str_replace("\t", '    ', $line))));
    }

    // safe() per line, keeping the line breaks (multi-line table cells).
    public static function safeLines(string $text): string
    {
        return implode("\n", array_map(self::safe(...), explode("\n", $text)));
    }
}
