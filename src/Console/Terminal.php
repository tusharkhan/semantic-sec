<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Console;

use Symfony\Component\Console\Formatter\OutputFormatter;

/** Text from the scanned project or the model, made safe for a terminal: valid UTF-8, no controls, no bidi overrides, no console tags. */
final class Terminal
{
    // A well-formed UTF-8 sequence is skipped; any other byte matches the alternative.
    private const INVALID_BYTE = '/(?:[\x00-\x7F]|[\xC2-\xDF][\x80-\xBF]|\xE0[\xA0-\xBF][\x80-\xBF]|[\xE1-\xEC\xEE\xEF][\x80-\xBF]{2}|\xED[\x80-\x9F][\x80-\xBF]|\xF0[\x90-\xBF][\x80-\xBF]{2}|[\xF1-\xF3][\x80-\xBF]{3}|\xF4[\x80-\x8F][\x80-\xBF]{2})(*SKIP)(*FAIL)|[\x80-\xFF]/';

    // Bidi embeddings, overrides, isolates and marks, which can reorder what the reader sees.
    private const BIDI = '/[\x{202A}-\x{202E}\x{2066}-\x{2069}\x{200E}\x{200F}\x{061C}]/u';

    // C0, DEL, C1 and the Unicode line and paragraph separators.
    private const CONTROLS = '/[\x{0000}-\x{001F}\x{007F}-\x{009F}\x{2028}\x{2029}]+/u';

    // One line: invalid bytes become U+FFFD, bidi controls go, other controls become spaces.
    public static function clean(string $text): string
    {
        return trim(self::controls(self::utf8($text)));
    }

    // clean(), then `<tags>` escaped so the formatter prints them literally.
    public static function safe(string $text): string
    {
        return OutputFormatter::escape(self::defuse(self::clean($text)));
    }

    // A line starting `::` (after whitespace) can be read as a GitHub Actions workflow command.
    public static function defuse(string $line): string
    {
        return (string) preg_replace('/^(\s*)::/', '$1: :', $line);
    }

    // One line of code or diff: tabs become four spaces, indentation kept, otherwise like safe().
    public static function safeLine(string $line): string
    {
        return OutputFormatter::escape(self::defuse(rtrim(self::controls(str_replace("\t", '    ', self::utf8($line))))));
    }

    // Multi-line prose or a diff for a non-console encoding: clean per line, indentation and line breaks kept, nothing escaped.
    public static function block(string $text): string
    {
        $lines = preg_split('/\r\n|\r|\n/', self::utf8($text)) ?: [];

        return rtrim(implode("\n", array_map(static fn (string $l): string => rtrim(self::controls(str_replace("\t", '    ', $l))), $lines)), "\n");
    }

    // safe() per line, keeping the line breaks (multi-line table cells).
    public static function safeLines(string $text): string
    {
        return implode("\n", array_map(self::safe(...), explode("\n", $text)));
    }

    private static function utf8(string $text): string
    {
        return preg_match('//u', $text) === 1 ? $text : (string) preg_replace(self::INVALID_BYTE, "\u{FFFD}", $text);
    }

    // Expects valid UTF-8.
    private static function controls(string $text): string
    {
        return (string) preg_replace(self::CONTROLS, ' ', (string) preg_replace(self::BIDI, '', $text));
    }
}
