<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Llm;

use PhpParser\Node\Stmt\ClassLike;
use PhpParser\Node\Stmt\Property;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;
use TusharKhan\SemanticSec\Payload\Payload;

/**
 * Grounds findings in the shown code (SPEC §10); M6 builds on ground(), and check() returns only its reason.
 *
 * @phpstan-type Index array{tags: array<string, array<int, true>>, headers: list<array{string, string, int, int}>}
 */
final class GroundingChecker
{
    // The path is greedy up to the last " :: ", since ids never contain one.
    private const HEADER = '~^// FILE: (.+) :: (.+?) \(L(\d+)-L(\d+)\)$~';

    private const TAG = '~^L(\d+)\|~';

    private const MAX_SHOWN = 150;

    /** @var \WeakMap<Payload, Index> */
    private \WeakMap $index;

    public function __construct(private readonly SymbolTable $symbols)
    {
        $this->index = new \WeakMap();
    }

    /**
     * @param  array<mixed>  $finding  one decoded finding; any shape is tolerated
     * @return string|null null when grounded, else the drop reason
     */
    public function check(array $finding, Payload $payload): ?string
    {
        return $this->ground($finding, $payload)[1];
    }

    /**
     * @param  array<mixed>  $finding  one decoded finding; any shape is tolerated
     * @return array{0: array<mixed>, 1: null}|array{0: null, 1: string} the normalised finding (int lines, attributed symbol, pruned path), or the drop reason
     */
    public function ground(array $finding, Payload $payload): array
    {
        $index = $this->index[$payload] ??= self::parse($payload->code);

        $file = $finding['file'] ?? null;
        if (!is_string($file) || !isset($index['tags'][$file])) {
            return [null, 'file '.self::show($file).' not in payload'];
        }
        $line = self::line($finding['line'] ?? null);
        if ($line === null || !isset($index['tags'][$file][$line])) {
            return [null, 'line L'.self::show($finding['line'] ?? null).' not in payload'];
        }
        $symbol = $finding['symbol'] ?? null;
        if (!$this->fits($symbol, $file, $line, $index)) {
            $header = self::header($index, $file, $line);
            if ($header === null) {
                return [null, "line {$line} outside ".self::show($symbol)];
            }
            $symbol = $header;
        }

        $path = [];
        foreach (is_array($finding['path'] ?? null) ? $finding['path'] : [] as $step) {
            $stepFile = is_array($step) ? ($step['file'] ?? null) : null;
            $stepLine = is_array($step) ? self::line($step['line'] ?? null) : null;
            if (is_string($stepFile) && $stepLine !== null && isset($index['tags'][$stepFile][$stepLine])) {
                $path[] = ['file' => $stepFile, 'line' => $stepLine, 'symbol' => is_string($step['symbol'] ?? null) ? $step['symbol'] : ''];
            }
        }

        return [[...$finding, 'line' => $line, 'symbol' => $symbol, 'path' => $path], null];
    }

    // True when the symbol may stand: unknown to the table, its span holds the line, or it is class-level and declared outside the payload.
    /** @param Index $index */
    private function fits(mixed $symbol, string $file, int $line, array $index): bool
    {
        if (!is_string($symbol)) {
            return false;
        }
        $span = $this->span($symbol);
        if ($span === null || ($span[0] === $file && $line >= $span[1] && $line <= $span[2])) {
            return true;
        }

        return $span[3] && !isset($index['tags'][$span[0]]);
    }

    // The id of the smallest header range in the file that holds the line.
    /** @param Index $index */
    private static function header(array $index, string $file, int $line): ?string
    {
        $best = null;
        foreach ($index['headers'] as [$hFile, $id, $from, $to]) {
            if ($hFile === $file && $line >= $from && $line <= $to && ($best === null || $to - $from < $best[1])) {
                $best = [$id, $to - $from];
            }
        }

        return $best[0] ?? null;
    }

    // An int, or an integral float such as 19.0; anything else is no line.
    private static function line(mixed $value): ?int
    {
        return match (true) {
            is_int($value) => $value,
            is_float($value) && is_finite($value) && floor($value) === $value && abs($value) < PHP_INT_MAX => (int) $value,
            default => null,
        };
    }

    // File => tagged lines, and every header, from the fenced code only; a tag belongs to the nearest header above it.
    /** @return Index */
    private static function parse(string $code): array
    {
        $tags = [];
        $headers = [];
        $file = null;
        foreach (explode("\n", $code) as $text) {
            if (preg_match(self::HEADER, $text, $m) === 1) {
                $file = $m[1];
                $tags[$file] ??= [];
                $headers[] = [$file, $m[2], (int) $m[3], (int) $m[4]];
            } elseif ($file !== null && preg_match(self::TAG, $text, $m) === 1) {
                $tags[$file][(int) $m[1]] = true;
            }
        }

        return ['tags' => $tags, 'headers' => $headers];
    }

    // [file, first line, last line, class-level] of a Class, Class::method or Class::$prop the table knows; null skips the span check.
    /** @return array{string, int, int, bool}|null */
    private function span(string $symbol): ?array
    {
        $symbol = ltrim(trim($symbol), '\\');
        $at = strpos($symbol, '::');
        if ($at === false) {
            $class = $this->symbols->getClass($symbol);

            return $class === null ? null : [$class->file, self::docStart($class->node, $class->startLine), $class->endLine, true];
        }
        $class = substr($symbol, 0, $at);
        $member = substr($symbol, $at + 2);
        if (!str_starts_with($member, '$')) {
            $method = $this->symbols->findMethod($class, preg_replace('~\(\)$~', '', $member) ?? $member);

            return $method === null ? null : [$method->file, self::docStart($method->node, $method->startLine), $method->endLine, false];
        }

        $name = substr($member, 1);
        if ($this->symbols->findProperty($class, $name) === null) {
            return null;
        }
        foreach ($this->symbols->lineage($class) as $owner) {
            $prop = $owner->properties[$name] ?? null;
            if ($prop !== null) {
                return [$owner->file, self::propertyStart($owner->node, $name, $prop->line), $prop->line, true];
            }
        }

        return null;
    }

    private static function docStart(\PhpParser\Node $node, int $start): int
    {
        return min($start, $node->getDocComment()?->getStartLine() ?? $start);
    }

    // The declaring statement's first line, or its docblock's; a promoted constructor parameter keeps its own line.
    private static function propertyStart(ClassLike $class, string $name, int $line): int
    {
        foreach ($class->stmts as $stmt) {
            if (!$stmt instanceof Property) {
                continue;
            }
            foreach ($stmt->props as $item) {
                if ($item->name->toString() === $name) {
                    return min($line, self::docStart($stmt, $stmt->getStartLine()));
                }
            }
        }

        return $line;
    }

    // A model value for a drop reason: one line, short.
    private static function show(mixed $value): string
    {
        $text = match (true) {
            is_string($value) => $value,
            is_int($value) => (string) $value,
            is_float($value) => var_export($value, true),
            is_bool($value) => $value ? 'true' : 'false',
            default => get_debug_type($value),
        };
        $text = (string) preg_replace('/[\x00-\x1F\x7F]+/', ' ', $text);

        return mb_strlen($text) > self::MAX_SHOWN ? mb_substr($text, 0, self::MAX_SHOWN - 1).'…' : $text;
    }
}
