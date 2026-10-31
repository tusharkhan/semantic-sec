<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Llm;

use PhpParser\Node\Stmt\ClassLike;
use PhpParser\Node\Stmt\Property;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;
use TusharKhan\SemanticSec\Payload\Payload;

/** Drops findings not anchored in the shown code (SPEC §10); spans start at a docblock, and a property's ends at its own line. */
final class GroundingChecker
{
    private const HEADER = '~^// FILE: (.+?) :: .* \(L\d+-L\d+\)$~';

    private const TAG = '~^L(\d+)\|~';

    private const MAX_SHOWN = 150;

    /** @var \WeakMap<Payload, array<string, array<int, true>>> */
    private \WeakMap $tags;

    public function __construct(private readonly SymbolTable $symbols)
    {
        $this->tags = new \WeakMap();
    }

    /**
     * @param  array<mixed>  $finding  one decoded finding; any shape is tolerated
     * @return string|null null when grounded, else the drop reason
     */
    public function check(array $finding, Payload $payload): ?string
    {
        $tags = $this->tags[$payload] ??= self::parse($payload->code);

        $file = $finding['file'] ?? null;
        if (!is_string($file) || !isset($tags[$file])) {
            return 'file '.self::show($file).' not in payload';
        }
        $line = $finding['line'] ?? null;
        if (!is_int($line) || !isset($tags[$file][$line])) {
            return 'line L'.self::show($line).' not in payload';
        }
        $symbol = $finding['symbol'] ?? null;
        $span = is_string($symbol) ? $this->span($symbol) : null;
        if ($span !== null && ($span[0] !== $file || $line < $span[1] || $line > $span[2])) {
            return "line {$line} outside ".self::show($symbol);
        }

        $path = array_key_exists('path', $finding) ? $finding['path'] : [];
        if (!is_array($path)) {
            return 'path step 0 not in payload';
        }
        foreach (array_values($path) as $i => $step) {
            $stepFile = is_array($step) ? ($step['file'] ?? null) : null;
            $stepLine = is_array($step) ? ($step['line'] ?? null) : null;
            if (!is_string($stepFile) || !is_int($stepLine) || !isset($tags[$stepFile][$stepLine])) {
                return "path step {$i} not in payload";
            }
        }

        return null;
    }

    // File => tagged lines, from the fenced code only; a tag belongs to the nearest header above it.
    /** @return array<string, array<int, true>> */
    private static function parse(string $code): array
    {
        $tags = [];
        $file = null;
        foreach (explode("\n", $code) as $text) {
            if (preg_match(self::HEADER, $text, $m) === 1) {
                $file = $m[1];
                $tags[$file] ??= [];
            } elseif ($file !== null && preg_match(self::TAG, $text, $m) === 1) {
                $tags[$file][(int) $m[1]] = true;
            }
        }

        return $tags;
    }

    // [file, first line, last line] of a Class, Class::method or Class::$prop the table knows; null skips the span check.
    /** @return array{string, int, int}|null */
    private function span(string $symbol): ?array
    {
        $symbol = ltrim(trim($symbol), '\\');
        $at = strpos($symbol, '::');
        if ($at === false) {
            $class = $this->symbols->getClass($symbol);

            return $class === null ? null : [$class->file, self::docStart($class->node, $class->startLine), $class->endLine];
        }
        $class = substr($symbol, 0, $at);
        $member = substr($symbol, $at + 2);
        if (!str_starts_with($member, '$')) {
            $method = $this->symbols->findMethod($class, preg_replace('~\(\)$~', '', $member) ?? $member);

            return $method === null ? null : [$method->file, self::docStart($method->node, $method->startLine), $method->endLine];
        }

        $name = substr($member, 1);
        if ($this->symbols->findProperty($class, $name) === null) {
            return null;
        }
        foreach ($this->symbols->lineage($class) as $owner) {
            $prop = $owner->properties[$name] ?? null;
            if ($prop !== null) {
                return [$owner->file, self::propertyStart($owner->node, $name, $prop->line), $prop->line];
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
