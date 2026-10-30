<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Framework\Laravel;

use PhpParser\Node;
use PhpParser\Node\Expr;

/** Reads string-or-array arguments (middleware, methods, ability models) into a flat string list. */
final class StringListReader
{
    public function __construct(private readonly ConstantEvaluator $eval)
    {
    }

    /**
     * Skips null items and keeps every resolvable item, warning about the rest.
     *
     * @param  list<Expr>  $args
     * @param  list<string>  $warnings
     * @return list<string>
     */
    public function stringList(array $args, string $file, int $line, string $what, array &$warnings): array
    {
        return $this->read($args, $file, $line, $what, $warnings, false) ?? [];
    }

    /**
     * Like stringList(), but any null or unresolvable item makes the whole list null.
     *
     * @param  list<Expr>  $args
     * @param  list<string>  $warnings
     * @return list<string>|null
     */
    public function strictStringList(array $args, string $file, int $line, string $what, array &$warnings): ?array
    {
        return $this->read($args, $file, $line, $what, $warnings, true);
    }

    /**
     * @param  list<Expr>  $args
     * @param  list<string>  $warnings
     * @return list<string>|null
     */
    private function read(array $args, string $file, int $line, string $what, array &$warnings, bool $strict): ?array
    {
        $out = [];
        $failed = false;
        foreach ($args as $value) {
            foreach ($value instanceof Expr\Array_ ? $value->items : [$value] as $item) {
                if ($item instanceof Node\ArrayItem) {
                    if ($item->unpack) {
                        $failed = self::fail($warnings, $file, $line, $what);

                        continue;
                    }
                    $item = $item->value;
                }
                if (! $strict && $item instanceof Expr\ConstFetch && strtolower($item->name->toString()) === 'null') {
                    continue;
                }
                $str = $this->eval->string($item, $file);
                if ($str === null) {
                    $failed = self::fail($warnings, $file, $line, $what);
                } else {
                    $out[] = $str;
                }
            }
        }

        return $failed && $strict ? null : $out;
    }

    /** @param list<string> $warnings */
    private static function fail(array &$warnings, string $file, int $line, string $what): true
    {
        $warnings[] = sprintf('%s:%d: route %s could not be resolved', $file, $line, $what);

        return true;
    }
}
