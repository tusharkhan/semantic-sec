<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Framework\Laravel;

use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;

/** Walks a class's parent chain through the symbol table, including the first out-of-table parent. */
final class Ancestry
{
    /** @param list<string> $bases */
    public static function descendsFrom(SymbolTable $symbols, ?string $class, array $bases): bool
    {
        $seen = [];
        while ($class !== null) {
            $class = ltrim($class, '\\');
            if (isset($seen[$class])) {
                return false;
            }
            if (in_array($class, $bases, true)) {
                return true;
            }
            $seen[$class] = true;
            $class = $symbols->getClass($class)?->parent;
        }

        return false;
    }
}
