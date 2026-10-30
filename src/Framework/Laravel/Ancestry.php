<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Framework\Laravel;

use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;

/** Whether a class is, or descends from, one of the bases; the walk lives in SymbolTable::isSubclassOf. */
final class Ancestry
{
    /** @param list<string> $bases */
    public static function descendsFrom(SymbolTable $symbols, ?string $class, array $bases): bool
    {
        if ($class === null) {
            return false;
        }
        $class = ltrim($class, '\\');
        foreach ($bases as $base) {
            if ($class === ltrim($base, '\\') || $symbols->isSubclassOf($class, $base)) {
                return true;
            }
        }

        return false;
    }
}
