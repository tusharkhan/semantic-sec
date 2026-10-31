<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Framework\Laravel;

use PhpParser\Node\Expr;
use TusharKhan\SemanticSec\Parsing\Symbols\MethodSymbol;

/** One `Gate::define()` call: its callback when the symbol table resolves it, else why not. */
final readonly class GateDefinition
{
    public function __construct(
        public string $ability,
        public string $file,
        public int $line,
        public ?MethodSymbol $method,
        public Expr\Closure|Expr\ArrowFunction|null $closure,
        public ?string $unresolved,
    ) {
    }
}
