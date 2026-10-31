<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Parsing\Symbols;

use PhpParser\Node\Stmt\Function_;

/** A global (or namespaced) function the project itself defines. */
final readonly class FunctionSymbol
{
    public function __construct(
        public string $name,
        public string $file,
        public Function_ $node,
    ) {
    }

    public function id(): string
    {
        return $this->name.'()';
    }
}
