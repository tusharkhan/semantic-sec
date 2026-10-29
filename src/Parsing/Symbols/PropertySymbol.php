<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Parsing\Symbols;

final readonly class PropertySymbol
{
    public function __construct(public string $name, public ?string $type, public int $line, public ?\PhpParser\Node\Expr $default)
    {
    }
}
