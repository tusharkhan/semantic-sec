<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Parsing\Symbols;

final readonly class ClassSymbol
{
    /**
     * @param  'class'|'trait'|'interface'|'enum'  $kind
     * @param  list<string>  $interfaces
     * @param  list<string>  $traits
     * @param  array<string, PropertySymbol>  $properties
     * @param  array<string, MethodSymbol>  $methods  keyed by lowercased name
     */
    public function __construct(
        public string $name,
        public string $kind,
        public string $file,
        public int $startLine,
        public int $endLine,
        public ?string $parent,
        public array $interfaces,
        public array $traits,
        public array $properties,
        public array $methods,
    ) {
    }
}
