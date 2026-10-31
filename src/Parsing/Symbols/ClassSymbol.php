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
     * @param  array<string, string>  $docProperties  class-level @property* name => type
     * @param  array<string, string>  $docMethods  class-level @method lowercased name => return type
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
        public \PhpParser\Node\Stmt\ClassLike $node,
        public array $docProperties = [],
        public array $docMethods = [],
    ) {
    }
}
