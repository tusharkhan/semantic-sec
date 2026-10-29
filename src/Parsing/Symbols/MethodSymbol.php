<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Parsing\Symbols;

use PhpParser\Node\Stmt\ClassMethod;

final readonly class MethodSymbol
{
    /** @param array<string, ?string> $params name => type */
    public function __construct(
        public string $class,
        public string $name,
        public string $file,
        public int $startLine,
        public int $endLine,
        public array $params,
        public ?string $returnType,
        public bool $static,
        public ClassMethod $node,
    ) {
    }

    public function id(): string
    {
        return $this->class.'::'.$this->name;
    }
}
