<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Parsing\Symbols;

use PhpParser\Node\Stmt\ClassMethod;

final readonly class MethodSymbol
{
    /**
     * @param  array<string, ?string>  $params  name => type
     * @param  array<int, array<string, string>>  $docVars  start file position of a `$x = …;` statement => var name => its `@var` class type
     */
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
        public ?string $returnGeneric = null, // first class-like generic argument of the docblock return type
        public array $docVars = [],
        public bool $returnsStatic = false, // declared `static` or `$this`: the receiver's class
        public bool $returnsSelf = false, // declared `self`: the declaring class or any subclass
        public bool $returnAmbiguous = false, // two or more class-like members (or `parent`); returnType is only a hint
    ) {
    }

    public function id(): string
    {
        return $this->class.'::'.$this->name;
    }
}
