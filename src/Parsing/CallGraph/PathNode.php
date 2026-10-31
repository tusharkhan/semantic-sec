<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Parsing\CallGraph;

use PhpParser\Node;
use TusharKhan\SemanticSec\Parsing\Symbols\MethodSymbol;

/** One function body on an execution path: a method, a closure, or an app function (closure holds its Function_). */
final readonly class PathNode
{
    /**
     * @param  string  $id  "Class::method", "closure@<file>:<line>" or "name()" for an app function
     * @param  ?string  $calledBy  parent PathNode id
     * @param  ?string  $closureClass  the class `$this` is bound to when known: for a closure, for a trait method the using class, or for an inherited method the subclass
     * @param  bool  $assumed  reached through an assumed sole implementation, here or upstream
     */
    public function __construct(
        public string $id,
        public ?MethodSymbol $method,
        public ?Node\FunctionLike $closure,
        public string $file,
        public int $startLine,
        public int $endLine,
        public int $depth,
        public ?CallSite $calledFrom,
        public ?string $calledBy,
        public ?string $closureClass = null,
        public bool $assumed = false,
    ) {
    }
}
