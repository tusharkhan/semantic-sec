<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Parsing\CallGraph;

use PhpParser\Node;
use TusharKhan\SemanticSec\Parsing\Symbols\MethodSymbol;

/** One function body on an execution path: a method or a closure. */
final readonly class PathNode
{
    /**
     * @param  string  $id  "Class::method" or "closure@<file>:<line>"
     * @param  ?string  $calledBy  parent PathNode id
     * @param  ?string  $closureClass  the class `$this` is bound to when known: for a closure, or for a trait method the using class
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
    ) {
    }
}
