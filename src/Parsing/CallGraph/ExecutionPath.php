<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Parsing\CallGraph;

/** The bodies reachable from a route action, entry first in BFS order. */
final readonly class ExecutionPath
{
    /**
     * @param  list<PathNode>  $nodes  entry first, BFS order
     * @param  list<string>  $unresolved  "file:line: <call text>"
     * @param  list<array{caller: string, start: int, end: int, callee: string}>  $edges  every call site resolved to a node (already-visited ones too), by the call's file positions
     */
    public function __construct(public array $nodes, public array $unresolved, public array $edges = [])
    {
        if ($nodes === []) {
            throw new \InvalidArgumentException('An execution path needs an entry node');
        }
    }

    public function entry(): PathNode
    {
        return $this->nodes[0];
    }
}
