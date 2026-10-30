<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Parsing\CallGraph;

/** The bodies reachable from a route action, entry first in BFS order. */
final readonly class ExecutionPath
{
    /**
     * @param  list<PathNode>  $nodes  entry first, BFS order
     * @param  list<string>  $unresolved  "file:line: <call text>"
     */
    public function __construct(public array $nodes, public array $unresolved)
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
