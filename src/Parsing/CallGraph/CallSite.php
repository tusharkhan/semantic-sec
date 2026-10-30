<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Parsing\CallGraph;

/** Where a callee was called from; conditional when the call sits inside a branch, loop or short-circuit. */
final readonly class CallSite
{
    public function __construct(public string $file, public int $line, public bool $conditional)
    {
    }
}
