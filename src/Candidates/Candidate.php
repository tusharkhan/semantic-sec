<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Candidates;

use TusharKhan\SemanticSec\Analysis\Category;
use TusharKhan\SemanticSec\Framework\Laravel\RouteEntry;
use TusharKhan\SemanticSec\Parsing\CallGraph\ExecutionPath;

/** A route worth sending to the LLM, with the categories it was selected for and why (SPEC §7). */
final readonly class Candidate
{
    /**
     * @param  list<Category>  $categories
     * @param  array<string, string>  $reasons  category value => one-line reason
     */
    public function __construct(public RouteEntry $route, public ExecutionPath $path, public array $categories, public array $reasons)
    {
    }
}
