<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Candidates;

use TusharKhan\SemanticSec\Analysis\Category;

/** Why a route was not selected for a category (null: for any category), and the check that justifies it. */
final readonly class Exclusion
{
    public function __construct(public string $routeKey, public ?Category $category, public string $reason, public string $checkSource)
    {
    }
}
