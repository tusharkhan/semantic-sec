<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Parsing;

final readonly class SuppressionSet
{
    /**
     * @param  list<object>  $suppressions  Task 12 narrows this to list<Suppression>.
     * @param  list<string>  $invalid
     */
    public function __construct(public array $suppressions, public array $invalid)
    {
    }
}
