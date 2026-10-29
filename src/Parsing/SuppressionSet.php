<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Parsing;

use TusharKhan\SemanticSec\Analysis\Category;

final readonly class SuppressionSet
{
    /**
     * @param  list<Suppression>  $suppressions
     * @param  list<string>  $invalid
     */
    public function __construct(public array $suppressions, public array $invalid)
    {
    }

    public function find(int $line, Category $category): ?Suppression
    {
        foreach ($this->suppressions as $suppression) {
            if ($suppression->covers($line, $category)) {
                return $suppression;
            }
        }

        return null;
    }

    /** @return list<Suppression> */
    public function withoutReason(): array
    {
        return array_values(array_filter(
            $this->suppressions,
            static fn (Suppression $s): bool => $s->reason === null,
        ));
    }
}
