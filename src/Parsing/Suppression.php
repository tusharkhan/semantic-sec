<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Parsing;

use TusharKhan\SemanticSec\Analysis\Category;

final readonly class Suppression
{
    public function __construct(
        public string $file,
        public ?Category $category,
        public int $startLine,
        public int $endLine,
        public int $commentLine,
        public ?string $reason,
    ) {
    }

    public function covers(int $line, Category $category): bool
    {
        return $line >= $this->startLine
            && $line <= $this->endLine
            && ($this->category === null || $this->category === $category);
    }
}
