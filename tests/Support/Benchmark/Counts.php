<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support\Benchmark;

/** Tallies for one slice (set, app, failing-only); rates are null when there is nothing to divide by. */
final class Counts
{
    public function __construct(
        public readonly int $cases = 0,
        public readonly int $found = 0,
        public readonly int $flagged = 0,
        public readonly int $publicRoutes = 0,
        public readonly int $publicViolations = 0,
        public readonly int $mapVariants = 0,
        public readonly int $mapMismatches = 0,
        public readonly int $unattributed = 0,
    ) {
    }

    public function foundRate(): ?float
    {
        return $this->cases === 0 ? null : $this->found / $this->cases;
    }

    public function flaggedRate(): ?float
    {
        return $this->cases === 0 ? null : $this->flagged / $this->cases;
    }

    public function mapRate(): ?float
    {
        return $this->mapVariants === 0 ? null : ($this->mapVariants - $this->mapMismatches) / $this->mapVariants;
    }
}
