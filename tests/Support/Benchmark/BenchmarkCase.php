<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support\Benchmark;

/** One expected.yaml case: a vulnerable and a safe variant of the same flaw. */
final class BenchmarkCase
{
    public function __construct(
        public readonly string $id,
        public readonly string $app,
        public readonly string $set,
        public readonly string $category,
        public readonly Variant $vulnerable,
        public readonly Variant $safe,
    ) {
    }
}
