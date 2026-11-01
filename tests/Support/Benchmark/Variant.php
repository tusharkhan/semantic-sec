<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support\Benchmark;

/** One side of a benchmark case; $file is the symbol's file relative to the app root; $posthoc marks $accept as added after a live run. */
final class Variant
{
    /**
     * @param list<string> $map
     * @param list<string> $accept
     */
    public function __construct(
        public readonly string $route,
        public readonly string $symbol,
        public readonly string $file,
        public readonly array $map,
        public readonly ?int $line = null,
        public readonly bool $suppressed = false,
        public readonly array $accept = [],
        public readonly ?bool $candidate = null,
        public readonly bool $posthoc = false,
    ) {
    }
}
