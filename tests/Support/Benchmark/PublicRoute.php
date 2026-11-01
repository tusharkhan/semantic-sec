<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support\Benchmark;

/** A public-by-design route: any finding on its symbol is a violation. */
final class PublicRoute
{
    public function __construct(
        public readonly string $app,
        public readonly string $set,
        public readonly string $route,
        public readonly string $symbol,
    ) {
    }
}
