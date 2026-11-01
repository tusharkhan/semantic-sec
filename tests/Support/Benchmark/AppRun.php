<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support\Benchmark;

/** @phpstan-import-type Usage from Report */
final class AppRun
{
    /**
     * @param array<mixed> $analyze
     * @param array<mixed> $map
     * @param array<mixed> $dryRun
     * @param Usage $usage
     * @param list<string> $models
     */
    public function __construct(
        public readonly string $app,
        public readonly array $analyze,
        public readonly array $map,
        public readonly array $dryRun,
        public readonly array $usage,
        public readonly array $models,
        public readonly int $requests,
    ) {
    }
}
