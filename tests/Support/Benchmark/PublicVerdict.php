<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support\Benchmark;

/** @phpstan-import-type Finding from CaseVerdict */
final class PublicVerdict
{
    /**
     * @param Finding|null $by first finding on the route's symbol
     * @param Finding|null $byFailing first such finding at medium or high confidence
     */
    public function __construct(
        public readonly PublicRoute $route,
        public readonly ?array $by,
        public readonly ?array $byFailing,
    ) {
    }
}
