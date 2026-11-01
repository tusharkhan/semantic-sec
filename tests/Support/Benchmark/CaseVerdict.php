<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support\Benchmark;

/**
 * How one case scored; each *By is the finding that decided it, null when none did; *Strict ignores post-hoc accepts.
 *
 * @phpstan-type Finding array{list: string, category: string, confidence: string, file: string, line: int, symbol: string, title: string}
 * @phpstan-type MapCheck array{expected: list<string>, actual: list<string>|null, ok: bool}
 */
final class CaseVerdict
{
    /**
     * @param Finding|null $foundBy
     * @param Finding|null $flaggedBy
     * @param MapCheck $mapVulnerable
     * @param MapCheck $mapSafe
     * @param list<string>|null $vulnerableCategories categories the vulnerable route was selected for; null when not measured
     * @param list<string>|null $safeCategories
     */
    public function __construct(
        public readonly BenchmarkCase $case,
        public readonly bool $found,
        public readonly ?array $foundBy,
        public readonly bool $foundFailing,
        public readonly bool $flagged,
        public readonly ?array $flaggedBy,
        public readonly bool $flaggedFailing,
        public readonly array $mapVulnerable,
        public readonly array $mapSafe,
        public readonly ?bool $selectedVulnerable,
        public readonly ?array $vulnerableCategories,
        public readonly ?bool $selectedSafe,
        public readonly ?array $safeCategories,
        public readonly bool $foundStrict = false,
        public readonly bool $foundStrictFailing = false,
    ) {
    }
}
