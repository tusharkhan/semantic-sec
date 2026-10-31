<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Engine;

use TusharKhan\SemanticSec\Parsing\Suppression;

/**
 * What one engine run produced; payloads = skipped + unsent + cacheHits + sent, and sent = ok + refused + truncated + invalid + failed.
 * skipped: no source code; unsent: stopped by the budget; filtered: count of findings below `level`, which are kept in $filtered.
 *
 * @phpstan-type Stats array{candidates:int, payloads:int, skipped:int, unsent:int, sent:int, cacheHits:int, ok:int, refused:int, truncated:int, invalid:int, failed:int, dropped:int, filtered:int, tokens:int, budgetExceeded:bool}
 */
final readonly class AnalysisResult
{
    /**
     * @param list<array{vulnerability: Vulnerability, failing: bool}> $findings
     * @param list<array{vulnerability: Vulnerability, suppression: Suppression}> $suppressed
     * @param list<Vulnerability> $baselined
     * @param list<string> $warnings
     * @param Stats $stats
     * @param list<Vulnerability> $filtered findings below `level`, kept for baselines and reports
     */
    public function __construct(
        public array $findings,
        public array $suppressed,
        public array $baselined,
        public array $warnings,
        public array $stats,
        public array $filtered = [],
    ) {
    }
}
