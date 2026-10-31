<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Engine;

use TusharKhan\SemanticSec\Parsing\Suppression;

/**
 * What one engine run produced; payloads = skipped + cacheHits + sent, and sent = ok + refused + truncated + invalid + failed.
 *
 * @phpstan-type Stats array{candidates:int, payloads:int, skipped:int, sent:int, cacheHits:int, ok:int, refused:int, truncated:int, invalid:int, failed:int, dropped:int, tokens:int, budgetExceeded:bool}
 */
final readonly class AnalysisResult
{
    /**
     * @param list<array{vulnerability: Vulnerability, failing: bool}> $findings
     * @param list<array{vulnerability: Vulnerability, suppression: Suppression}> $suppressed
     * @param list<Vulnerability> $baselined
     * @param list<string> $warnings
     * @param Stats $stats
     */
    public function __construct(
        public array $findings,
        public array $suppressed,
        public array $baselined,
        public array $warnings,
        public array $stats,
    ) {
    }
}
