<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Console;

use TusharKhan\SemanticSec\Engine\AnalysisResult;

final class ExitCode
{
    public const OK = 0;
    public const FINDINGS = 1;
    public const ERROR = 2;
    public const BUDGET = 3;

    // Stats that fail a --strict run, in the order the reason names them.
    private const STRICT = ['failed', 'refused', 'invalid', 'truncated', 'unsent'];

    // SPEC §13 precedence: 1 > strict-2 > 3 > all-failed-2 > 0.
    public static function for(AnalysisResult $result, bool $strict): int
    {
        if (self::hasFailing($result)) {
            return self::FINDINGS;
        }
        if ($strict && self::strictCounts($result) !== []) {
            return self::ERROR;
        }
        $s = $result->stats;
        if ($s['budgetExceeded']) {
            return self::BUDGET;
        }
        if ($s['sent'] + $s['cacheHits'] > 0 && $s['ok'] + $s['cacheHits'] === 0) {
            return self::ERROR;
        }

        return self::OK;
    }

    // The summary line when --strict decides the exit code, e.g. "strict: 3 failed, 2 unsent"; null otherwise.
    public static function strictReason(AnalysisResult $result, bool $strict): ?string
    {
        $counts = self::strictCounts($result);
        if (! $strict || $counts === [] || self::hasFailing($result)) {
            return null;
        }
        $parts = [];
        foreach ($counts as $stat => $n) {
            $parts[] = $n.' '.$stat;
        }

        return 'strict: '.implode(', ', $parts);
    }

    private static function hasFailing(AnalysisResult $result): bool
    {
        foreach ($result->findings as $finding) {
            if ($finding['failing']) {
                return true;
            }
        }

        return false;
    }

    /** @return array<string, int> the non-zero strict stats */
    private static function strictCounts(AnalysisResult $result): array
    {
        $out = [];
        foreach (self::STRICT as $stat) {
            $n = $result->stats[$stat];
            if ($n > 0) {
                $out[$stat] = $n;
            }
        }

        return $out;
    }
}
