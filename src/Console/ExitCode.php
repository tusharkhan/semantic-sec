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

    // SPEC §13: a failing finding beats the budget, which beats "every request failed" (plan decision 4).
    public static function for(AnalysisResult $result): int
    {
        foreach ($result->findings as $finding) {
            if ($finding['failing']) {
                return self::FINDINGS;
            }
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
}
