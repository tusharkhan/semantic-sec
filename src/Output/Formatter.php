<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Output;

use TusharKhan\SemanticSec\Engine\AnalysisResult;

/**
 * Renders one analysis run as the final bytes for stdout or --output.
 *
 * @phpstan-type Meta array{tool: string, version: string, provider: string, model: string, strictReason?: string|null, level?: string, budget?: int|null, exitCode?: int}
 */
interface Formatter
{
    /** @param Meta $meta */
    public function format(AnalysisResult $r, array $meta): string;
}
