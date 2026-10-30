<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Console;

final class ExitCode
{
    public const OK = 0;
    public const FINDINGS = 1;
    public const ERROR = 2;
    public const BUDGET = 3;
}
