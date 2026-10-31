<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Llm;

enum LlmOutcome: string
{
    case Ok = 'ok';
    case Refused = 'refused';
    case Truncated = 'truncated';
    case Invalid = 'invalid';
}
