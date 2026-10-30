<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Framework\Laravel;

enum AuthStrength: string
{
    case None = 'none';
    case Authentication = 'authentication';
    case Authorization = 'authorization';
}
