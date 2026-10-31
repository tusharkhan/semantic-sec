<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Framework\Laravel;

enum MiddlewareKind: string
{
    case Authentication = 'authentication';
    case Ability = 'ability';
    case Authorization = 'authorization';
    case Other = 'other';
}
