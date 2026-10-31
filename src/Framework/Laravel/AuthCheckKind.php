<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Framework\Laravel;

enum AuthCheckKind: string
{
    case Authentication = 'authentication';
    case RouteAbility = 'route_ability';
    case ControllerAbility = 'controller_ability';
    case FormRequest = 'form_request';
    case AbortGuard = 'abort_guard';
    case QueryScope = 'query_scope';
    case CustomHelper = 'custom_helper';
    case Middleware = 'middleware';
}
