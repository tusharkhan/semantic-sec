<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Framework\Laravel;

final readonly class AuthorizationMap
{
    /**
     * @param  list<RouteEntry>  $routes
     * @param  list<string>  $warnings
     */
    public function __construct(public array $routes, public array $warnings)
    {
    }

    public function find(string $key): ?RouteEntry
    {
        foreach ($this->routes as $route) {
            if (in_array($key, $route->keys(), true)) {
                return $route;
            }
        }

        return null;
    }
}
