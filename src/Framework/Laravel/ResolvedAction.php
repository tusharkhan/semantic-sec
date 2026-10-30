<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Framework\Laravel;

/** A route action plus what an action array may add to the route (middleware, name) and the warnings raised. */
final readonly class ResolvedAction
{
    /**
     * @param  list<string>  $middleware
     * @param  list<string>  $warnings
     */
    public function __construct(
        public RouteAction $action,
        public array $middleware = [],
        public ?string $name = null,
        public array $warnings = [],
    ) {
    }
}
