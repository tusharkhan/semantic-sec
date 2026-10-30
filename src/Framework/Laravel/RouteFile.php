<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Framework\Laravel;

final readonly class RouteFile
{
    /** @param list<string> $middleware */
    public function __construct(public string $path, public string $prefix, public array $middleware, public ?string $namespace)
    {
    }
}
