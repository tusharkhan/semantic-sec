<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Framework\Laravel;

final readonly class AuthCheck
{
    public function __construct(
        public AuthCheckKind $kind,
        public AuthStrength $strength,
        public string $source,
        public string $file,
        public int $line,
        public ?string $covers = null, // route parameter this check is proven to protect; null = route-wide or unknown
        public ?string $model = null, // query_scope only: FQN of the model the scoped query reads, when known
        public bool $routeWide = false, // an ability with no model argument, a role check or `can:` with no arguments
    ) {
    }
}
