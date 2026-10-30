<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Framework\Laravel;

final readonly class RouteParameter
{
    public function __construct(
        public string $name,
        public ?string $field,
        public bool $optional,
        public ?string $boundModel = null,
    ) {
    }
}
