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
    ) {
    }
}
