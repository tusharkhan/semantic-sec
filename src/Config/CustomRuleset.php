<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Config;

final readonly class CustomRuleset
{
    public function __construct(public string $name, public string $prompt)
    {
    }
}
