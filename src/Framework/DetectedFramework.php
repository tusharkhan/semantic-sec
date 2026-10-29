<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Framework;

final readonly class DetectedFramework
{
    public function __construct(public string $name, public ?int $majorVersion)
    {
    }
}
