<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Payload;

final class TokenEstimator
{
    /** Deliberately pessimistic: ceil(bytes / 3.5). */
    public static function estimate(string $text): int
    {
        return (int) ceil(strlen($text) / 3.5);
    }
}
