<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Payload;

final class TokenEstimator
{
    /** Deliberately pessimistic: ceil(bytes / 3.5). */
    public static function estimate(string $text): int
    {
        return self::forBytes(strlen($text));
    }

    public static function forBytes(int $bytes): int
    {
        return (int) ceil($bytes / 3.5);
    }
}
