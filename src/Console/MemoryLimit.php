<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Console;

/** Raises PHP's memory limit for real projects; SEMANTIC_SEC_MEMORY_LIMIT overrides it. */
final class MemoryLimit
{
    private const TARGET = '1G';

    private const TARGET_BYTES = 1 << 30;

    public static function apply(?string $env): void
    {
        if ($env !== null && trim($env) !== '') {
            ini_set('memory_limit', trim($env));

            return;
        }
        if (self::shouldRaise((string) ini_get('memory_limit'))) {
            ini_set('memory_limit', self::TARGET);
        }
    }

    public static function shouldRaise(string $current): bool
    {
        $bytes = self::bytes($current);

        return $bytes !== null && $bytes !== -1 && $bytes < self::TARGET_BYTES;
    }

    // Parses php.ini shorthand (128M, 1G, 512K, bytes); null when unparseable.
    private static function bytes(string $value): ?int
    {
        if (preg_match('/^\s*(-?\d+)\s*([kmg]?)\s*$/i', $value, $m) !== 1) {
            return null;
        }
        $n = (int) $m[1];
        if ($n < 0) {
            return -1;
        }

        return $n * match (strtolower($m[2])) {
            'k' => 1 << 10,
            'm' => 1 << 20,
            'g' => 1 << 30,
            default => 1,
        };
    }
}
