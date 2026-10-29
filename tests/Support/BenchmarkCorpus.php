<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support;

use Symfony\Component\Yaml\Yaml;

final class BenchmarkCorpus
{
    public static function root(): string
    {
        return dirname(__DIR__, 2) . '/benchmark';
    }

    /** @return list<array<string, mixed>> */
    public static function cases(): array
    {
        return self::list('cases');
    }

    /** @return list<array<string, mixed>> */
    public static function publicRoutes(): array
    {
        return self::list('public_routes');
    }

    // Maps App\X\Y::m to <root>/<app>/app/X/Y.php.
    public static function fileForSymbol(string $app, string $symbol): string
    {
        $class = explode('::', $symbol)[0];
        $relative = preg_replace('/^App\\\\/', '', $class) ?? $class;

        return self::root() . '/' . $app . '/app/' . str_replace('\\', '/', $relative) . '.php';
    }

    /** @return list<array<string, mixed>> */
    private static function list(string $key): array
    {
        $data = Yaml::parseFile(self::root() . '/expected.yaml');
        $items = is_array($data) ? ($data[$key] ?? null) : null;

        if (! is_array($items)) {
            return [];
        }

        /** @var list<array<string, mixed>> */
        return array_values($items);
    }
}
