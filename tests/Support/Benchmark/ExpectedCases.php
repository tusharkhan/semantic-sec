<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support\Benchmark;

use Symfony\Component\Yaml\Yaml;

/** Reads benchmark/expected.yaml text; CorpusIntegrityTest validates the real file, so this only types it. */
final class ExpectedCases
{
    /** @return list<BenchmarkCase> */
    public static function load(string $yaml): array
    {
        $cases = [];
        foreach (self::section($yaml, 'cases') as $case) {
            $cases[] = new BenchmarkCase(
                self::string($case, 'id'),
                self::string($case, 'app'),
                self::set($case),
                self::string($case, 'category'),
                self::variant(self::map($case, 'vulnerable')),
                self::variant(self::map($case, 'safe')),
            );
        }

        return $cases;
    }

    /** @return list<PublicRoute> */
    public static function publicRoutes(string $yaml): array
    {
        $routes = [];
        foreach (self::section($yaml, 'public_routes') as $route) {
            $routes[] = new PublicRoute(self::string($route, 'app'), self::set($route), self::string($route, 'route'), self::symbol(self::string($route, 'symbol')));
        }

        return $routes;
    }

    // App\X\Y::m lives in app/X/Y.php.
    public static function fileOf(string $symbol): string
    {
        $class = explode('::', self::symbol($symbol))[0];

        return 'app/'.str_replace('\\', '/', (string) preg_replace('/^App\\\\/', '', $class)).'.php';
    }

    public static function symbol(string $symbol): string
    {
        return ltrim($symbol, '\\');
    }

    /** @param array<mixed> $data */
    private static function variant(array $data): Variant
    {
        $symbol = self::symbol(self::string($data, 'symbol'));
        $accept = array_map(static fn (mixed $s): string => self::symbol(is_string($s) ? $s : ''), is_array($data['accept'] ?? null) ? array_values($data['accept']) : []);

        return new Variant(
            self::string($data, 'route'),
            $symbol,
            self::fileOf($symbol),
            array_values(array_map(static fn (mixed $k): string => is_string($k) ? $k : '', is_array($data['map'] ?? null) ? $data['map'] : [])),
            is_int($data['line'] ?? null) ? $data['line'] : null,
            ($data['suppressed'] ?? false) === true,
            $accept,
            is_bool($data['candidate'] ?? null) ? $data['candidate'] : null,
        );
    }

    /** @return list<array<mixed>> */
    private static function section(string $yaml, string $key): array
    {
        $data = Yaml::parse($yaml);
        $items = is_array($data) && is_array($data[$key] ?? null) ? $data[$key] : [];

        return array_values(array_filter($items, is_array(...)));
    }

    /** @param array<mixed> $item */
    private static function set(array $item): string
    {
        return is_string($item['set'] ?? null) ? $item['set'] : 'existing';
    }

    /**
     * @param array<mixed> $item
     *
     * @return array<mixed>
     */
    private static function map(array $item, string $key): array
    {
        return is_array($item[$key] ?? null) ? $item[$key] : throw new \InvalidArgumentException("expected.yaml: {$key} must be a mapping");
    }

    /** @param array<mixed> $item */
    private static function string(array $item, string $key): string
    {
        return is_string($item[$key] ?? null) && $item[$key] !== '' ? $item[$key] : throw new \InvalidArgumentException("expected.yaml: {$key} must be a non-empty string");
    }
}
