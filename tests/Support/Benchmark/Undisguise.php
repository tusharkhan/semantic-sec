<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support\Benchmark;

/** Rewrites our analyze, map and dry-run JSON from a disguised run back to original symbols, files and routes. */
final class Undisguise
{
    private const LISTS = ['findings', 'filtered', 'baselined', 'suppressed'];

    /**
     * @param array<mixed> $analyze
     *
     * @return array<mixed>
     */
    public static function analyze(DisguiseMap $map, string $app, array $analyze): array
    {
        foreach (self::LISTS as $list) {
            if (! is_array($analyze[$list] ?? null)) {
                continue;
            }
            foreach ($analyze[$list] as $i => $finding) {
                if (! is_array($finding)) {
                    continue;
                }
                $finding = self::location($map, $app, $finding);
                if (is_string($finding['route'] ?? null)) {
                    $finding['route'] = self::route($map, $app, $finding['route']);
                }
                foreach (is_array($finding['path'] ?? null) ? $finding['path'] : [] as $j => $step) {
                    $finding['path'][$j] = is_array($step) ? self::location($map, $app, $step) : $step;
                }
                $analyze[$list][$i] = $finding;
            }
        }

        return $analyze;
    }

    /**
     * @param array<mixed> $json `map --format=json`
     *
     * @return array<mixed>
     */
    public static function map(DisguiseMap $map, string $app, array $json): array
    {
        foreach (is_array($json['routes'] ?? null) ? $json['routes'] : [] as $i => $route) {
            if (! is_array($route) || ! is_string($route['uri'] ?? null)) {
                continue;
            }
            $methods = is_array($route['methods'] ?? null) ? array_values(array_filter($route['methods'], is_string(...))) : [];
            $json['routes'][$i]['uri'] = self::uri($map, $app, $methods, $route['uri']);
            if (is_array($route['action'] ?? null) && is_string($route['action']['class'] ?? null)) {
                $json['routes'][$i]['action']['class'] = $map->originalClass($app, $route['action']['class']);
            }
        }

        return $json;
    }

    /**
     * @param array<mixed> $dryRun `analyze --dry-run --format json`
     *
     * @return array<mixed>
     */
    public static function dryRun(DisguiseMap $map, string $app, array $dryRun): array
    {
        foreach (is_array($dryRun['candidates'] ?? null) ? $dryRun['candidates'] : [] as $i => $row) {
            if (is_array($row) && is_string($row['route'] ?? null)) {
                $dryRun['candidates'][$i]['route'] = self::route($map, $app, $row['route']);
            }
        }

        return $dryRun;
    }

    // "GET|HEAD /alpha/x" becomes "GET|HEAD /vuln/x"; the URI is looked up by the first verb the map knows.
    public static function route(DisguiseMap $map, string $app, string $key): string
    {
        [$methods, $uri] = explode(' ', $key, 2) + [1 => ''];

        return $methods.' '.self::uri($map, $app, explode('|', $methods), $uri);
    }

    /** @param list<string> $methods */
    private static function uri(DisguiseMap $map, string $app, array $methods, string $uri): string
    {
        foreach ($methods as $method) {
            $original = $map->originalRoute($app, $method.' '.$uri);
            if ($original !== $method.' '.$uri) {
                return explode(' ', $original, 2)[1] ?? $uri;
            }
        }

        return $uri;
    }

    /**
     * @param array<mixed> $item
     *
     * @return array<mixed>
     */
    private static function location(DisguiseMap $map, string $app, array $item): array
    {
        if (is_string($item['file'] ?? null)) {
            $item['file'] = $map->originalFile($app, $item['file']);
        }
        if (is_string($item['symbol'] ?? null)) {
            $item['symbol'] = $map->originalSymbol($app, $item['symbol']);
        }

        return $item;
    }
}
