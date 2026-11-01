<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support\Benchmark;

/**
 * Scores `analyze --format json` and `map --format=json` output against expected.yaml (M8 plan, Decision 4).
 *
 * @phpstan-import-type Finding from CaseVerdict
 * @phpstan-import-type MapCheck from CaseVerdict
 */
final class Scorer
{
    private const FAILING = ['medium', 'high'];

    // Lists a finding can sit in; baselined never occurs because the benchmark runs with --no-baseline.
    private const REPORTED = ['findings', 'filtered'];

    /**
     * @param list<BenchmarkCase> $cases
     * @param array<string, array<mixed>> $analyzeJsonByApp decoded analyze JSON per app
     * @param array<string, array<mixed>> $mapJsonByApp decoded map JSON per app
     * @param list<PublicRoute> $publicRoutes
     * @param array<string, array<mixed>> $dryRunJsonByApp decoded `analyze --dry-run --format json` per app; empty skips the selection stage
     */
    public static function score(array $cases, array $analyzeJsonByApp, array $mapJsonByApp, array $publicRoutes = [], array $dryRunJsonByApp = []): Score
    {
        $verdicts = [];
        foreach ($cases as $case) {
            $analyze = $analyzeJsonByApp[$case->app] ?? throw new \InvalidArgumentException("no analyze output for {$case->app}");
            $reported = self::findings($analyze, self::REPORTED);
            $vulnerablePool = $case->vulnerable->suppressed ? [...self::findings($analyze, ['suppressed']), ...$reported] : $reported;
            $targets = [[$case->vulnerable->file, $case->vulnerable->symbol]];
            foreach ($case->vulnerable->accept as $symbol) {
                $targets[] = [ExpectedCases::fileOf($symbol), $symbol];
            }
            $found = self::first($vulnerablePool, static fn (array $f): bool => $f['category'] === $case->category && in_array([$f['file'], $f['symbol']], $targets, true));
            $flagged = self::first($reported, static fn (array $f): bool => $f['symbol'] === $case->safe->symbol);
            $map = $mapJsonByApp[$case->app] ?? [];
            $dryRun = $dryRunJsonByApp[$case->app] ?? null;
            $vulnerableCategories = $dryRun === null ? null : self::selectedFor($dryRun, $case->vulnerable->route);
            $safeCategories = $dryRun === null ? null : self::selectedFor($dryRun, $case->safe->route);

            $verdicts[] = new CaseVerdict(
                $case,
                $found[0] !== null,
                $found[0],
                $found[1] !== null,
                $flagged[0] !== null,
                $flagged[0],
                $flagged[1] !== null,
                self::mapCheck($map, $case->vulnerable),
                self::mapCheck($map, $case->safe),
                $vulnerableCategories === null ? null : in_array($case->category, $vulnerableCategories, true),
                $vulnerableCategories,
                $safeCategories === null ? null : $safeCategories !== [],
                $safeCategories,
            );
        }

        $publics = [];
        foreach ($publicRoutes as $route) {
            $analyze = $analyzeJsonByApp[$route->app] ?? throw new \InvalidArgumentException("no analyze output for {$route->app}");
            [$by, $byFailing] = self::first(self::findings($analyze, self::REPORTED), static fn (array $f): bool => $f['symbol'] === $route->symbol);
            $publics[] = new PublicVerdict($route, $by, $byFailing);
        }

        return new Score($verdicts, $publics);
    }

    /**
     * The first match, and the first match at medium or high confidence.
     *
     * @param list<Finding> $pool
     * @param \Closure(Finding): bool $match
     *
     * @return array{0: Finding|null, 1: Finding|null}
     */
    private static function first(array $pool, \Closure $match): array
    {
        $any = $failing = null;
        foreach ($pool as $finding) {
            if (! $match($finding)) {
                continue;
            }
            $any ??= $finding;
            if ($failing === null && in_array($finding['confidence'], self::FAILING, true)) {
                $failing = $finding;
            }
        }

        return [$any, $failing];
    }

    /**
     * @param array<mixed> $analyze
     * @param list<string> $lists
     *
     * @return list<Finding>
     */
    private static function findings(array $analyze, array $lists): array
    {
        $out = [];
        foreach ($lists as $list) {
            foreach (is_array($analyze[$list] ?? null) ? $analyze[$list] : [] as $f) {
                if (! is_array($f)) {
                    continue;
                }
                $out[] = [
                    'list' => $list,
                    'category' => self::str($f, 'category'),
                    'confidence' => self::str($f, 'confidence'),
                    'file' => (string) preg_replace('#^\./#', '', self::str($f, 'file')),
                    'line' => is_int($f['line'] ?? null) ? $f['line'] : 0,
                    'symbol' => ExpectedCases::symbol(self::str($f, 'symbol')),
                    'title' => self::str($f, 'title'),
                ];
            }
        }

        return $out;
    }

    /**
     * Expected and actual check kinds as sets; a check of strength none does not count, as in BenchmarkMapTest.
     *
     * @param array<mixed> $map
     *
     * @return MapCheck
     */
    private static function mapCheck(array $map, Variant $variant): array
    {
        $expected = array_values(array_unique($variant->map));
        sort($expected);
        $route = self::route($map, $variant->route);
        if ($route === null) {
            return ['expected' => $expected, 'actual' => null, 'ok' => false];
        }
        $actual = [];
        foreach (is_array($route['checks'] ?? null) ? $route['checks'] : [] as $check) {
            if (is_array($check) && ($check['strength'] ?? 'none') !== 'none' && is_string($check['kind'] ?? null)) {
                $actual[$check['kind']] = true;
            }
        }
        $actual = array_keys($actual);
        sort($actual);

        return ['expected' => $expected, 'actual' => $actual, 'ok' => $expected === $actual];
    }

    /**
     * @param array<mixed> $map
     *
     * @return array<mixed>|null
     */
    private static function route(array $map, string $key): ?array
    {
        [$method, $uri] = explode(' ', $key, 2) + [1 => ''];
        foreach (is_array($map['routes'] ?? null) ? $map['routes'] : [] as $route) {
            if (is_array($route) && ($route['uri'] ?? null) === $uri && in_array($method, is_array($route['methods'] ?? null) ? $route['methods'] : [], true)) {
                return $route;
            }
        }

        return null;
    }

    /**
     * Categories the dry run selected this route for; [] when it was not a candidate.
     *
     * @param array<mixed> $dryRun
     *
     * @return list<string>
     */
    private static function selectedFor(array $dryRun, string $key): array
    {
        [$method, $uri] = explode(' ', $key, 2) + [1 => ''];
        foreach (is_array($dryRun['candidates'] ?? null) ? $dryRun['candidates'] : [] as $row) {
            if (! is_array($row) || ! is_string($row['route'] ?? null)) {
                continue;
            }
            [$methods, $rowUri] = explode(' ', $row['route'], 2) + [1 => ''];
            if ($rowUri === $uri && in_array($method, explode('|', $methods), true)) {
                return array_values(array_filter(is_array($row['categories'] ?? null) ? $row['categories'] : [], is_string(...)));
            }
        }

        return [];
    }

    /** @param array<mixed> $f */
    private static function str(array $f, string $key): string
    {
        return is_string($f[$key] ?? null) ? $f[$key] : '';
    }
}
