<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support\Benchmark;

/** Which cases were in the disguised copy the competitor reviewed; the rest are "not run", never misses. */
final class CompetitorScope
{
    // Only Vuln/Safe files are renamed; any other file keeps its path in the copy.
    private const DISGUISED = '#/(Vuln|Safe)/#';

    public function __construct(private readonly DisguiseMap $map, private readonly ?string $source)
    {
    }

    public function ran(BenchmarkCase $case): bool
    {
        return $this->contains($case->app, $case->vulnerable->symbol) && $this->contains($case->app, $case->safe->symbol);
    }

    public function ranRoute(PublicRoute $route): bool
    {
        return $this->contains($route->app, $route->symbol);
    }

    // With the source: the disguised file exists there. Without: the map listed the file, or it was never renamed.
    private function contains(string $app, string $symbol): bool
    {
        if (! in_array($app, $this->map->apps(), true)) {
            return false;
        }
        if ($this->source !== null) {
            return is_file($this->source.'/'.$app.'/'.ExpectedCases::fileOf($this->map->disguisedSymbol($app, $symbol)));
        }
        $file = ExpectedCases::fileOf($symbol);

        return preg_match(self::DISGUISED, $file) !== 1 || $this->map->hasOriginalFile($app, $file);
    }
}
