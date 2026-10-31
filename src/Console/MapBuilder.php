<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Console;

use TusharKhan\SemanticSec\Config\Config;
use TusharKhan\SemanticSec\Config\ConfigLoader;
use TusharKhan\SemanticSec\Framework\DetectedFramework;
use TusharKhan\SemanticSec\Framework\FrameworkDetector;
use TusharKhan\SemanticSec\Framework\Laravel\AuthorizationMap;
use TusharKhan\SemanticSec\Framework\Laravel\LaravelContext;
use TusharKhan\SemanticSec\Parsing\AstGenerator;
use TusharKhan\SemanticSec\Parsing\FileFinder;
use TusharKhan\SemanticSec\Parsing\ProjectParser;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTableBuilder;

final class MapBuilder
{
    private int $parses = 0;

    // How many times this builder parsed a project; lets tests prove analyze parses once.
    public function parses(): int
    {
        return $this->parses;
    }

    /** @return array{0: AuthorizationMap, 1: DetectedFramework, 2: list<string>} */
    public function build(string $root, ?string $configPath, ?string $framework): array
    {
        $project = $this->project($root, $configPath, $framework);

        return [$project->map, $project->framework, $project->warnings];
    }

    // $config, when given, is used as loaded instead of reading $configPath.
    public function project(string $root, ?string $configPath, ?string $framework, ?Config $config = null): MappedProject
    {
        $config ??= (new ConfigLoader())->load($root, $configPath);
        $detected = (new FrameworkDetector())->detect($root, $framework);
        $this->parses++;
        $parsed = (new ProjectParser(new FileFinder(), new AstGenerator()))->parse($root, $config->exclude);
        $symbols = (new SymbolTableBuilder())->build($parsed);
        $map = (new LaravelContext())->buildAuthorizationMap($parsed, $symbols, $config, $detected);

        $warnings = [];
        foreach ($parsed->failures as $failure) {
            $warnings[] = $failure->sourceLine === null
                ? sprintf('%s: %s', $failure->path, $failure->getMessage())
                : sprintf('%s:%d: %s', $failure->path, $failure->sourceLine, $failure->getMessage());
        }
        array_push($warnings, ...$symbols->duplicates(), ...$symbols->failures(), ...$map->warnings);

        return new MappedProject($config, $detected, $parsed, $symbols, $map, $warnings);
    }
}
