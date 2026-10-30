<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support;

use TusharKhan\SemanticSec\Config\ConfigLoader;
use TusharKhan\SemanticSec\Framework\FrameworkDetector;
use TusharKhan\SemanticSec\Framework\Laravel\AuthorizationMap;
use TusharKhan\SemanticSec\Framework\Laravel\LaravelContext;
use TusharKhan\SemanticSec\Parsing\AstGenerator;
use TusharKhan\SemanticSec\Parsing\FileFinder;
use TusharKhan\SemanticSec\Parsing\ProjectParser;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTableBuilder;

final class BenchmarkMaps
{
    /** @var array<string, AuthorizationMap> */
    private static array $cache = [];

    public static function build(string $app): AuthorizationMap
    {
        if (isset(self::$cache[$app])) {
            return self::$cache[$app];
        }
        $root = BenchmarkCorpus::root().'/'.$app;
        $config = (new ConfigLoader())->load($root);
        $framework = (new FrameworkDetector())->detect($root);
        $parsed = (new ProjectParser(new FileFinder(), new AstGenerator()))->parse($root);
        $symbols = (new SymbolTableBuilder())->build($parsed);

        return self::$cache[$app] = (new LaravelContext())->buildAuthorizationMap($parsed, $symbols, $config, $framework);
    }
}
