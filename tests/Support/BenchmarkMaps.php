<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support;

use TusharKhan\SemanticSec\Candidates\CandidateSelector;
use TusharKhan\SemanticSec\Config\ConfigLoader;
use TusharKhan\SemanticSec\Framework\FrameworkDetector;
use TusharKhan\SemanticSec\Framework\Laravel\AuthorizationMap;
use TusharKhan\SemanticSec\Framework\Laravel\LaravelContext;
use TusharKhan\SemanticSec\Parsing\AstGenerator;
use TusharKhan\SemanticSec\Parsing\FileFinder;
use TusharKhan\SemanticSec\Parsing\ProjectParser;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTableBuilder;
use TusharKhan\SemanticSec\Payload\PayloadBuilder;

final class BenchmarkMaps
{
    /** @var array<string, array{AuthorizationMap, CandidateSelector, PayloadBuilder, SymbolTable}> */
    private static array $cache = [];

    public static function build(string $app): AuthorizationMap
    {
        return self::project($app)[0];
    }

    public static function selector(string $app): CandidateSelector
    {
        return self::project($app)[1];
    }

    public static function payloadBuilder(string $app): PayloadBuilder
    {
        return self::project($app)[2];
    }

    public static function symbols(string $app): SymbolTable
    {
        return self::project($app)[3];
    }

    /** @return array{AuthorizationMap, CandidateSelector, PayloadBuilder, SymbolTable} */
    private static function project(string $app): array
    {
        if (isset(self::$cache[$app])) {
            return self::$cache[$app];
        }
        $root = BenchmarkCorpus::root().'/'.$app;
        $config = (new ConfigLoader())->load($root);
        $framework = (new FrameworkDetector())->detect($root);
        $parsed = (new ProjectParser(new FileFinder(), new AstGenerator()))->parse($root);
        $symbols = (new SymbolTableBuilder())->build($parsed);
        $context = new LaravelContext();

        return self::$cache[$app] = [
            $context->buildAuthorizationMap($parsed, $symbols, $config, $framework),
            $context->candidateSelector($parsed, $symbols, $config, $framework),
            $context->payloadBuilder($parsed, $symbols, $config, $framework),
            $symbols,
        ];
    }
}
