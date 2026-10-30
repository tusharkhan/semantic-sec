<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Framework\Laravel;

use TusharKhan\SemanticSec\Config\Config;
use TusharKhan\SemanticSec\Framework\DetectedFramework;
use TusharKhan\SemanticSec\Framework\FrameworkContext;
use TusharKhan\SemanticSec\Parsing\ParseResult;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;

final class LaravelContext implements FrameworkContext
{
    public function name(): string
    {
        return 'laravel';
    }

    public function buildAuthorizationMap(ParseResult $parsed, SymbolTable $symbols, Config $config, DetectedFramework $framework): AuthorizationMap
    {
        $eval = new ConstantEvaluator();
        $warnings = [];

        [$registry, $w] = MiddlewareRegistry::fromProject($parsed, $symbols, $framework, $eval, $config->authMiddleware);
        array_push($warnings, ...$w);

        [$files, $w] = (new RouteFileLocator())->locate($parsed, $symbols, $framework, $config, $eval);
        array_push($warnings, ...$w);

        $collector = new RouteCollector($parsed, $eval);
        $routes = [];
        foreach ($files as $file) {
            [$found, $w] = $collector->collect($file);
            array_push($routes, ...$found);
            array_push($warnings, ...$w);
        }

        // Safety net: a routes/ file that defines routes but that nothing loads.
        $visited = array_flip($collector->visited());
        foreach ($parsed->files as $file) {
            $path = $file->file->path;
            if (str_starts_with($path, 'routes/') && ! isset($visited[$path]) && RouteCollector::definesRoutes($file->ast)) {
                $warnings[] = sprintf('%s defines routes but is not loaded by any analysed source', $path);
            }
        }

        $controllerMiddleware = new ControllerMiddlewareReader($symbols, $eval);
        [$policies, $w] = PolicyRegistry::fromProject($symbols, $eval);
        array_push($warnings, ...$w);

        $extractor = new AuthCheckExtractor($symbols, $registry, $policies, $controllerMiddleware, $config->authHelpers);
        $out = [];
        foreach ($routes as $route) {
            [$entry, $w] = $extractor->extract($route);
            $out[] = $entry;
            array_push($warnings, ...$w);
        }

        return new AuthorizationMap($out, array_values(array_unique($warnings)));
    }
}
