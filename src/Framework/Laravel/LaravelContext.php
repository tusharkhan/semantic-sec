<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Framework\Laravel;

use TusharKhan\SemanticSec\Candidates\CandidateSelector;
use TusharKhan\SemanticSec\Config\Config;
use TusharKhan\SemanticSec\Framework\DetectedFramework;
use TusharKhan\SemanticSec\Framework\FrameworkContext;
use TusharKhan\SemanticSec\Parsing\CallGraph\CallGraphBuilder;
use TusharKhan\SemanticSec\Parsing\CallGraph\TypeResolver;
use TusharKhan\SemanticSec\Parsing\ParseResult;
use TusharKhan\SemanticSec\Parsing\Symbols\AuthUserModel;
use TusharKhan\SemanticSec\Parsing\Symbols\RelationResolver;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;
use TusharKhan\SemanticSec\Payload\PayloadBuilder;

final class LaravelContext implements FrameworkContext
{
    private const FACADES = [
        'Auth', 'Gate', 'DB', 'Cache', 'Log', 'Storage', 'Route', 'Request', 'Response',
        'Session', 'Mail', 'Queue', 'Event', 'Config', 'Validator', 'Hash', 'URL', 'Redirect',
    ];

    private const PROMPT_CONTEXT = <<<'TXT'
        Laravel notes:
        - Route model binding loads a type-hinted model by its route key only; it does not check that the current user may access it, and only scopeBindings() limits a child model to its parent.
        - Policies run only when called: $this->authorize(), Gate::authorize(), the `can:` middleware or authorizeResource(); Gate::allows() and ->can() just return a boolean.
        - A FormRequest's authorize() runs before the controller action; returning true allows every caller, and rules() only validates input.
        - The `auth` middleware only proves someone is logged in; route-group middleware applies to every route it wraps, controller middleware too unless limited with only()/except().
        - Model::find()/findOrFail() read any row; ownership needs a where on the owner column or a query through the user's relation.
        - Passing $request->all() to create(), update() or fill() writes every fillable attribute the client sends.
        TXT;

    public function facadeMap(): array
    {
        $map = [];
        foreach (self::FACADES as $facade) {
            $id = 'facade:'.$facade;
            $map['Illuminate\\Support\\Facades\\'.$facade] = $id;
            $map[$facade] = $id;
            $map['\\'.$facade] = $id;
        }

        return $map;
    }

    public function promptContext(): string
    {
        return self::PROMPT_CONTEXT;
    }

    public function name(): string
    {
        return 'laravel';
    }

    public function buildAuthorizationMap(ParseResult $parsed, SymbolTable $symbols, Config $config, DetectedFramework $framework): AuthorizationMap
    {
        $eval = new ConstantEvaluator();
        $warnings = [];

        [$registry, $w] = MiddlewareRegistry::fromProject($parsed, $symbols, $framework, $eval, $config->authMiddleware, $config->authorizationMiddleware);
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

        [$extractor, $w] = $this->extractor($parsed, $symbols, $config, $registry, $eval);
        array_push($warnings, ...$w);
        $out = [];
        foreach ($routes as $route) {
            [$entry, $w] = $extractor->extract($route);
            $out[] = $entry;
            array_push($warnings, ...$w);
        }

        return new AuthorizationMap($out, array_values(array_unique($warnings)));
    }

    /** The SPEC §7 selector for this project; its warnings were already reported by buildAuthorizationMap(). */
    public function candidateSelector(ParseResult $parsed, SymbolTable $symbols, Config $config, DetectedFramework $framework): CandidateSelector
    {
        $eval = new ConstantEvaluator();
        [$registry] = MiddlewareRegistry::fromProject($parsed, $symbols, $framework, $eval, $config->authMiddleware, $config->authorizationMiddleware);
        [$extractor] = $this->extractor($parsed, $symbols, $config, $registry, $eval);
        $relations = new RelationResolver($symbols);
        $types = new TypeResolver($symbols, $relations, AuthUserModel::resolve($parsed, $symbols, $eval));
        $graphs = new CallGraphBuilder($symbols, $types, $this->facadeMap(), $config->maxDepth);

        return new CandidateSelector($symbols, $graphs, $extractor, $types, $relations, $config);
    }

    /** The SPEC §9 payload builder for this project; its warnings were already reported by buildAuthorizationMap(). */
    public function payloadBuilder(ParseResult $parsed, SymbolTable $symbols, Config $config, DetectedFramework $framework): PayloadBuilder
    {
        $eval = new ConstantEvaluator();
        [$registry] = MiddlewareRegistry::fromProject($parsed, $symbols, $framework, $eval, $config->authMiddleware, $config->authorizationMiddleware);
        [$extractor] = $this->extractor($parsed, $symbols, $config, $registry, $eval);
        [$policies] = PolicyRegistry::fromProject($symbols, $eval);

        return new PayloadBuilder($parsed, $symbols, $extractor, $policies, $config);
    }

    /** @return array{AuthCheckExtractor, list<string>} */
    private function extractor(ParseResult $parsed, SymbolTable $symbols, Config $config, MiddlewareRegistry $registry, ConstantEvaluator $eval): array
    {
        [$policies, $warnings] = PolicyRegistry::fromProject($symbols, $eval);
        $authUser = AuthUserModel::resolve($parsed, $symbols, $eval);

        return [new AuthCheckExtractor($symbols, $registry, $policies, new ControllerMiddlewareReader($symbols, $eval), $config->authHelpers, new RelationResolver($symbols), $authUser), $warnings];
    }
}
