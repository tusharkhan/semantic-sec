<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Candidates;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use PhpParser\NodeFinder;
use PhpParser\PrettyPrinter\Standard;
use TusharKhan\SemanticSec\Analysis\Category;
use TusharKhan\SemanticSec\Config\Config;
use TusharKhan\SemanticSec\Framework\Laravel\Ancestry;
use TusharKhan\SemanticSec\Framework\Laravel\AuthCheck;
use TusharKhan\SemanticSec\Framework\Laravel\AuthCheckExtractor;
use TusharKhan\SemanticSec\Framework\Laravel\AuthCheckKind;
use TusharKhan\SemanticSec\Framework\Laravel\AuthExpressions;
use TusharKhan\SemanticSec\Framework\Laravel\AuthorizationMap;
use TusharKhan\SemanticSec\Framework\Laravel\AuthStrength;
use TusharKhan\SemanticSec\Framework\Laravel\RouteEntry;
use TusharKhan\SemanticSec\Parsing\CallGraph\CallGraphBuilder;
use TusharKhan\SemanticSec\Parsing\CallGraph\ExecutionPath;
use TusharKhan\SemanticSec\Parsing\CallGraph\PathNode;
use TusharKhan\SemanticSec\Parsing\CallGraph\TypeResolver;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;

/** Decides which routes go to the LLM and for which categories (SPEC §7); when unsure, a route is a candidate. */
final class CandidateSelector
{
    public const NO_TRIGGER = 'no identifier / no state change';

    private const STATE_VERBS = ['POST', 'PUT', 'PATCH', 'DELETE'];

    private const STATE_CALLS = ['save', 'update', 'delete', 'destroy', 'create', 'forcedelete', 'restore', 'insert', 'upsert'];

    private const MASS_CALLS = ['create', 'update', 'fill', 'forcefill', 'upsert', 'firstorcreate', 'updateorcreate'];

    private const STATUS_WRITES = ['update', 'fill', 'forcefill', 'updateorcreate', 'updatequietly', 'forceupdate'];

    private const WORKFLOW_CALLS = ['cancel', 'refund', 'approve', 'reject', 'ship', 'complete', 'publish'];

    private const GUARDS = ['abort_if', 'abort_unless', 'throw_if', 'throw_unless'];

    private const BLOCKING = ['abort', 'abort_if', 'abort_unless', 'throw_if', 'throw_unless'];

    private const INPUT_READS = ['input', 'get', 'query', 'route', 'integer', 'post'];

    private const MASS_READS = ['all', 'input', 'post', 'collect'];

    private const WRAPPERS = ['intval', 'strval', 'trim', 'urldecode'];

    // Calls that leave the user's relation scope.
    private const SCOPE_RESETS = ['newquery', 'query', 'newmodelquery', 'replicate', 'getmodel', 'getrelated', 'newmodelinstance', 'make'];

    // Laravel helpers that never look anything up.
    private const HARMLESS_FUNCTIONS = ['response', 'abort', 'abort_if', 'abort_unless', 'throw_if', 'throw_unless', 'logger', 'info', 'report', 'view', 'redirect', 'back', 'route', 'url', 'trans', '__', 'session', 'cache', 'now'];

    private const REQUESTS = ['Illuminate\\Http\\Request', 'Illuminate\\Foundation\\Http\\FormRequest'];

    private const REQUEST_FACADES = ['Illuminate\\Support\\Facades\\Request', 'Request'];

    private const MODEL_ROOTS = ['Illuminate\\Database\\Eloquent\\Model', 'Illuminate\\Foundation\\Auth\\User', 'Illuminate\\Database\\Eloquent\\Relations\\Pivot', 'Illuminate\\Database\\Eloquent\\Relations\\MorphPivot'];

    private const MAX_SOURCE = 120;

    private readonly Standard $printer;

    /** @var list<Exclusion> */
    private array $exclusions = [];

    /** @var array<string, PathNode> per route: node id => node */
    private array $nodes = [];

    /** @var array<string, FunctionBody> per route: node id => body */
    private array $bodies = [];

    /** @var array<int, PathNode> per route: spl id of a call => the callee node it reaches */
    private array $callees = [];

    /** @var array<string, array<string, array{0: string, 1: ?string}>> per route: node id => variable => [route parameter, bound model] */
    private array $routeVars = [];

    /** @var array<string, array<string, true>> per route: node id => parameters that receive mass input */
    private array $massVars = [];

    public function __construct(
        private readonly SymbolTable $symbols,
        private readonly CallGraphBuilder $graphs,
        private readonly AuthCheckExtractor $extractor,
        private readonly TypeResolver $types,
        private readonly Config $config,
    ) {
        $this->printer = new Standard();
    }

    /** @return array{0: list<Candidate>, 1: list<string>} */
    public function select(AuthorizationMap $map, bool $deep): array
    {
        $this->exclusions = [];
        $candidates = [];
        $warnings = [];
        foreach ($map->routes as $route) {
            try {
                $candidate = $this->route($route, $deep);
            } catch (\Throwable $e) {
                // Unanalysable routes are reviewed, never dropped.
                $warnings[] = sprintf('%s:%d: candidate selection failed: %s', $route->file, $route->line, $e->getMessage());
                $entry = new PathNode(self::key($route), null, null, $route->file, $route->line, $route->line, 0, null, null);
                $reason = 'selection failed: '.$e->getMessage();
                $candidate = new Candidate($route, new ExecutionPath([$entry], []), [Category::Idor, Category::MissingAuthorization], ['idor' => $reason, 'missing_authorization' => $reason]);
            } finally {
                $this->nodes = $this->bodies = $this->callees = $this->routeVars = $this->massVars = [];
            }
            if ($candidate !== null) {
                $candidates[] = $candidate;
            }
        }

        return [$candidates, $warnings];
    }

    /** @return list<Exclusion> every decision not to select, from the last select() */
    public function exclusions(): array
    {
        return $this->exclusions;
    }

    private function route(RouteEntry $route, bool $deep): ?Candidate
    {
        $key = self::key($route);
        $paths = $this->paths();
        $file = $this->actionFile($route);
        if ($paths !== [] && ! self::under($file, $paths)) {
            $this->exclude($key, null, 'action outside the configured paths', sprintf('%s is not under paths: %s', $file, implode(', ', $paths)));

            return null;
        }
        $path = $this->graphs->build($route);
        $this->index($route, $path);
        $checks = $this->pathChecks($route, $path);

        $reasons = [];
        $identifiers = $this->identifiers($route, $path);
        if ($identifiers !== []) {
            $this->idor($key, $identifiers, $checks, $deep, $reasons);
        }
        $writes = $this->writes($path, self::STATE_CALLS);
        $verbs = array_values(array_intersect($route->methods, self::STATE_VERBS));
        if ($verbs !== [] || $writes !== []) {
            $this->missingAuthorization($key, $path, $verbs, $writes, $checks, $deep, $reasons);
        }
        $this->massAssignment($key, $path, $reasons);
        $this->deserialization($path, $reasons);
        $this->workflow($key, $path, $reasons);

        if ($reasons === []) {
            if ($identifiers === [] && $verbs === [] && $writes === []) {
                $this->exclude($key, null, self::NO_TRIGGER, '');
            }

            return null;
        }
        $categories = array_values(array_filter(Category::cases(), static fn (Category $c): bool => isset($reasons[$c->value])));
        $ordered = [];
        foreach ($categories as $category) {
            $ordered[$category->value] = $reasons[$category->value];
        }

        return new Candidate($route, $path, $categories, $ordered);
    }

    // ---- path facts --------------------------------------------------------------------------------------------

    private function index(RouteEntry $route, ExecutionPath $path): void
    {
        foreach ($path->nodes as $node) {
            $this->nodes[$node->id] = $node;
            $this->bodies[$node->id] = new FunctionBody($this->symbols, $node);
        }
        // The call expression behind each edge: the only call at the site's line with the callee's name.
        foreach ($path->nodes as $node) {
            $parent = $node->calledBy === null ? null : ($this->bodies[$node->calledBy] ?? null);
            if ($parent === null || $node->calledFrom === null || $node->method === null) {
                continue;
            }
            $found = [];
            foreach ($parent->calls as $call) {
                if ($call->getStartLine() === $node->calledFrom->line && self::callName($call) === strtolower($node->method->name)) {
                    $found[] = $call;
                }
            }
            if (count($found) === 1) {
                $this->callees[spl_object_id($found[0])] = $node;
            }
        }
        $entry = $path->entry();
        $this->routeVars[$entry->id] = $this->entryVariables($route, $this->bodies[$entry->id]);
        foreach ($path->nodes as $node) {
            foreach ($this->argumentPairs($node) as [$arg, $param, $parent]) {
                $body = $this->bodies[$parent->id];
                if ($arg instanceof Expr\Variable && is_string($arg->name) && isset($this->routeVars[$parent->id][$arg->name])) {
                    [$routeParam, $model] = $this->routeVars[$parent->id][$arg->name];
                    // A bound model counts only while the variable still holds it.
                    $this->routeVars[$node->id][$param] = [$routeParam, $model !== null && $body->auth->isUntouchedParam($arg->name, $arg->getStartFilePos()) ? $model : null];
                }
                if ($this->isMassInput($arg, $body, $this->massVars[$parent->id] ?? [])) {
                    $this->massVars[$node->id][$param] = true;
                }
            }
        }
    }

    /** @return array<string, array{0: string, 1: ?string}> action variable => [route parameter, bound model] */
    private function entryVariables(RouteEntry $route, FunctionBody $body): array
    {
        $out = [];
        foreach ($route->parameters as $p) {
            foreach (array_keys($body->params) as $name) {
                if ($name === $p->name || ($p->boundModel !== null && self::snake($name) === $p->name)) {
                    $out[$name] = [$p->name, $p->boundModel];
                }
            }
        }

        return $out;
    }

    /** @return list<array{0: Expr, 1: string, 2: PathNode}> argument in the caller, callee parameter, caller */
    private function argumentPairs(PathNode $node): array
    {
        if ($node->method === null || $node->calledBy === null || ! isset($this->nodes[$node->calledBy])) {
            return [];
        }
        $call = null;
        foreach ($this->bodies[$node->calledBy]->calls as $candidate) {
            if (($this->callees[spl_object_id($candidate)] ?? null) === $node) {
                $call = $candidate;
            }
        }
        if ($call === null) {
            return [];
        }
        $pairs = [];
        $params = $node->method->node->params;
        foreach (AuthExpressions::args($call) as $i => $arg) {
            $param = $params[$i] ?? null;
            if ($param === null || $param->variadic || ! $param->var instanceof Expr\Variable || ! is_string($param->var->name)) {
                break;
            }
            $pairs[] = [$arg, $param->var->name, $this->nodes[$node->calledBy]];
        }

        return $pairs;
    }

    // A callee's checks count only when every call site back to the entry is unconditional and nothing on the way is assumed.
    private function effective(PathNode $node): bool
    {
        for ($n = $node; $n->calledBy !== null; $n = $this->nodes[$n->calledBy]) {
            if ($n->assumed || $n->calledFrom === null || $n->calledFrom->conditional || ! isset($this->nodes[$n->calledBy])) {
                return false;
            }
        }

        return ! $n->assumed;
    }

    /** @return list<AuthCheck> Authorization-strength checks: the route's own, plus those of every effective callee */
    private function pathChecks(RouteEntry $route, ExecutionPath $path): array
    {
        $out = array_values(array_filter($route->checks, static fn (AuthCheck $c): bool => $c->strength === AuthStrength::Authorization));
        foreach ($path->nodes as $node) {
            if ($node === $path->entry() || $node->method === null || ! $this->effective($node)) {
                continue;
            }
            $bound = [];
            $toRoute = [];
            foreach ($this->routeVars[$node->id] ?? [] as $var => [$routeParam, $model]) {
                if ($model !== null) {
                    $bound[$var] = $model;
                    $toRoute[$var] = $routeParam;
                }
            }
            [$found] = $this->extractor->bodyChecks($node->method, $node->file, $bound);
            foreach ($found as $c) {
                if ($c->strength === AuthStrength::Authorization) {
                    $out[] = new AuthCheck($c->kind, $c->strength, $c->source, $c->file, $c->line, $c->covers === null ? null : ($toRoute[$c->covers] ?? null), $c->model, $c->routeWide);
                }
            }
        }

        return $out;
    }

    // ---- idor ----------------------------------------------------------------------------------------------------

    /** @return list<array{label: string, param: ?string, models: list<?string>}> models: what the identifier is looked up on (null: unknown) */
    private function identifiers(RouteEntry $route, ExecutionPath $path): array
    {
        $entry = $path->entry();
        $out = [];
        foreach ($route->parameters as $p) {
            $variable = null;
            foreach ($this->routeVars[$entry->id] ?? [] as $var => [$routeParam]) {
                if ($routeParam === $p->name) {
                    $variable = $var;
                }
            }
            $models = match (true) {
                $p->boundModel !== null => [$p->boundModel],
                $variable !== null => $this->flowModels($entry, $variable),
                default => [],
            };
            $out[] = ['label' => '{'.$p->name.'}', 'param' => $p->name, 'models' => $models];
        }
        foreach ($path->nodes as $node) {
            $body = $this->bodies[$node->id];
            foreach ($body->calls as $call) {
                $name = $this->idInputName($call, $body);
                if ($name === null) {
                    continue;
                }
                $models = $this->readModels($node, $call);
                if ($models !== []) {
                    $out[] = ['label' => sprintf("request input '%s'", $name), 'param' => null, 'models' => $models];
                }
            }
        }

        return $out;
    }

    /**
     * @param  list<array{label: string, param: ?string, models: list<?string>}>  $identifiers
     * @param  list<AuthCheck>  $checks
     * @param  array<string, string>  $reasons
     */
    private function idor(string $key, array $identifiers, array $checks, bool $deep, array &$reasons): void
    {
        $labels = array_map(static fn (array $i): string => $i['label'], $identifiers);
        if ($deep) {
            $reasons[Category::Idor->value] = '--deep: identifiers '.implode(', ', $labels);

            return;
        }
        $uncovered = [];
        $sources = [];
        foreach ($identifiers as $identifier) {
            $source = $this->coverage($identifier, $checks);
            if ($source === null) {
                $uncovered[] = $identifier['label'].self::lookupText($identifier['models']);
            } else {
                $sources[] = $identifier['label'].': '.$source;
            }
        }
        if ($uncovered !== []) {
            $reasons[Category::Idor->value] = 'identifier '.implode(', ', $uncovered).' not covered by an authorization check';

            return;
        }
        $this->exclude($key, Category::Idor, 'every identifier is covered by an authorization check', implode('; ', array_unique($sources)));
    }

    /**
     * (a) a check covering the parameter, (b) a query scope on every model it is looked up on, (c) a route-wide check.
     *
     * @param  array{label: string, param: ?string, models: list<?string>}  $identifier
     * @param  list<AuthCheck>  $checks
     */
    private function coverage(array $identifier, array $checks): ?string
    {
        foreach ($checks as $c) {
            if ($identifier['param'] !== null && $c->covers === $identifier['param']) {
                return $this->checkText($c);
            }
        }
        $models = $identifier['models'];
        if ($models !== [] && ! in_array(null, $models, true)) {
            $scopes = [];
            foreach (array_unique($models) as $model) {
                foreach ($checks as $c) {
                    if ($c->kind === AuthCheckKind::QueryScope && $c->model !== null && $c->model === $model) {
                        $scopes[$model] = $this->checkText($c);
                    }
                }
            }
            if (count($scopes) === count(array_unique($models))) {
                return implode('; ', $scopes);
            }
        }
        foreach ($checks as $c) {
            if ($c->routeWide && $c->covers === null) {
                return $this->checkText($c);
            }
        }

        return null;
    }

    /** @param list<?string> $models */
    private static function lookupText(array $models): string
    {
        $known = array_values(array_unique(array_filter($models, static fn (?string $m): bool => $m !== null)));
        if ($models === [] || $known === []) {
            return '';
        }

        return ' (looked up on '.implode(', ', array_map(self::short(...), $known)).')';
    }

    // The id-like name a request read uses: $request->input('post_id'), request('id'), Request::query('userId').
    private function idInputName(Expr $call, FunctionBody $body): ?string
    {
        $name = AuthExpressions::name($call);
        $args = AuthExpressions::args($call);
        $read = match (true) {
            $call instanceof Expr\FuncCall => $name === 'request',
            $call instanceof Expr\StaticCall => self::isRequestFacade($call->class) && in_array($name, self::INPUT_READS, true),
            AuthExpressions::isCall($call) => in_array($name, self::INPUT_READS, true) && $this->isRequestReceiver($call->var, $body),
            default => false,
        };
        $key = $args[0] ?? null;
        if (! $read || ! $key instanceof Node\Scalar\String_) {
            return null;
        }
        $value = $key->value;

        return $value === 'id' || str_ends_with($value, '_id') || preg_match('/[a-z0-9]Id$/', $value) === 1 ? $value : null;
    }

    /** @return list<?string> models a request read reaches as a lookup argument, directly or through a variable */
    private function readModels(PathNode $node, Expr $read): array
    {
        $body = $this->bodies[$node->id];
        $expr = $read;
        for ($i = 0; $i < 8; $i++) {
            $parent = $body->positions->parent($expr);
            if ($parent instanceof Expr\Cast || $parent instanceof Expr\BinaryOp\Coalesce) {
                $expr = $parent;

                continue;
            }
            if ($parent instanceof Node\Arg) {
                $call = $body->positions->parent($parent);
                if ($call instanceof Expr\FuncCall && in_array(AuthExpressions::name($call), self::WRAPPERS, true)) {
                    $expr = $call;

                    continue;
                }
                if ($call instanceof Expr\CallLike) {
                    $index = array_search($parent, $call->getRawArgs(), true);

                    return $this->consumerModels($node, $call, is_int($index) ? $index : -1, []);
                }
            }
            if ($parent instanceof Expr\Assign && $parent->expr === $expr && $parent->var instanceof Expr\Variable && is_string($parent->var->name)) {
                return $this->flowModels($node, $parent->var->name);
            }

            return [];
        }

        return [];
    }

    /**
     * Models a variable is looked up on, following it into callees; null for a use whose effect is unknown.
     *
     * @param  array<string, true>  $seen
     * @return list<?string>
     */
    private function flowModels(PathNode $node, string $var, array $seen = []): array
    {
        $key = $node->id."\0".$var;
        if (isset($seen[$key]) || count($seen) > 16) {
            return [];
        }
        $seen[$key] = true;
        $models = [];
        foreach ($this->bodies[$node->id]->calls as $call) {
            if ($call instanceof Expr\New_ && ! isset($this->callees[spl_object_id($call)])) {
                continue;
            }
            foreach ($call->isFirstClassCallable() ? [] : $call->getRawArgs() as $index => $arg) {
                if ($arg instanceof Node\Arg && self::isVariable(self::unwrap($arg->value), $var)) {
                    array_push($models, ...$this->consumerModels($node, $call, $index, $seen));
                }
            }
        }

        return $models;
    }

    /**
     * @param  array<string, true>  $seen
     * @return list<?string>
     */
    private function consumerModels(PathNode $node, Expr\CallLike $call, int $index, array $seen): array
    {
        $callee = $this->callees[spl_object_id($call)] ?? null;
        if ($callee !== null) {
            $param = $callee->method?->node->params[$index] ?? null;
            if ($param === null || $param->variadic || ! $param->var instanceof Expr\Variable || ! is_string($param->var->name)) {
                return [null];
            }

            return $this->flowModels($callee, $param->var->name, $seen);
        }
        $name = AuthExpressions::name($call) ?? '';
        if (($call instanceof Expr\StaticCall || AuthExpressions::isCall($call)) && self::isLookup($name)) {
            return [$this->lookupModel($node, $call)];
        }
        if ($call instanceof Expr\FuncCall && (in_array($name, self::HARMLESS_FUNCTIONS, true) || in_array($name, self::WRAPPERS, true)
            || (function_exists($name) && (new \ReflectionFunction($name))->isInternal()))) {
            return [];
        }

        // Anything else may look it up out of sight.
        return [null];
    }

    private static function isLookup(string $name): bool
    {
        return str_starts_with($name, 'find') || str_starts_with($name, 'where') || str_starts_with($name, 'first') || $name === 'sole';
    }

    // The finder's class: X in X::find|where..(), or the model a query or relation receiver reads.
    private function lookupModel(PathNode $node, Expr\CallLike $call): ?string
    {
        if ($call instanceof Expr\StaticCall) {
            return $this->types->staticModel($call, $node);
        }

        return AuthExpressions::isCall($call) ? $this->types->queryModel($call->var, $node) : null;
    }

    // ---- missing_authorization ----------------------------------------------------------------------------------

    /**
     * @param  list<string>  $verbs
     * @param  list<array{PathNode, Expr\CallLike}>  $writes
     * @param  list<AuthCheck>  $checks
     * @param  array<string, string>  $reasons
     */
    private function missingAuthorization(string $key, ExecutionPath $path, array $verbs, array $writes, array $checks, bool $deep, array &$reasons): void
    {
        $change = $verbs !== [] ? implode('/', $verbs).' route' : 'writes via '.$this->print($writes[0][1]);
        if ($deep) {
            $reasons[Category::MissingAuthorization->value] = '--deep: '.$change.' changes state';

            return;
        }
        if ($checks !== []) {
            $this->exclude($key, Category::MissingAuthorization, 'an authorization check is on the path', $this->checkText($checks[0]));

            return;
        }
        $all = $this->writes($path, [...self::STATE_CALLS, ...AuthExpressions::WRITES]);
        $scoped = $all !== [];
        $texts = [];
        foreach ($all as [$node, $call]) {
            $scoped = $scoped && AuthExpressions::isCall($call) && $this->authRooted($call->var, $this->bodies[$node->id]);
            $texts[] = sprintf('%s (%s:%d)', $this->print($call), $node->file, $call->getStartLine());
        }
        if ($scoped) {
            $this->exclude($key, Category::MissingAuthorization, 'every model write is reached through the authenticated user', implode('; ', array_unique($texts)));

            return;
        }
        $reasons[Category::MissingAuthorization->value] = $change.' with no authorization check';
    }

    /**
     * Model writes anywhere on the path: a named call on a model, a query or relation, or a receiver of unknown type.
     *
     * @param  list<string>  $names
     * @return list<array{PathNode, Expr\CallLike}>
     */
    private function writes(ExecutionPath $path, array $names): array
    {
        $out = [];
        foreach ($path->nodes as $node) {
            foreach ($this->bodies[$node->id]->calls as $call) {
                if (in_array(self::callName($call), $names, true) && ($call instanceof Expr\StaticCall || AuthExpressions::isCall($call)) && $this->isModelWrite($node, $call)) {
                    $out[] = [$node, $call];
                }
            }
        }

        return $out;
    }

    private function isModelWrite(PathNode $node, Expr\StaticCall|Expr\MethodCall|Expr\NullsafeMethodCall $call): bool
    {
        if ($call instanceof Expr\StaticCall) {
            return $this->types->staticModel($call, $node) !== null;
        }
        if ($this->types->queryModel($call->var, $node) !== null) {
            return true;
        }

        // A receiver of known non-model type is not a model write (a project class is followed instead).
        return $this->types->typeOf($call->var, $node) === null;
    }

    // The receiver chain starts at the authenticated user and keeps its relation scope.
    private function authRooted(Expr $expr, FunctionBody $body, int $depth = 0): bool
    {
        while (AuthExpressions::isCall($expr) || $expr instanceof Expr\PropertyFetch || $expr instanceof Expr\NullsafePropertyFetch) {
            if ($body->auth->isAuthUser($expr)) {
                return true;
            }
            if (! $expr->name instanceof Node\Identifier || (AuthExpressions::isCall($expr) && in_array($expr->name->toLowerString(), self::SCOPE_RESETS, true))) {
                return false;
            }
            $expr = $expr->var;
        }
        if ($body->auth->isAuthUser($expr)) {
            return true;
        }
        if (! $expr instanceof Expr\Variable || $depth > 3) {
            return false;
        }
        $values = $body->auth->assignedValues($expr);
        if ($values === null || $values === []) {
            return false;
        }
        foreach ($values as $value) {
            if (! $this->authRooted($value, $body, $depth + 1)) {
                return false;
            }
        }

        return true;
    }

    // ---- mass_assignment ----------------------------------------------------------------------------------------

    /** @param array<string, string> $reasons */
    private function massAssignment(string $key, ExecutionPath $path, array &$reasons): void
    {
        $hits = [];
        $safe = [];
        foreach ($path->nodes as $node) {
            $body = $this->bodies[$node->id];
            foreach ($body->calls as $call) {
                $name = self::callName($call);
                if (! in_array($name, self::MASS_CALLS, true) || ! ($call instanceof Expr\StaticCall || AuthExpressions::isCall($call))) {
                    continue;
                }
                $mass = false;
                foreach (AuthExpressions::args($call) as $arg) {
                    $mass = $mass || $this->isMassInput($arg, $body, $this->massVars[$node->id] ?? []);
                }
                if (! $mass) {
                    continue;
                }
                $where = sprintf('%s (%s:%d)', $this->print($call), $node->file, $call->getStartLine());
                [$known, $model] = $this->writeModel($node, $call);
                if (! $known) {
                    continue;
                }
                if ($model === null) {
                    $hits[] = $where.': model unknown';

                    continue;
                }
                [$open, $why] = $name === 'forcefill' ? [true, 'forceFill ignores $fillable'] : $this->massVerdict($model);
                if ($open) {
                    $hits[] = $where.': '.self::short($model).' '.$why;
                } else {
                    $safe[] = $why;
                }
            }
        }
        if ($hits !== []) {
            $reasons[Category::MassAssignment->value] = 'mass input written via '.implode('; ', $hits);
        } elseif ($safe !== []) {
            $this->exclude($key, Category::MassAssignment, 'mass input only reaches models that guard sensitive fields', implode('; ', array_unique($safe)));
        }
    }

    /** @return array{bool, ?string} whether this is a model write to judge (false: a followed or non-model call), and the model when known */
    private function writeModel(PathNode $node, Expr\StaticCall|Expr\MethodCall|Expr\NullsafeMethodCall $call): array
    {
        if (isset($this->callees[spl_object_id($call)])) {
            return [false, null];
        }
        if ($call instanceof Expr\StaticCall) {
            $model = $this->types->staticModel($call, $node);
            if ($model !== null) {
                return [true, $model];
            }
            if (! $call->class instanceof Node\Name) {
                return [true, null];
            }
            $class = ltrim($call->class->toString(), '\\');

            // A vendor class may be a model; a project non-model or a facade is not.
            return [$this->symbols->getClass($class) === null && ! str_starts_with($class, 'Illuminate\\Support\\Facades\\') && ! in_array(strtolower($class), ['self', 'static', 'parent'], true), null];
        }
        $model = $this->types->queryModel($call->var, $node);
        if ($model !== null) {
            return [true, $model];
        }
        $type = $this->types->typeOf($call->var, $node);

        return [$type === null || $this->symbols->getClass($type) !== null, null];
    }

    /** @return array{bool, string} whether sensitive fields are open, and why */
    private function massVerdict(string $model): array
    {
        $short = self::short($model);
        $fillable = $this->stringProperty($model, 'fillable');
        $guarded = $this->stringProperty($model, 'guarded');
        if ($fillable === null || $guarded === null) {
            return [true, 'has $fillable/$guarded that cannot be read'];
        }
        $sensitive = array_map('strtolower', $this->config->sensitiveFields);
        if ($fillable !== false && $fillable !== []) {
            $hit = array_values(array_intersect(array_map('strtolower', $fillable), $sensitive));

            return $hit !== [] ? [true, '$fillable includes '.implode(', ', $hit)] : [false, sprintf("%s::\$fillable = ['%s']", $model, implode("', '", $fillable))];
        }
        if ($guarded !== false) {
            if ($guarded === []) {
                return [true, '$guarded = []'];
            }
            if (in_array('*', $guarded, true)) {
                return [false, sprintf("%s::\$guarded = ['*']", $model)];
            }
            $open = array_values(array_diff($sensitive, array_map('strtolower', $guarded)));

            return $open !== [] ? [true, '$guarded leaves '.implode(', ', $open).' open'] : [false, sprintf("%s::\$guarded = ['%s']", $model, implode("', '", $guarded))];
        }
        $lineage = $this->symbols->lineage($model);
        $root = $lineage === [] ? null : $lineage[count($lineage) - 1]->parent;
        if ($root !== null && in_array(ltrim($root, '\\'), self::MODEL_ROOTS, true)) {
            return [false, sprintf('%s declares no $fillable or $guarded (Laravel guards every attribute)', $model)];
        }

        return [true, 'attributes unknown: '.$short.' extends a class outside the project'];
    }

    /** @return list<string>|false|null the string list a property defaults to; false when not declared, null when unreadable */
    private function stringProperty(string $model, string $name): array|false|null
    {
        $property = $this->symbols->findProperty($model, $name);
        if ($property === null) {
            return false;
        }
        if ($property->default === null) {
            return [];
        }
        if (! $property->default instanceof Expr\Array_) {
            return null;
        }
        $out = [];
        foreach ($property->default->items as $item) {
            if ($item->key !== null || $item->unpack || ! $item->value instanceof Node\Scalar\String_) {
                return null;
            }
            $out[] = $item->value->value;
        }

        return $out;
    }

    /** @param array<string, true> $massVars */
    private function isMassInput(Expr $expr, FunctionBody $body, array $massVars, int $depth = 0): bool
    {
        if ($depth > 4) {
            return false;
        }
        $name = AuthExpressions::name($expr);
        $noArgs = $expr instanceof Expr\CallLike && ! $expr->isFirstClassCallable() && $expr->getRawArgs() === [];
        // all()/input()/post()/collect() with keys read only those keys; except() reads everything else.
        $readsAll = $name === 'except' || ($noArgs && in_array($name, self::MASS_READS, true));
        if (AuthExpressions::isCall($expr)) {
            return $readsAll && $this->isRequestReceiver($expr->var, $body);
        }
        if ($expr instanceof Expr\StaticCall) {
            return $readsAll && self::isRequestFacade($expr->class);
        }
        if ($expr instanceof Expr\FuncCall && in_array($name, ['array_merge', 'array_replace'], true)) {
            foreach (AuthExpressions::args($expr) as $arg) {
                if ($this->isMassInput($arg, $body, $massVars, $depth + 1)) {
                    return true;
                }
            }

            return false;
        }
        if (! $expr instanceof Expr\Variable || ! is_string($expr->name)) {
            return false;
        }
        if (isset($massVars[$expr->name]) && $body->auth->isUntouchedParam($expr->name, $expr->getStartFilePos())) {
            return true;
        }
        $values = $body->auth->assignedValues($expr);
        if ($values === null || $values === []) {
            return false;
        }
        foreach ($values as $value) {
            if (! $this->isMassInput($value, $body, $massVars, $depth + 1)) {
                return false;
            }
        }

        return true;
    }

    // $request (by name or Request/FormRequest type) or request() with no arguments.
    private function isRequestReceiver(Expr $expr, FunctionBody $body): bool
    {
        if ($expr instanceof Expr\FuncCall) {
            return AuthExpressions::name($expr) === 'request' && $expr->getRawArgs() === [];
        }
        if (! $expr instanceof Expr\Variable || ! is_string($expr->name)) {
            return false;
        }

        return $expr->name === 'request' || Ancestry::descendsFrom($this->symbols, $body->params[$expr->name] ?? null, self::REQUESTS);
    }

    private static function isRequestFacade(Node $class): bool
    {
        return $class instanceof Node\Name && in_array(ltrim($class->toString(), '\\'), self::REQUEST_FACADES, true);
    }

    // ---- insecure_deserialization -------------------------------------------------------------------------------

    /** @param array<string, string> $reasons */
    private function deserialization(ExecutionPath $path, array &$reasons): void
    {
        $hits = [];
        foreach ($path->nodes as $node) {
            foreach ($this->bodies[$node->id]->calls as $call) {
                if (! $call instanceof Expr\FuncCall || AuthExpressions::name($call) !== 'unserialize') {
                    continue;
                }
                $args = $call->isFirstClassCallable() ? [] : $call->getArgs();
                if ($args !== [] && self::isConstant($args[0]->value)) {
                    continue;
                }
                $limited = isset($args[1]) && self::disallowsClasses($args[1]->value);
                $hits[] = sprintf('%s (%s:%d)%s', $this->print($call), $node->file, $call->getStartLine(), $limited ? '; allowed_classes => false limits object injection but is still reviewed' : '');
            }
        }
        if ($hits !== []) {
            $reasons[Category::InsecureDeserialization->value] = 'unserialize of a non-constant value: '.implode('; ', $hits);
        }
    }

    private static function isConstant(Expr $expr): bool
    {
        if ($expr instanceof Node\Scalar\String_ || $expr instanceof Node\Scalar\Int_ || $expr instanceof Node\Scalar\Float_
            || $expr instanceof Expr\ConstFetch || $expr instanceof Expr\ClassConstFetch) {
            return true;
        }
        if ($expr instanceof Expr\BinaryOp\Concat) {
            return self::isConstant($expr->left) && self::isConstant($expr->right);
        }

        return false;
    }

    private static function disallowsClasses(Expr $options): bool
    {
        if (! $options instanceof Expr\Array_) {
            return false;
        }
        foreach ($options->items as $item) {
            if ($item->key instanceof Node\Scalar\String_ && $item->key->value === 'allowed_classes' && $item->value instanceof Expr\ConstFetch) {
                return strtolower($item->value->name->toString()) === 'false';
            }
        }

        return false;
    }

    // ---- workflow_bypass ----------------------------------------------------------------------------------------

    /** @param array<string, string> $reasons */
    private function workflow(string $key, ExecutionPath $path, array &$reasons): void
    {
        $open = [];
        $guards = [];
        foreach ($path->nodes as $node) {
            $body = $this->bodies[$node->id];
            foreach ($this->workflowTriggers($body) as [$at, $field, $receiver, $text]) {
                $guard = $this->statusGuard($body, $at, $field, $receiver);
                $where = sprintf('%s (%s:%d)', $text, $node->file, $at->getStartLine());
                if ($guard === null) {
                    $open[] = $where;
                } else {
                    $text = $guard instanceof Stmt\If_ ? 'if ('.$this->print($guard->cond).')' : ($guard instanceof Expr ? $this->print($guard) : '');
                    $guards[] = sprintf('%s (%s:%d)', $text, $node->file, $guard->getStartLine());
                }
            }
        }
        if ($open !== []) {
            $reasons[Category::WorkflowBypass->value] = 'state transition with no status guard before it: '.implode('; ', $open);
        } elseif ($guards !== []) {
            $this->exclude($key, Category::WorkflowBypass, 'every status write follows a guard on the same field', implode('; ', array_unique($guards)));
        }
    }

    /** @return list<array{Node, ?string, ?string, string}> write or call, status field (null: unknown), receiver text, description */
    private function workflowTriggers(FunctionBody $body): array
    {
        $out = [];
        foreach ($body->calls as $call) {
            $name = self::callName($call);
            if (! AuthExpressions::isCall($call) && ! $call instanceof Expr\StaticCall) {
                continue;
            }
            if (in_array($name, self::STATUS_WRITES, true)) {
                foreach (AuthExpressions::args($call) as $arg) {
                    foreach ($arg instanceof Expr\Array_ ? $arg->items : [] as $item) {
                        if ($item->key instanceof Node\Scalar\String_ && self::isStatusField($item->key->value)) {
                            $out[] = [$call, $item->key->value, null, $this->print($call)];
                        }
                    }
                }
            }
            if (in_array($name, self::WORKFLOW_CALLS, true) || str_starts_with($name, 'transition')) {
                $out[] = [$call, null, AuthExpressions::isCall($call) ? $this->print($call->var) : null, $this->print($call)];
            }
        }
        foreach ((new NodeFinder())->findInstanceOf($body->stmts, Expr\Assign::class) as $assign) {
            $var = $assign->var;
            if (($var instanceof Expr\PropertyFetch || $var instanceof Expr\NullsafePropertyFetch) && $var->name instanceof Node\Identifier && self::isStatusField($var->name->toString())) {
                $out[] = [$assign, $var->name->toString(), null, $this->print($assign)];
            }
        }

        return $out;
    }

    // An unconditional abort_*/throw_* or blocking `if` before the write that compares the same field (or, for a named transition, a status field of the same receiver).
    private function statusGuard(FunctionBody $body, Node $at, ?string $field, ?string $receiver): ?Node
    {
        $finder = new NodeFinder();
        $candidates = $finder->find($body->stmts, static fn (Node $n): bool => ($n instanceof Expr\FuncCall && in_array(AuthExpressions::name($n), self::GUARDS, true)) || $n instanceof Stmt\If_);
        foreach ($candidates as $guard) {
            if ($guard->getEndFilePos() >= $at->getStartFilePos() || ! $body->positions->isUnconditional($guard)) {
                continue;
            }
            if ($guard instanceof Stmt\If_) {
                $condition = self::blocks($guard->stmts) ? $guard->cond : null;
            } else {
                $condition = AuthExpressions::args($guard)[0] ?? null;
            }
            if ($condition !== null && $this->comparesField($condition, $field, $receiver)) {
                return $guard;
            }
        }

        return null;
    }

    /** @param array<Stmt> $stmts */
    private static function blocks(array $stmts): bool
    {
        foreach ($stmts as $stmt) {
            if ($stmt instanceof Stmt\Return_ || ($stmt instanceof Stmt\Expression && ($stmt->expr instanceof Expr\Throw_ || $stmt->expr instanceof Expr\Exit_
                || ($stmt->expr instanceof Expr\FuncCall && in_array(AuthExpressions::name($stmt->expr), self::BLOCKING, true))))) {
                return true;
            }
        }

        return false;
    }

    private function comparesField(Expr $condition, ?string $field, ?string $receiver): bool
    {
        foreach ((new NodeFinder())->find([$condition], static fn (Node $n): bool => $n instanceof Expr\BinaryOp\Identical || $n instanceof Expr\BinaryOp\NotIdentical
            || $n instanceof Expr\BinaryOp\Equal || $n instanceof Expr\BinaryOp\NotEqual || AuthExpressions::isFunc($n, 'in_array')) as $comparison) {
            $operands = $comparison instanceof Expr\BinaryOp ? [$comparison->left, $comparison->right] : array_slice(AuthExpressions::args($comparison), 0, 1);
            foreach ($operands as $operand) {
                if (! ($operand instanceof Expr\PropertyFetch || $operand instanceof Expr\NullsafePropertyFetch) || ! $operand->name instanceof Node\Identifier) {
                    continue;
                }
                $name = $operand->name->toString();
                if ($field !== null ? $name === $field : ($receiver !== null && self::isStatusField($name) && $this->print($operand->var) === $receiver)) {
                    return true;
                }
            }
        }

        return false;
    }

    private static function isStatusField(string $name): bool
    {
        return preg_match('/(^|_)(status|state|stage|step)$/i', $name) === 1 || preg_match('/[a-z0-9](Status|State|Stage|Step)$/', $name) === 1;
    }

    // ---- helpers ------------------------------------------------------------------------------------------------

    private function exclude(string $key, ?Category $category, string $reason, string $source): void
    {
        $this->exclusions[] = new Exclusion($key, $category, $reason, $source);
    }

    private function checkText(AuthCheck $check): string
    {
        return sprintf('%s (%s:%d)', $check->source, $check->file, $check->line);
    }

    /** @return list<string> */
    private function paths(): array
    {
        $out = [];
        foreach ($this->config->paths as $path) {
            $path = trim(preg_replace('#^\./#', '', $path) ?? $path, '/');
            if ($path !== '') {
                $out[] = $path;
            }
        }

        return $out;
    }

    /** @param list<string> $paths */
    private static function under(string $file, array $paths): bool
    {
        foreach ($paths as $path) {
            if ($file === $path || str_starts_with($file, $path.'/')) {
                return true;
            }
        }

        return false;
    }

    private function actionFile(RouteEntry $route): string
    {
        $action = $route->action;
        if ($action->closure === null && $action->class !== null && $action->method !== null) {
            $method = $this->symbols->findMethod($action->class, $action->method);
            if ($method !== null) {
                return $method->file;
            }
        }

        return $route->file;
    }

    private static function key(RouteEntry $route): string
    {
        return implode('|', $route->methods).' '.$route->uri;
    }

    private static function callName(Expr $call): string
    {
        return $call instanceof Expr\New_ ? '__construct' : (AuthExpressions::name($call) ?? '');
    }

    private static function unwrap(Expr $expr): Expr
    {
        for ($i = 0; $i < 4; $i++) {
            if ($expr instanceof Expr\Cast) {
                $expr = $expr->expr;
            } elseif ($expr instanceof Expr\FuncCall && in_array(AuthExpressions::name($expr), self::WRAPPERS, true) && count(AuthExpressions::args($expr)) >= 1) {
                $expr = AuthExpressions::args($expr)[0];
            } else {
                break;
            }
        }

        return $expr;
    }

    private static function isVariable(Expr $expr, string $name): bool
    {
        return $expr instanceof Expr\Variable && $expr->name === $name;
    }

    // Mirrors Laravel's Str::snake for parameter binding.
    private static function snake(string $value): string
    {
        return ctype_lower($value) ? $value : mb_strtolower((string) preg_replace('/(.)(?=[A-Z])/u', '$1_', $value), 'UTF-8');
    }

    private function print(Expr $expr): string
    {
        $text = (string) preg_replace('/\\\\?(?:[A-Za-z_][A-Za-z0-9_]*\\\\)+([A-Za-z_][A-Za-z0-9_]*)/', '$1', $this->printer->prettyPrintExpr($expr));
        $text = (string) preg_replace('/\s+/', ' ', $text);

        return strlen($text) > self::MAX_SOURCE ? substr($text, 0, self::MAX_SOURCE - 3).'...' : $text;
    }

    private static function short(string $class): string
    {
        $pos = strrpos($class, '\\');

        return $pos === false ? $class : substr($class, $pos + 1);
    }
}
