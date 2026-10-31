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
use TusharKhan\SemanticSec\Framework\Laravel\Verbs;
use TusharKhan\SemanticSec\Parsing\CallGraph\CallGraphBuilder;
use TusharKhan\SemanticSec\Parsing\CallGraph\ExecutionPath;
use TusharKhan\SemanticSec\Parsing\CallGraph\PathNode;
use TusharKhan\SemanticSec\Parsing\CallGraph\TypeResolver;
use TusharKhan\SemanticSec\Parsing\Symbols\RelationResolver;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;

/** Decides which routes go to the LLM and for which categories (SPEC §7); when unsure, a route is a candidate. */
final class CandidateSelector
{
    public const NO_TRIGGER = 'no identifier / no state change';

    // Reason prefix for a category whose trigger never fired on the route.
    public const NO_TRIGGER_PREFIX = 'no trigger';

    private const STATE_VERBS = ['POST', 'PUT', 'PATCH', 'DELETE'];

    // An action named like this changes state even when its write is out of sight (SPEC §7 destroy-style action).
    private const DESTROY_STYLE = '/^(destroy$|delete|remove|purge|truncate)/i';

    private const DB_FACADES = ['Illuminate\\Support\\Facades\\DB', 'DB'];

    private const MASS_CALLS = ['create', 'update', 'fill', 'forcefill', 'upsert', 'firstorcreate', 'updateorcreate'];

    private const STATUS_WRITES = ['update', 'fill', 'forcefill', 'updateorcreate', 'updatequietly', 'forceupdate'];

    private const WORKFLOW_CALLS = ['cancel', 'refund', 'approve', 'reject', 'ship', 'complete', 'publish'];

    private const GUARDS = ['abort_if', 'abort_unless', 'throw_if', 'throw_unless'];

    private const BLOCKING = ['abort', 'abort_if', 'abort_unless', 'throw_if', 'throw_unless'];

    private const INPUT_READS = ['input', 'get', 'query', 'route', 'integer', 'post'];

    private const MASS_READS = ['all', 'input', 'post', 'collect', 'query'];

    // Calls that turn a query into a model or values (besides every first* and find*); anything after them leaves the scoped query.
    private const MATERIALISING = ['sole', 'get', 'value', 'pluck', 'cursor', 'lazy'];

    // Query and model methods Eloquent itself provides; any other method on a user-rooted chain is unknown.
    private const ELOQUENT_METHODS = [
        'where', 'orderby', 'orderbydesc', 'latest', 'oldest', 'with', 'without', 'withcount', 'limit', 'take', 'skip', 'offset', 'select',
        'addselect', 'distinct', 'groupby', 'having', 'withtrashed', 'onlytrashed', 'sole', 'get', 'value', 'pluck', 'count', 'exists',
        'doesntexist', 'paginate', 'simplepaginate', 'cursorpaginate', 'cursor', 'lazy', 'sum', 'max', 'min', 'avg', 'tobase', 'getresults',
    ];

    // Relation definitions a model's relation method builds, and the modifiers chained onto them.
    private const RELATION_DEFINITIONS = [
        'hasone', 'hasmany', 'belongsto', 'belongstomany', 'hasonethrough', 'hasmanythrough', 'morphone', 'morphmany', 'morphto', 'morphtomany',
        'morphedbymany', 'withpivot', 'withtimestamps', 'withdefault', 'as', 'using', 'wherepivot', 'ofmany', 'latestofmany', 'oldestofmany',
    ];

    // Builder calls that keep the query on the same rows or only shape the result.
    private const BUILDER_MODIFIERS = ['join', 'leftjoin', 'rightjoin', 'crossjoin', 'has', 'doesnthave', 'withwhere', 'lockforupdate', 'sharedlock', 'orderbyraw', 'selectraw', 'reorder', 'forpage', 'tosql', 'clone'];

    // Model reads usually called statically or on a collection of models.
    private const STATIC_READS = ['query', 'all', 'newquery', 'exists'];

    // Finders that throw when the scoped query has no such row.
    private const THROWING = ['findorfail', 'firstorfail', 'sole'];

    // Eloquent and Authenticatable methods a write may call directly on the user.
    private const USER_METHODS = ['getkey', 'getauthidentifier', 'can', 'cannot', 'cant', 'tokencan', 'fresh', 'refresh', 'load', 'loadmissing', 'toarray', 'tojson', 'only', 'getattribute', 'token', 'currentaccesstoken'];

    // Internal functions that run a callable argument.
    private const CALLABLE_FUNCTIONS = [
        'call_user_func', 'call_user_func_array', 'forward_static_call', 'forward_static_call_array', 'array_map', 'array_walk', 'array_walk_recursive',
        'array_filter', 'array_reduce', 'usort', 'uasort', 'uksort', 'iterator_apply', 'register_shutdown_function', 'spl_autoload_register',
    ];

    private const NOT_MASS = ['only', 'validated', 'safe'];

    // Laravel helpers equivalent to the request, the response or a safe facade, plus aborts.
    private const KNOWN_FUNCTIONS = [
        'response', 'request', 'auth', 'redirect', 'back', 'to_route', 'view', 'abort', 'abort_if', 'abort_unless', 'throw_if', 'throw_unless',
        'logger', 'info', 'config', 'session', 'cache', 'validator', 'trans', '__',
    ];

    private const SAFE_FACADES = ['Log', 'Cache', 'Validator', 'Config', 'Session', 'Auth', 'Request', 'Response'];

    private const FACADES_NS = 'Illuminate\\Support\\Facades\\';

    private const FACADES = ['Auth', 'Gate', 'DB', 'Cache', 'Log', 'Storage', 'Route', 'Request', 'Response', 'Session', 'Mail', 'Queue', 'Event', 'Config', 'Validator', 'Hash', 'URL', 'Redirect', 'Notification', 'Bus', 'Http'];

    private const WRAPPERS = ['intval', 'strval', 'trim', 'urldecode'];

    private const REQUESTS = ['Illuminate\\Http\\Request', 'Illuminate\\Foundation\\Http\\FormRequest'];

    private const REQUEST_FACADES = ['Illuminate\\Support\\Facades\\Request', 'Request'];

    private const MODEL_ROOTS = ['Illuminate\\Database\\Eloquent\\Model', 'Illuminate\\Foundation\\Auth\\User', 'Illuminate\\Database\\Eloquent\\Relations\\Pivot', 'Illuminate\\Database\\Eloquent\\Relations\\MorphPivot'];

    private const BUILDERS = ['Illuminate\\Database\\Eloquent\\Builder', 'Illuminate\\Database\\Query\\Builder'];

    private const RELATIONS_NS = 'Illuminate\\Database\\Eloquent\\Relations\\';

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

    /** @var array<string, list<Expr\Assign|Expr\AssignOp|Expr\AssignRef|Stmt\Foreach_>> per route: node id => its writes */
    private array $writeNodes = [];

    /** @var array<string, mixed> per route: memoised taint steps and callee taints */
    private array $taintMemo = [];

    /** @var array<string, array<string, array{0: string, 1: ?string}>> per route: node id => variable => [route parameter, bound model] */
    private array $routeVars = [];

    /** @var array<string, array<string, true>> per route: node id => parameters that receive mass input */
    private array $massVars = [];

    /** @var array<string, FunctionBody> per select(): function AST and class => its body, shared by every route */
    private array $bodyCache = [];

    /** @var array<string, true> per flowModels() walk: node and variable already expanded */
    private array $flowVisited = [];

    private int $flowDepth = 0;

    /** @var array<int, array<string, true>> per select(): spl id of an expression => the variable names it mentions */
    private array $mentionCache = [];

    /** @var array<string, true> per route: categories with a recorded exclusion */
    private array $decided = [];

    public function __construct(
        private readonly SymbolTable $symbols,
        private readonly CallGraphBuilder $graphs,
        private readonly AuthCheckExtractor $extractor,
        private readonly TypeResolver $types,
        private readonly RelationResolver $relations,
        private readonly Config $config,
    ) {
        $this->printer = new Standard();
    }

    /** @return array{0: list<Candidate>, 1: list<string>} */
    public function select(AuthorizationMap $map, bool $deep): array
    {
        $this->exclusions = [];
        $this->bodyCache = $this->mentionCache = [];
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
                $this->nodes = $this->bodies = $this->callees = $this->routeVars = $this->massVars = $this->decided = $this->writeNodes = $this->taintMemo = $this->flowVisited = [];
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
        $writes = $this->writes($path);
        $verbs = array_values(array_intersect($route->methods, self::STATE_VERBS));
        $destroy = $route->action->closure === null && $route->action->method !== null && preg_match(self::DESTROY_STYLE, $route->action->method) === 1 ? $route->action->method : null;
        if ($verbs !== [] || $writes !== [] || $destroy !== null) {
            $this->missingAuthorization($key, $path, $verbs, $writes, $destroy, $checks, $deep, $reasons);
        }
        $this->massAssignment($key, $path, $reasons);
        $this->deserialization($path, $reasons);
        $this->workflow($key, $path, $reasons);

        $why = [
            Category::Idor->value => 'no route parameter or id-named request input reaching a call',
            Category::MissingAuthorization->value => 'no state-changing verb, write or destroy-style action',
            Category::MassAssignment->value => 'no mass input reaching a model write',
            Category::InsecureDeserialization->value => 'no unserialize of a non-constant value',
            Category::WorkflowBypass->value => 'no status write or transition call',
        ];
        foreach (Category::cases() as $category) {
            if (! isset($reasons[$category->value]) && ! isset($this->decided[$category->value])) {
                $this->exclude($key, $category, self::NO_TRIGGER_PREFIX.': '.$why[$category->value], '');
            }
        }
        $this->decided = [];
        if ($reasons === []) {
            if ($identifiers === [] && $verbs === [] && $writes === [] && $destroy === null) {
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
            $fn = $node->closure ?? $node->method?->node;
            $cacheKey = $fn === null ? null : spl_object_id($fn).':'.($node->method->class ?? '');
            $this->bodies[$node->id] = $cacheKey === null ? new FunctionBody($this->symbols, $node) : ($this->bodyCache[$cacheKey] ??= new FunctionBody($this->symbols, $node));
        }
        // The call expression behind every edge, already-visited call sites included: matched by its file positions and name.
        $byCaller = [];
        $sitesOf = [];
        foreach ($path->edges as $edge) {
            $byCaller[$edge['caller']][$edge['start'].':'.$edge['end']][] = $edge['callee'];
        }
        foreach ($byCaller as $caller => $sites) {
            foreach (isset($this->bodies[$caller]) ? $this->bodies[$caller]->calls : [] as $call) {
                foreach ($sites[$call->getStartFilePos().':'.$call->getEndFilePos()] ?? [] as $calleeId) {
                    $callee = $this->nodes[$calleeId] ?? null;
                    if ($callee !== null && ($call instanceof Expr\FuncCall) === ($callee->method === null) && self::shortName(self::callName($call)) === self::calleeName($callee)) {
                        $this->callees[spl_object_id($call)] = $callee;
                        $sitesOf[$callee->id][] = [$call, $this->nodes[$caller]];
                    }
                }
            }
        }
        $entry = $path->entry();
        $this->routeVars[$entry->id] = $this->entryVariables($route, $this->bodies[$entry->id]);
        foreach ($path->nodes as $node) {
            $held = [];
            $sites = $this->argumentPairs($node, $sitesOf[$node->id] ?? []);
            foreach ($sites as $pairs) {
                foreach ($pairs as [$arg, $param, $parent]) {
                    $body = $this->bodies[$parent->id];
                    if ($arg instanceof Expr\Variable && is_string($arg->name) && isset($this->routeVars[$parent->id][$arg->name])) {
                        [$routeParam, $model] = $this->routeVars[$parent->id][$arg->name];
                        // A bound model counts only while the variable still holds it.
                        $held[$param][] = [$routeParam, $model !== null && $body->auth->isUntouchedParam($arg->name, $arg->getStartFilePos()) ? $model : null];
                    }
                    if ($this->isMassInput($arg, $body, $this->massVars[$parent->id] ?? [])) {
                        $this->massVars[$node->id][$param] = true;
                    }
                }
            }
            // A parameter holds a route variable only when every call site passes that same one.
            foreach ($held as $param => $values) {
                if (count($values) === count($sites) && count(array_unique(array_map('serialize', $values))) === 1) {
                    $this->routeVars[$node->id][$param] = $values[0];
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

    // Lower-cased name a call to the node is written with: the method name, or an app function's unqualified name.
    private static function calleeName(PathNode $node): ?string
    {
        if ($node->method !== null) {
            return strtolower($node->method->name);
        }

        return $node->closure instanceof Stmt\Function_ ? strtolower($node->closure->name->toString()) : null;
    }

    private static function shortName(string $name): string
    {
        $pos = strrpos($name, '\\');

        return $pos === false ? $name : substr($name, $pos + 1);
    }

    /** @return array<Node\Param> parameters of a method or app-function node */
    private static function params(PathNode $node): array
    {
        return $node->method?->node->params ?? ($node->closure instanceof Stmt\Function_ ? $node->closure->params : []);
    }

    /**
     * @param  list<array{Expr\CallLike, PathNode}>  $sites  every call reaching the node, and its caller
     * @return list<list<array{0: Expr, 1: string, 2: PathNode}>> per call site: argument in the caller, callee parameter, caller
     */
    private function argumentPairs(PathNode $node, array $sites): array
    {
        $out = [];
        $params = self::params($node);
        foreach ($sites as [$call, $caller]) {
            $pairs = [];
            foreach (AuthExpressions::args($call) as $i => $arg) {
                $param = $params[$i] ?? null;
                if ($param === null || $param->variadic || ! $param->var instanceof Expr\Variable || ! is_string($param->var->name)) {
                    break;
                }
                $pairs[] = [$arg, $param->var->name, $caller];
            }
            $out[] = $pairs;
        }

        return $out;
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
                    $out[] = new AuthCheck($c->kind, $c->strength, $c->source, $c->file, $c->line, $c->covers === null ? null : ($toRoute[$c->covers] ?? null), $c->model, $c->routeWide, $c->abilities, $c->abilityModel);
                }
            }
        }

        return $out;
    }

    // ---- idor ----------------------------------------------------------------------------------------------------

    /** @return list<array{label: string, param: ?string, bound: bool, models: list<string>, flows: list<array{known: bool, lookup: bool, model: ?string, scoped: bool, firm: bool, throws: bool, loose: bool, text: string}>}> */
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
            $bound = $p->boundModel !== null;
            $flows = $variable === null ? [] : $this->flowModels($entry, $variable, [], $bound);
            $models = $bound ? [(string) $p->boundModel] : self::knownModels($flows);
            $out[] = ['label' => '{'.$p->name.'}', 'param' => $p->name, 'bound' => $bound, 'models' => $models, 'flows' => $flows];
        }
        foreach ($path->nodes as $node) {
            $body = $this->bodies[$node->id];
            foreach ((new NodeFinder())->find($body->stmts, static fn (Node $n): bool => $n instanceof Expr\CallLike || $n instanceof Expr\PropertyFetch
                || $n instanceof Expr\NullsafePropertyFetch || $n instanceof Expr\ArrayDimFetch) as $read) {
                \assert($read instanceof Expr);
                $name = $this->idInputName($read, $body, $node);
                if ($name === null) {
                    continue;
                }
                $flows = $this->readModels($node, $read);
                if ($flows !== []) {
                    $out[] = ['label' => sprintf("request input '%s'", $name), 'param' => null, 'bound' => false, 'models' => self::knownModels($flows), 'flows' => $flows];
                }
            }
            // Request input of any name that reaches a pivot or relation write chooses which rows get linked.
            foreach ($body->calls as $call) {
                if (! AuthExpressions::isCall($call) && ! $call instanceof Expr\StaticCall || ! $this->isChosenLink($call) || ! $this->carriesInput($call, $body, $node)) {
                    continue;
                }
                $where = sprintf('%s (%s:%d)', $this->print($call), $node->file, $call->getStartLine());
                $out[] = ['label' => 'request input to '.$where, 'param' => null, 'bound' => false, 'models' => [], 'flows' => [self::unknownFlow($where)]];
            }
        }

        return $out;
    }

    // Some argument of the call holds request input (directly, through a variable, or as a callee's mass-input parameter).
    private function carriesInput(Expr\CallLike $call, FunctionBody $body, PathNode $node): bool
    {
        $massVars = $this->massVars[$node->id] ?? [];
        foreach ($call->isFirstClassCallable() ? [] : $call->getArgs() as $arg) {
            $hit = (new NodeFinder())->findFirst([$arg->value], static fn (Node $n): bool => $n instanceof Expr
                && (($n instanceof Expr\Variable && is_string($n->name) && isset($massVars[$n->name])) || $body->auth->isRequestInput($n)));
            if ($hit !== null || $this->isMassInput($arg->value, $body, $massVars)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  list<array{label: string, param: ?string, bound: bool, models: list<string>, flows: list<array{known: bool, lookup: bool, model: ?string, scoped: bool, firm: bool, throws: bool, loose: bool, text: string}>}>  $identifiers
     * @param  list<AuthCheck>  $checks
     * @param  array<string, string>  $reasons
     */
    private function idor(string $key, array $identifiers, array $checks, bool $deep, array &$reasons): void
    {
        $uncovered = [];
        $sources = [];
        foreach ($identifiers as $identifier) {
            $source = $this->coverage($identifier, $checks);
            if ($source === null) {
                $uncovered[] = $identifier['label'].($identifier['models'] === [] ? '' : ' (looked up on '.implode(', ', array_map(self::short(...), $identifier['models'])).')');
            } else {
                $sources[] = $identifier['label'].': '.$source;
            }
        }
        if ($uncovered !== []) {
            $reasons[Category::Idor->value] = ($deep ? '--deep: ' : '').'identifier '.implode(', ', array_unique($uncovered)).' not covered by an authorization check';

            return;
        }
        $covered = implode('; ', array_unique($sources));
        if ($deep) {
            $reasons[Category::Idor->value] = '--deep: every identifier is covered by an authorization check: '.$covered;

            return;
        }
        $this->exclude($key, Category::Idor, 'every identifier is covered by an authorization check', $covered);
    }

    /**
     * (a) a check covering the parameter; (b) the lookup receiving the identifier is itself scoped to the user;
     * (c) a route-wide check.
     *
     * @param  array{label: string, param: ?string, bound: bool, models: list<string>, flows: list<array{known: bool, lookup: bool, model: ?string, scoped: bool, firm: bool, throws: bool, loose: bool, text: string}>}  $identifier
     * @param  list<AuthCheck>  $checks
     */
    private function coverage(array $identifier, array $checks): ?string
    {
        foreach ($checks as $c) {
            if ($identifier['param'] !== null && $c->covers === $identifier['param']) {
                return $this->checkText($c);
            }
        }
        $flows = $identifier['flows'];
        if ($identifier['bound']) {
            // A bound model is protected only by an unconditional, throwing scoped lookup that receives it directly.
            foreach ($flows as $flow) {
                if ($flow['lookup'] && $flow['scoped'] && $flow['firm'] && $flow['throws'] && ! $flow['loose']) {
                    return $flow['text'];
                }
            }
        } elseif ($flows !== [] && array_filter($flows, static fn (array $f): bool => ! $f['lookup'] || ! $f['scoped']) === []) {
            return implode('; ', array_unique(array_map(static fn (array $f): string => $f['text'], $flows)));
        }
        foreach ($checks as $c) {
            if ($c->routeWide && $c->covers === null) {
                return $this->checkText($c);
            }
        }

        return null;
    }

    /**
     * @param  list<array{known: bool, lookup: bool, model: ?string, scoped: bool, firm: bool, throws: bool, loose: bool, text: string}>  $flows
     * @return list<string>
     */
    private static function knownModels(array $flows): array
    {
        $out = [];
        foreach ($flows as $flow) {
            if ($flow['model'] !== null) {
                $out[$flow['model']] = true;
            }
        }

        return array_keys($out);
    }

    // The id-like name a request read uses: ->input('post_id'), request('id'), Request::query('userId'), ->post_id, ['post_id'],
    // and ['post_id'] on an array of request input ($q = $request->all(); $q['post_id']).
    private function idInputName(Expr $read, FunctionBody $body, PathNode $node): ?string
    {
        $key = null;
        if ($read instanceof Expr\PropertyFetch || $read instanceof Expr\NullsafePropertyFetch) {
            $key = $read->name instanceof Node\Identifier && $this->isRequestReceiver($read->var, $body) ? $read->name->toString() : null;
        } elseif ($read instanceof Expr\ArrayDimFetch) {
            $key = $read->dim instanceof Node\Scalar\String_ && self::isIdName($read->dim->value) && $this->isRequestArray($read->var, $body, $node) ? $read->dim->value : null;
        } else {
            $name = AuthExpressions::name($read);
            $isRead = match (true) {
                $read instanceof Expr\FuncCall => $name === 'request',
                $read instanceof Expr\StaticCall => self::isRequestFacade($read->class) && in_array($name, self::INPUT_READS, true),
                AuthExpressions::isCall($read) => in_array($name, self::INPUT_READS, true) && $this->isRequestReceiver($read->var, $body),
                default => false,
            };
            $arg = $isRead ? (AuthExpressions::args($read)[0] ?? null) : null;
            $key = $arg instanceof Node\Scalar\String_ ? $arg->value : null;
        }
        if ($key === null) {
            return null;
        }

        return self::isIdName($key) ? $key : null;
    }

    private static function isIdName(string $key): bool
    {
        return $key === 'id' || str_ends_with($key, '_id') || preg_match('/[a-z0-9]Id$/', $key) === 1;
    }

    // The request itself, any request-input value ($request->all(), validated(), only(..), a variable holding one), or a
    // callee parameter that receives mass input.
    private function isRequestArray(Expr $expr, FunctionBody $body, PathNode $node): bool
    {
        if ($this->isRequestReceiver($expr, $body)) {
            return true;
        }
        if ($expr instanceof Expr\Variable && is_string($expr->name) && isset($this->massVars[$node->id][$expr->name])) {
            return true;
        }

        return ! $expr instanceof Expr\PropertyFetch && ! $expr instanceof Expr\NullsafePropertyFetch && $body->auth->isRequestInput($expr);
    }

    /**
     * Where a request read flows: up through casts, wrappers and arrays into a call, or into a variable.
     *
     * @return list<array{known: bool, lookup: bool, model: ?string, scoped: bool, firm: bool, throws: bool, loose: bool, text: string}>
     */
    private function readModels(PathNode $node, Expr $read): array
    {
        $body = $this->bodies[$node->id];
        $expr = $read;
        $wrapped = false;
        for ($i = 0; $i < 12; $i++) {
            $parent = $body->positions->parent($expr);
            if ($parent instanceof Expr\Cast || $parent instanceof Expr\BinaryOp\Coalesce || $parent instanceof Expr\Ternary) {
                $expr = $parent;

                continue;
            }
            if ($parent instanceof Node\ArrayItem || $parent instanceof Expr\Array_) {
                $wrapped = true;
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

                    $flows = $this->consumer($node, $call, is_int($index) ? $index : -1, $wrapped || $parent->unpack, [], false, $parent->name?->toString());
                    // A call that may return the read passes it on: follow its result too.
                    if (! $this->isRealLookup($node, $call) && $this->calleeReturns($node, $call, $parent, 0)) {
                        foreach ($this->readModels($node, $call) as $flow) {
                            $flow['loose'] = true;
                            $flows[] = $flow;
                        }
                    }

                    return $flows;
                }
            }
            if ($parent instanceof Expr\Assign && $parent->expr === $expr && $parent->var instanceof Expr\Variable && is_string($parent->var->name)) {
                return $this->flowModels($node, $parent->var->name, [], false);
            }

            return [];
        }

        return [];
    }

    /**
     * Where a variable goes: every call it is an argument of (followed into callees) and every variable it is copied to.
     * $bound: the variable holds a bound model, so `$v->id` and `$v->getKey()` carry its key.
     *
     * @param  array<string, true>  $seen
     * @return list<array{known: bool, lookup: bool, model: ?string, scoped: bool, firm: bool, throws: bool, loose: bool, text: string}>
     */
    private function flowModels(PathNode $node, string $var, array $seen, bool $bound): array
    {
        $key = $node->id."\0".$var;
        if ($this->flowDepth === 0) {
            $this->flowVisited = [];
        }
        // Each variable is expanded once per walk: its flows are the same whichever path reached it.
        if (isset($seen[$key]) || isset($this->flowVisited[$key])) {
            return [];
        }
        if (count($seen) > 24) {
            return [self::unknownFlow()];
        }
        $seen[$key] = true;
        $this->flowVisited[$key] = true;
        $this->flowDepth++;
        try {
            return $this->expandFlows($node, $var, $seen, $bound);
        } finally {
            $this->flowDepth--;
        }
    }

    /**
     * @param  array<string, true>  $seen
     * @return list<array{known: bool, lookup: bool, model: ?string, scoped: bool, firm: bool, throws: bool, loose: bool, text: string}>
     */
    private function expandFlows(PathNode $node, string $var, array $seen, bool $bound): array
    {
        $body = $this->bodies[$node->id];
        $flows = [];
        foreach ($body->calls as $call) {
            if (($call instanceof Expr\New_ && ! isset($this->callees[spl_object_id($call)])) || $call->isFirstClassCallable()) {
                continue;
            }
            foreach ($call->getRawArgs() as $index => $arg) {
                if (! $arg instanceof Node\Arg) {
                    continue;
                }
                $direct = $this->carries(self::unwrap($arg->value), $var, $bound);
                if (! $direct && ! $this->mentions($arg->value, $var)) {
                    continue;
                }
                foreach ($this->consumer($node, $call, $index, ! $direct || $arg->unpack, $seen, $bound, $arg->name?->toString()) as $flow) {
                    $flow['loose'] = $flow['loose'] || ! $direct;
                    $flows[] = $flow;
                }
            }
        }
        // Every write of a value carrying the identifier carries it on, loosely unless it is a plain copy.
        foreach ($this->taintedWrites($node, $var, 0) as [$target, $copy]) {
            if (! $target instanceof Expr\Variable || ! is_string($target->name)) {
                $flows[] = self::unknownFlow();

                continue;
            }
            if ($target->name === $var) {
                continue;
            }
            foreach ($this->flowModels($node, $target->name, $seen, $copy && $bound) as $flow) {
                $flow['loose'] = $flow['loose'] || ! $copy;
                $flows[] = $flow;
            }
        }
        return $flows;
    }

    private function carries(Expr $expr, string $var, bool $bound): bool
    {
        if (self::isVariable($expr, $var)) {
            return true;
        }
        if (! $bound) {
            return false;
        }
        $id = ($expr instanceof Expr\PropertyFetch || $expr instanceof Expr\NullsafePropertyFetch) && $expr->name instanceof Node\Identifier && $expr->name->toString() === 'id';
        $key = AuthExpressions::isCall($expr) && AuthExpressions::name($expr) === 'getkey';

        return ($id || $key) && self::isVariable($expr->var, $var);
    }

    // The value of $rhs may still hold the identifier: it is mentioned outside a model lookup's arguments (a lookup's result
    // is a model, analysed as a consumer of its own) and outside a followed callee that never returns it; any other call may.
    private function carriedBy(Expr $rhs, string $var, PathNode $node, int $depth = 0): bool
    {
        $body = $this->bodies[$node->id];
        $occurrences = (new NodeFinder())->find([$rhs], fn (Node $n): bool => $n instanceof Expr && $this->mentionsDirectly($n, $var));
        foreach ($occurrences as $occurrence) {
            $consumed = false;
            $child = $occurrence;
            for ($p = $body->positions->parent($occurrence); $p !== null && $occurrence !== $rhs; $p = $body->positions->parent($p)) {
                if ($p instanceof Expr\CallLike && ! $p->isFirstClassCallable() && $this->isRealLookup($node, $p)) {
                    $consumed = true;

                    break;
                }
                if ($p instanceof Expr\CallLike && $child instanceof Node\Arg && self::unwrap($child->value) === $occurrence && ! $this->calleeReturns($node, $p, $child, $depth)) {
                    $consumed = true;

                    break;
                }
                if ($p === $rhs) {
                    break;
                }
                $child = $p;
            }
            if (! $consumed) {
                return true;
            }
        }

        return false;
    }

    // Whether a followed callee may return the argument: false only when the argument maps to a plain parameter and
    // no return of the callee carries it (through local copies too).
    private function calleeReturns(PathNode $node, Expr\CallLike $call, Node\Arg $arg, int $depth): bool
    {
        $callee = $this->callees[spl_object_id($call)] ?? null;
        $index = array_search($arg, $call->getRawArgs(), true);
        $param = $callee === null || $arg->unpack || ! is_int($index) ? null : $this->calleeParam($callee, $index, $arg->name?->toString());
        $calleeBody = $callee === null ? null : ($this->bodies[$callee->id] ?? null);
        if ($callee === null || $param === null || $calleeBody === null) {
            return true;
        }
        $tainted = $this->calleeTaint($callee, $param, $depth);
        if ($tainted === null) {
            return true;
        }
        foreach ((new NodeFinder())->find($calleeBody->stmts, static fn (Node $n): bool => $n instanceof Stmt\Return_ || $n instanceof Expr\Yield_ || $n instanceof Expr\YieldFrom || $n instanceof Expr\ArrowFunction) as $exit) {
            $value = match (true) {
                $exit instanceof Stmt\Return_, $exit instanceof Expr\YieldFrom, $exit instanceof Expr\ArrowFunction => $exit->expr,
                $exit instanceof Expr\Yield_ => $exit->value,
                default => null,
            };
            foreach (array_keys($tainted) as $t) {
                if ($value !== null && $this->carriedBy($value, (string) $t, $callee, $depth + 1)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * One taint step, shared by route bodies and callees: every write of a value carrying $var (assignments of every
     * kind, list destructuring, foreach value and key, by-reference outputs of a call it is passed to).
     *
     * @return list<array{Expr, bool}> target, and whether it is a plain copy of $var
     */
    private function taintedWrites(PathNode $node, string $var, int $depth): array
    {
        $key = 'w'.$node->id."\0".$var."\0".$depth;
        if (array_key_exists($key, $this->taintMemo)) {
            /** @var list<array{Expr, bool}> */
            return $this->taintMemo[$key];
        }
        $body = $this->bodies[$node->id];
        $out = [];
        if (! isset($this->writeNodes[$node->id])) {
            /** @var list<Expr\Assign|Expr\AssignOp|Expr\AssignRef|Stmt\Foreach_> $found */
            $found = (new NodeFinder())->find($body->stmts, static fn (Node $n): bool => $n instanceof Expr\Assign || $n instanceof Expr\AssignOp || $n instanceof Expr\AssignRef || $n instanceof Stmt\Foreach_);
            $this->writeNodes[$node->id] = $found;
        }
        foreach ($this->writeNodes[$node->id] as $write) {
            if (! $this->carriedBy($write->expr, $var, $node, $depth)) {
                continue;
            }
            $copy = $write instanceof Expr\Assign && self::isVariable(self::unwrap($write->expr), $var);
            $targets = $write instanceof Stmt\Foreach_ ? array_filter([$write->valueVar, $write->keyVar]) : [$write->var];
            foreach ($targets as $target) {
                foreach (self::destructured($target) as $leaf) {
                    $out[] = [$leaf, $copy && $leaf === $target];
                }
            }
        }
        foreach ($body->calls as $call) {
            foreach ($this->refOutputs($node, $call, $var, $depth) as $target) {
                $out[] = [$target, false];
            }
        }

        return $this->taintMemo[$key] = $out;
    }

    /** @return list<Expr> the variables a list or array destructuring target writes, or the target itself */
    private static function destructured(Expr $target): array
    {
        if (! $target instanceof Expr\List_ && ! $target instanceof Expr\Array_) {
            return [$target];
        }
        $out = [];
        foreach ($target->items as $item) {
            if ($item !== null) {
                array_push($out, ...self::destructured($item->value));
            }
        }

        return $out;
    }

    /**
     * Arguments a call may write a value carrying $var into: by-reference parameters a followed callee taints, every
     * by-reference parameter of an internal function, and every other variable argument of any other non-lookup call.
     *
     * @return list<Expr>
     */
    private function refOutputs(PathNode $node, Expr\CallLike $call, string $var, int $depth): array
    {
        if ($call->isFirstClassCallable()) {
            return [];
        }
        $args = array_values(array_filter($call->getRawArgs(), static fn ($a): bool => $a instanceof Node\Arg));
        $carrier = null;
        foreach ($args as $arg) {
            if ($this->mentions($arg->value, $var)) {
                $carrier = $arg;

                break;
            }
        }
        if ($carrier === null || $this->isRealLookup($node, $call)) {
            return [];
        }
        $callee = $this->callees[spl_object_id($call)] ?? null;
        $params = null;
        if ($callee !== null) {
            $index = array_search($carrier, $call->getRawArgs(), true);
            $param = $carrier->unpack || ! is_int($index) || ! self::isVariable(self::unwrap($carrier->value), $var) ? null : $this->calleeParam($callee, $index, $carrier->name?->toString());
            $tainted = $param === null || $depth > 4 ? null : $this->calleeTaint($callee, $param, $depth + 1);
            if ($tainted !== null) {
                $params = [];
                foreach (self::params($callee) as $i => $p) {
                    if ($p->byRef && $p->var instanceof Expr\Variable && is_string($p->var->name) && isset($tainted[$p->var->name])) {
                        $params[$i] = $p->var->name;
                    }
                }
            }
        } elseif ($call instanceof Expr\FuncCall && $call->name instanceof Node\Name && function_exists($name = ltrim($call->name->toString(), '\\')) && (new \ReflectionFunction($name))->isInternal()) {
            $params = [];
            foreach ((new \ReflectionFunction($name))->getParameters() as $p) {
                if ($p->isPassedByReference()) {
                    $params[$p->getPosition()] = $p->getName();
                }
            }
        } elseif ($call instanceof Expr\FuncCall && $call->name instanceof Node\Name && $this->knownFunction(strtolower(ltrim($call->name->toString(), '\\')))) {
            return [];
        }
        $out = [];
        foreach ($args as $i => $arg) {
            if ($arg === $carrier || self::isVariable(self::unwrap($arg->value), $var)) {
                continue;
            }
            $hit = $params === null ? ! $arg->unpack && self::unwrap($arg->value) instanceof Expr\Variable
                : ($arg->name === null ? isset($params[$i]) : in_array($arg->name->toString(), $params, true));
            if ($hit) {
                $out[] = $arg->value;
            }
        }

        return $out;
    }

    /**
     * Variables of a callee that may hold its parameter, by the shared taint walk; null when the value escapes into a
     * property, an array element or another non-variable target.
     *
     * @return array<string, true>|null
     */
    private function calleeTaint(PathNode $callee, string $param, int $depth): ?array
    {
        if ($depth > 4 || ! isset($this->bodies[$callee->id])) {
            return null;
        }
        $key = 't'.$callee->id."\0".$param."\0".$depth;
        if (array_key_exists($key, $this->taintMemo)) {
            /** @var array<string, true>|null */
            return $this->taintMemo[$key];
        }
        // Guards recursion through the callee's own calls.
        $this->taintMemo[$key] = null;
        $tainted = [$param => true];
        $queue = [$param];
        while ($queue !== []) {
            $var = array_shift($queue);
            foreach ($this->taintedWrites($callee, $var, $depth + 1) as [$target]) {
                if (! $target instanceof Expr\Variable || ! is_string($target->name) || count($tainted) > 32) {
                    return $this->taintMemo[$key] = null;
                }
                if (! isset($tainted[$target->name])) {
                    $tainted[$target->name] = true;
                    $queue[] = $target->name;
                }
            }
        }

        return $this->taintMemo[$key] = $tainted;
    }

    // The callee parameter an argument binds to, by name when named; null when it is variadic or not a plain variable.
    private function calleeParam(PathNode $callee, int $index, ?string $named): ?string
    {
        $params = self::params($callee);
        $param = $params[$index] ?? null;
        if ($named !== null) {
            $param = null;
            foreach ($params as $candidate) {
                if ($candidate->var instanceof Expr\Variable && $candidate->var->name === $named) {
                    $param = $candidate;
                }
            }
        }
        if ($param === null || $param->variadic || ! $param->var instanceof Expr\Variable || ! is_string($param->var->name)) {
            return null;
        }

        return $param->var->name;
    }

    private function mentionsDirectly(Node $n, string $var): bool
    {
        if ($n instanceof Expr\Variable) {
            return $n->name === $var;
        }
        if (! AuthExpressions::isFunc($n, 'compact')) {
            return false;
        }
        foreach (AuthExpressions::args($n) as $arg) {
            if ($arg instanceof Node\Scalar\String_ && $arg->value === $var) {
                return true;
            }
        }

        return false;
    }

    private function mentions(Expr $expr, string $var): bool
    {
        $id = spl_object_id($expr);
        if (! isset($this->mentionCache[$id])) {
            $names = [];
            foreach ((new NodeFinder())->find([$expr], static fn (Node $n): bool => $n instanceof Expr\Variable || AuthExpressions::isFunc($n, 'compact')) as $n) {
                if ($n instanceof Expr\Variable) {
                    if (is_string($n->name)) {
                        $names[$n->name] = true;
                    }

                    continue;
                }
                foreach (AuthExpressions::args($n) as $arg) {
                    if ($arg instanceof Node\Scalar\String_) {
                        $names[$arg->value] = true;
                    }
                }
            }
            $this->mentionCache[$id] = $names;
        }

        return isset($this->mentionCache[$id][$var]);
    }

    /**
     * What a call does with an argument: follow it into a callee, record a lookup, ignore a known harmless call,
     * or report an unknown effect. $loose: the argument is inside an array, named or unpacked.
     *
     * @param  array<string, true>  $seen
     * @return list<array{known: bool, lookup: bool, model: ?string, scoped: bool, firm: bool, throws: bool, loose: bool, text: string}>
     */
    private function consumer(PathNode $node, Expr\CallLike $call, int $index, bool $loose, array $seen, bool $bound, ?string $named = null): array
    {
        $name = AuthExpressions::name($call) ?? '';
        $callee = $this->callees[spl_object_id($call)] ?? null;
        if ($callee !== null) {
            $param = $this->calleeParam($callee, $index, $named);
            if ($loose || $param === null) {
                return [self::unknownFlow()];
            }

            return $this->flowModels($callee, $param, $seen, $bound);
        }
        // A pivot or relation write links whatever rows the value names.
        if (! $call instanceof Expr\FuncCall && in_array($name, Verbs::RELATION_WRITES, true)) {
            return [self::unknownFlow(sprintf('%s (%s:%d)', $this->print($call), $node->file, $call->getStartLine()))];
        }
        if (($call instanceof Expr\StaticCall || AuthExpressions::isCall($call)) && $this->isRealLookup($node, $call)) {
            return [$this->lookupFlow($node, $call)];
        }
        if ($call instanceof Expr\FuncCall) {
            return $this->knownFunction($name) || in_array($name, self::WRAPPERS, true) ? [] : [self::unknownFlow()];
        }
        if ($call instanceof Expr\StaticCall && $this->types->staticModel($call, $node) !== null) {
            return [];
        }
        if (AuthExpressions::isCall($call) && ($this->harmlessReceiver($call->var, $this->bodies[$node->id]) || $this->types->queryModel($call->var, $node) !== null)) {
            return [];
        }

        // Anything else may look it up out of sight.
        return [self::unknownFlow()];
    }

    /** @return array{known: bool, lookup: bool, model: ?string, scoped: bool, firm: bool, throws: bool, loose: bool, text: string} */
    private static function unknownFlow(string $text = ''): array
    {
        return ['known' => false, 'lookup' => false, 'model' => null, 'scoped' => false, 'firm' => false, 'throws' => false, 'loose' => false, 'text' => $text];
    }

    /** @return array{known: bool, lookup: bool, model: ?string, scoped: bool, firm: bool, throws: bool, loose: bool, text: string} */
    private function lookupFlow(PathNode $node, Expr\StaticCall|Expr\MethodCall|Expr\NullsafeMethodCall $call): array
    {
        $body = $this->bodies[$node->id];
        $top = $call;
        // Climb to the outermost call of the fluent chain.
        while (($p = $body->positions->parent($top)) !== null && AuthExpressions::isCall($p) && $p->var === $top) {
            $top = $p;
        }

        return [
            'known' => true,
            'lookup' => true,
            'model' => $this->lookupModel($node, $call),
            'scoped' => $this->chainScoped($top, $body, $node, true) && ! $this->widened($top, $body),
            'firm' => $body->positions->isUnconditional($call) && $this->effective($node),
            'throws' => in_array(AuthExpressions::name($call), self::THROWING, true) || in_array(AuthExpressions::name($top), self::THROWING, true),
            'loose' => false,
            'text' => sprintf('%s (%s:%d)', $this->print($top), $node->file, $call->getStartLine()),
        ];
    }

    // A lookup-named call on a model class, or on a receiver typed as a model, an Eloquent or query builder, or a relation.
    private function isRealLookup(PathNode $node, Expr\CallLike $call): bool
    {
        if (! Verbs::isLookup(AuthExpressions::name($call) ?? '')) {
            return false;
        }
        if ($call instanceof Expr\StaticCall) {
            return $this->types->staticModel($call, $node) !== null;
        }
        if (! AuthExpressions::isCall($call)) {
            return false;
        }
        if ($this->types->queryModel($call->var, $node) !== null) {
            return true;
        }
        $type = $this->types->typeOf($call->var, $node);

        return $type !== null && (in_array($type, self::BUILDERS, true) || str_starts_with($type, self::RELATIONS_NS));
    }

    // The finder's class: X in X::find|where..(), or the model a query or relation receiver reads.
    private function lookupModel(PathNode $node, Expr\StaticCall|Expr\MethodCall|Expr\NullsafeMethodCall $call): ?string
    {
        if ($call instanceof Expr\StaticCall) {
            return $this->types->staticModel($call, $node);
        }

        return $this->types->queryModel($call->var, $node);
    }

    /**
     * A query chain scoped to the user: it holds where(col, <auth id>) / whereBelongsTo(<auth user>), or (when $relations)
     * starts at the auth user through a relation method; an orWhere, a scope reset or a call after first()/find()/get() voids it.
     */
    private function chainScoped(Expr $top, FunctionBody $body, PathNode $node, bool $relations): bool
    {
        $expr = $top;
        $hops = [];
        $where = false;
        while (! $body->auth->isAuthUser($expr)) {
            if (AuthExpressions::isCall($expr) || $expr instanceof Expr\StaticCall) {
                $name = AuthExpressions::name($expr) ?? '';
                if (str_starts_with($name, 'orwhere') || in_array($name, Verbs::SCOPE_RESETS, true)) {
                    return false;
                }
                // A model or value taken out of the query ends the scope for anything chained after it.
                if ($hops !== [] && self::materialises($name)) {
                    return false;
                }
                $where = $where || $body->auth->isWhereScope($expr);
                $hops[] = $expr;
                if ($expr instanceof Expr\StaticCall) {
                    return $where;
                }
                $expr = $expr->var;
            } elseif ($expr instanceof Expr\PropertyFetch || $expr instanceof Expr\NullsafePropertyFetch) {
                $hops[] = $expr;
                $expr = $expr->var;
            } else {
                return $where;
            }
        }
        if ($where) {
            return true;
        }
        $first = $hops[count($hops) - 1] ?? null;

        return $relations && $first !== null && AuthExpressions::isCall($first) && $this->isRelation($expr, $first, $node);
    }

    /**
     * A still-unmaterialised query chain that leaves the code the selector can see: passed to a call that is not a builder
     * method, or held in a variable that later is (or is reassigned from one, or widened by orWhere or an unknown method).
     */
    private function widened(Expr $top, FunctionBody $body): bool
    {
        $name = AuthExpressions::name($top) ?? '';
        if (self::materialises($name) || in_array($name, Verbs::READS, true)) {
            return false;
        }
        $parent = $body->positions->parent($top);
        if ($parent instanceof Node\Arg) {
            return $this->escapesInto($body->positions->parent($parent), $body);
        }
        if (! $parent instanceof Expr\Assign || $parent->expr !== $top || ! $parent->var instanceof Expr\Variable || ! is_string($parent->var->name)) {
            return false;
        }
        $var = $parent->var->name;

        return $this->builderEscapes($var, $body, true, fn (Expr $value): bool => $value === $top || $this->builderChainOn($value, $var));
    }

    /**
     * Whether a builder held in $var may be changed out of sight: passed to a non-builder call, captured by a closure,
     * taken by reference, reassigned from a value $keeps rejects, or (strict) chained with orWhere, a scope reset or an
     * unknown method; otherwise only orWhere and scope resets count.
     *
     * @param  callable(Expr): bool  $keeps
     */
    private function builderEscapes(string $var, FunctionBody $body, bool $strict, callable $keeps): bool
    {
        foreach ((new NodeFinder())->find($body->stmts, static fn (Node $n): bool => ($n instanceof Expr\Variable && $n->name === $var)
            || ($n instanceof Node\ClosureUse && $n->var->name === $var)) as $use) {
            if ($use instanceof Node\ClosureUse) {
                return true;
            }
            \assert($use instanceof Expr);
            $parent = $body->positions->parent($use);
            if ($parent instanceof Expr\AssignRef) {
                return true;
            }
            if ($parent instanceof Expr\Assign && $parent->var === $use) {
                if (! $keeps($parent->expr)) {
                    return true;
                }

                continue;
            }
            if ($parent instanceof Node\Arg && $this->escapesInto($body->positions->parent($parent), $body)) {
                return true;
            }
            for ($at = $use; ($p = $body->positions->parent($at)) !== null && AuthExpressions::isCall($p) && $p->var === $at; $at = $p) {
                $call = AuthExpressions::name($p) ?? '';
                if (str_starts_with($call, 'orwhere') || in_array($call, Verbs::SCOPE_RESETS, true) || ($strict && ! self::isBuilderMethod($call))) {
                    return true;
                }
            }
        }

        return false;
    }

    // A call a builder argument may be changed by: anything but a builder method or a request, response or safe-facade call.
    private function escapesInto(?Node $call, FunctionBody $body): bool
    {
        if (! $call instanceof Expr\CallLike) {
            return false;
        }
        $name = AuthExpressions::name($call) ?? '';
        if ($call instanceof Expr\FuncCall) {
            return ! $this->knownFunction($name);
        }
        if ($call instanceof Expr\StaticCall) {
            return ! ($call->class instanceof Node\Name && self::isSafeFacade(ltrim($call->class->toString(), '\\'))) && ! self::isBuilderMethod($name);
        }

        return ! ($call instanceof Expr\MethodCall || $call instanceof Expr\NullsafeMethodCall) || ! ($this->harmlessReceiver($call->var, $body) || self::isBuilderMethod($name));
    }

    // $value is $var itself or a chain of builder methods on it.
    private function builderChainOn(Expr $value, string $var): bool
    {
        while (AuthExpressions::isCall($value)) {
            if (! self::isBuilderMethod(AuthExpressions::name($value) ?? '')) {
                return false;
            }
            $value = $value->var;
        }

        return self::isVariable($value, $var);
    }

    // A query-builder method that never widens the query: where* (not orWhere*), a modifier, or a read.
    private static function isBuilderMethod(string $name): bool
    {
        if (str_starts_with($name, 'orwhere') || in_array($name, Verbs::SCOPE_RESETS, true)) {
            return false;
        }

        return str_starts_with($name, 'where') || self::materialises($name) || in_array($name, [...self::ELOQUENT_METHODS, ...self::BUILDER_MODIFIERS, ...Verbs::READS], true);
    }

    private static function materialises(string $name): bool
    {
        return str_starts_with($name, 'first') || str_starts_with($name, 'find') || in_array($name, self::MATERIALISING, true);
    }

    // The hop right after the auth user names a relation RelationResolver knows on the auth user model.
    private function isRelation(Expr $user, Expr $hop, PathNode $node): bool
    {
        $name = ($hop instanceof Expr\PropertyFetch || $hop instanceof Expr\NullsafePropertyFetch || AuthExpressions::isCall($hop)) && $hop->name instanceof Node\Identifier ? $hop->name->toString() : null;
        $model = $name === null ? null : $this->types->typeOf($user, $node);

        return $model !== null && $this->relations->relatedClass($model, (string) $name) !== null;
    }

    // ---- missing_authorization ----------------------------------------------------------------------------------

    /**
     * @param  list<string>  $verbs
     * @param  list<array{PathNode, Expr\CallLike}>  $writes
     * @param  list<AuthCheck>  $checks
     * @param  array<string, string>  $reasons
     */
    private function missingAuthorization(string $key, ExecutionPath $path, array $verbs, array $writes, ?string $destroy, array $checks, bool $deep, array &$reasons): void
    {
        $change = match (true) {
            $verbs !== [] => implode('/', $verbs).' route',
            $writes !== [] => 'writes via '.$this->print($writes[0][1]),
            default => 'destroy-style action '.$destroy.'()',
        };
        // A query scope only limits what is read; it does not authorize a write.
        $authorizing = array_values(array_filter($checks, static fn (AuthCheck $c): bool => $c->kind !== AuthCheckKind::QueryScope));
        if ($authorizing !== [] && $deep) {
            $reasons[Category::MissingAuthorization->value] = '--deep: '.$change.' changes state; an authorization check is on the path: '.$this->checkText($authorizing[0]);

            return;
        }
        if ($authorizing !== []) {
            $this->exclude($key, Category::MissingAuthorization, 'an authorization check is on the path', $this->checkText($authorizing[0]));

            return;
        }
        $all = $writes;
        $hidden = $all === [] ? null : $this->unresolvedCall($path);
        $scoped = $all !== [] && $hidden === null;
        $texts = [];
        $chosen = null;
        foreach ($all as [$node, $call]) {
            $where = sprintf('%s (%s:%d)', $this->print($call), $node->file, $call->getStartLine());
            // A pivot or relation write fed a non-constant value picks the rows itself: never self-scoped.
            if ($chosen === null && $this->isChosenLink($call)) {
                $chosen = $where;
            }
            $scoped = $scoped && $chosen === null && AuthExpressions::isCall($call) && $this->authRooted($call->var, $this->bodies[$node->id], $node);
            $texts[] = $where;
        }
        $selfScoped = 'every model write is reached through the authenticated user or a user-scoped query';
        if ($scoped && $deep) {
            $reasons[Category::MissingAuthorization->value] = '--deep: '.$change.' changes state; '.$selfScoped.': '.implode('; ', array_unique($texts));

            return;
        }
        if ($scoped) {
            $this->exclude($key, Category::MissingAuthorization, $selfScoped, implode('; ', array_unique($texts)));

            return;
        }
        $reasons[Category::MissingAuthorization->value] = ($deep ? '--deep: ' : '').$change.' with no authorization check'
            .($chosen === null ? '' : '; relation write from a non-constant value '.$chosen).($hidden === null ? '' : '; unresolved call '.$hidden);
    }

    /**
     * Writes anywhere on the path: a write verb on a model, a query or relation, or a receiver of unknown type, and every
     * DB facade write (DB::delete(..), DB::table(..)->truncate()).
     *
     * @return list<array{PathNode, Expr\CallLike}>
     */
    private function writes(ExecutionPath $path): array
    {
        $out = [];
        foreach ($path->nodes as $node) {
            foreach ($this->bodies[$node->id]->calls as $call) {
                if (! $call instanceof Expr\StaticCall && ! AuthExpressions::isCall($call)) {
                    continue;
                }
                if ($this->isDbWrite($call) || (Verbs::isWrite(self::callName($call)) && $this->isModelWrite($node, $call))) {
                    $out[] = [$node, $call];
                }
            }
        }

        return $out;
    }

    // DB::insert/update/delete/statement/unprepared(..), or a write verb on a chain rooted at the DB facade.
    private function isDbWrite(Expr\StaticCall|Expr\MethodCall|Expr\NullsafeMethodCall $call): bool
    {
        if ($call instanceof Expr\StaticCall) {
            return self::isDbFacade($call->class) && in_array(self::callName($call), Verbs::DB_WRITES, true);
        }
        if (! Verbs::isWrite(self::callName($call))) {
            return false;
        }
        $root = $call->var;
        while (AuthExpressions::isCall($root)) {
            $root = $root->var;
        }

        return $root instanceof Expr\StaticCall && self::isDbFacade($root->class);
    }

    private static function isDbFacade(Node $class): bool
    {
        return $class instanceof Node\Name && in_array(ltrim($class->toString(), '\\'), self::DB_FACADES, true);
    }

    // A pivot or relation write (sync, attach, ...) with any argument that is not a constant.
    private function isChosenLink(Expr\CallLike $call): bool
    {
        if (! in_array(self::callName($call), Verbs::RELATION_WRITES, true) || $call->isFirstClassCallable()) {
            return false;
        }
        foreach ($call->getRawArgs() as $arg) {
            if (! $arg instanceof Node\Arg || ! self::isConstantValue($arg->value)) {
                return true;
            }
        }

        return false;
    }

    // A literal, a constant, or an array / concatenation of them.
    private static function isConstantValue(Expr $expr): bool
    {
        if ($expr instanceof Expr\Array_) {
            foreach ($expr->items as $item) {
                if ($item->unpack || ! self::isConstantValue($item->value) || ($item->key !== null && ! self::isConstantValue($item->key))) {
                    return false;
                }
            }

            return true;
        }
        if ($expr instanceof Expr\UnaryMinus || $expr instanceof Expr\UnaryPlus) {
            return self::isConstantValue($expr->expr);
        }

        return self::isConstant($expr);
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

    /**
     * A write receiver that is the auth user, one direct relation hop of it, or a where-scoped query, directly or through
     * a variable every assignment of which is one.
     */
    private function authRooted(Expr $expr, FunctionBody $body, PathNode $node, int $depth = 0): bool
    {
        if ($this->chainScoped($expr, $body, $node, false)) {
            return true;
        }
        $hops = [];
        $root = $expr;
        while (! $body->auth->isAuthUser($root) && (AuthExpressions::isCall($root) || $root instanceof Expr\PropertyFetch || $root instanceof Expr\NullsafePropertyFetch)) {
            $hops[] = $root;
            $root = $root->var;
        }
        if ($body->auth->isAuthUser($root)) {
            return $this->oneRelationHop(array_reverse($hops), $root, $node);
        }
        if ($hops !== [] || ! $root instanceof Expr\Variable || $depth > 3) {
            return false;
        }
        $values = $body->auth->assignedValues($root);
        if ($values === null || $values === [] || ! is_string($root->name) || $this->builderEscapes($root->name, $body, false, static fn (Expr $v): bool => true)) {
            return false;
        }
        foreach ($values as $value) {
            if (! $this->authRooted($value, $body, $node, $depth + 1)) {
                return false;
            }
        }

        return true;
    }

    /**
     * The user itself, `->relation` (a to-one model), or `->relation()` followed only by query calls, ending at most
     * at one materialising call: one direct relation hop and nothing beyond it.
     *
     * @param  list<Expr>  $hops  innermost first
     */
    private function oneRelationHop(array $hops, Expr $user, PathNode $node): bool
    {
        if ($hops === []) {
            return true;
        }
        $first = array_shift($hops);
        if (! $this->isRelation($user, $first, $node)) {
            return false;
        }
        if (! AuthExpressions::isCall($first)) {
            return $hops === [];
        }
        foreach ($hops as $i => $hop) {
            $name = AuthExpressions::isCall($hop) ? (AuthExpressions::name($hop) ?? '') : null;
            if ($name === null || in_array($name, Verbs::SCOPE_RESETS, true) || $this->isRelationName($first, $name, $node)) {
                return false;
            }
            if (self::materialises($name) && $i !== count($hops) - 1) {
                return false;
            }
        }

        return true;
    }

    // Whether $name is a relation of the model a relation call reads.
    private function isRelationName(Expr $relationCall, string $name, PathNode $node): bool
    {
        $model = $this->types->queryModel($relationCall, $node);

        return $model !== null && $this->relations->relatedClass($model, $name) !== null;
    }

    /** The first call on the path that is not followed and not on a request, response, safe-facade or user-scoped receiver. */
    private function unresolvedCall(ExecutionPath $path): ?string
    {
        foreach ($path->nodes as $node) {
            $body = $this->bodies[$node->id];
            foreach ($body->calls as $call) {
                if (isset($this->callees[spl_object_id($call)]) || ! $this->isUnresolved($call, $body, $node)) {
                    continue;
                }

                return sprintf('%s (%s:%d)', $this->print($call), $node->file, $call->getStartLine());
            }
        }

        return null;
    }

    private function isUnresolved(Expr\MethodCall|Expr\NullsafeMethodCall|Expr\StaticCall|Expr\FuncCall|Expr\New_ $call, FunctionBody $body, PathNode $node): bool
    {
        if ($call instanceof Expr\New_) {
            return true;
        }
        if ($call instanceof Expr\FuncCall) {
            return ! $call->name instanceof Node\Name || ! $this->knownFunction(strtolower(ltrim($call->name->toString(), '\\')), $call);
        }
        if (! $call->name instanceof Node\Identifier) {
            return true;
        }
        if ($call instanceof Expr\StaticCall) {
            if (! $call->class instanceof Node\Name) {
                return true;
            }

            if (self::isSafeFacade(ltrim($call->class->toString(), '\\'))) {
                return false;
            }

            // On a model class, only Eloquent reads and writes (writes are then held to the auth-rooted rule).
            return $this->types->staticModel($call, $node) === null || ! (self::isModelRead($call->name->toLowerString()) || $this->isModelWrite($node, $call) && self::isWriteName($call->name->toLowerString()));
        }
        if ($this->harmlessReceiver($call->var, $body)) {
            return false;
        }

        // Default deny: any other method on any receiver must be an Eloquent read, a model write or a relation.
        return ! $this->knownModelMethod($call, $body, $node);
    }

    // A chain rooted at the request, response()/request()/auth() and similar helpers, or a safe facade.
    private function harmlessReceiver(Expr $expr, FunctionBody $body): bool
    {
        while (AuthExpressions::isCall($expr) || $expr instanceof Expr\PropertyFetch || $expr instanceof Expr\NullsafePropertyFetch || $expr instanceof Expr\ArrayDimFetch) {
            // The user reached through the request is no request read.
            if ($body->auth->isAuthUser($expr)) {
                return false;
            }
            if ($this->isRequestReceiver($expr, $body)) {
                return true;
            }
            $expr = $expr->var;
        }
        if ($body->auth->isAuthUser($expr)) {
            return false;
        }
        if ($expr instanceof Expr\FuncCall) {
            return $expr->name instanceof Node\Name && in_array(strtolower(ltrim($expr->name->toString(), '\\')), self::KNOWN_FUNCTIONS, true);
        }
        if ($expr instanceof Expr\StaticCall) {
            return $expr->class instanceof Node\Name && self::isSafeFacade(ltrim($expr->class->toString(), '\\'));
        }

        return $this->isRequestReceiver($expr, $body);
    }

    private static function isModelRead(string $name): bool
    {
        return in_array($name, [...self::ELOQUENT_METHODS, ...self::USER_METHODS, ...self::STATIC_READS], true)
            || str_starts_with($name, 'where') || str_starts_with($name, 'orwhere') || str_starts_with($name, 'first') || str_starts_with($name, 'find');
    }

    private static function isWriteName(string $name): bool
    {
        return Verbs::isWrite($name);
    }

    // An Eloquent read on a receiver not proven to be an app class, a model write, or a relation of the model there.
    private function knownModelMethod(Expr\MethodCall|Expr\NullsafeMethodCall $call, FunctionBody $body, PathNode $node): bool
    {
        $name = $call->name instanceof Node\Identifier ? $call->name->toLowerString() : '';
        if (self::isWriteName($name)) {
            return $this->isModelWrite($node, $call);
        }
        $type = $this->types->typeOf($call->var, $node);
        if (self::isModelRead($name)) {
            return $type === null || $this->types->isModel($type) || str_starts_with($type, 'Illuminate\\');
        }
        if (in_array($name, self::RELATION_DEFINITIONS, true) && ($type === null || $this->types->isModel($type) || str_starts_with($type, self::RELATIONS_NS))) {
            return true;
        }
        if ($body->auth->isAuthUser($call->var)) {
            return $this->isRelation($call->var, $call, $node);
        }
        $model = $this->types->queryModel($call->var, $node) ?? $type;

        return $model !== null && $this->relations->relatedClass($model, $name) !== null;
    }

    private function knownFunction(string $name, ?Expr\FuncCall $call = null): bool
    {
        if (in_array($name, self::KNOWN_FUNCTIONS, true)) {
            return true;
        }
        if (in_array($name, self::CALLABLE_FUNCTIONS, true) || ! function_exists($name) || ! (new \ReflectionFunction($name))->isInternal()) {
            return false;
        }
        if ($call !== null && $call->isFirstClassCallable()) {
            return false;
        }
        $params = (new \ReflectionFunction($name))->getParameters();
        // compact() strings are variable names, never called.
        foreach ($call === null || $name === 'compact' ? [] : $call->getRawArgs() as $index => $arg) {
            if (! $arg instanceof Node\Arg || $arg->unpack || self::callableShaped($arg->value)) {
                return false;
            }
            $named = $arg->name?->toString();
            $param = $named === null ? ($params[$index] ?? null) : null;
            foreach ($named === null ? [] : $params as $candidate) {
                $param = $candidate->getName() === $named ? $candidate : $param;
            }
            // Whatever reaches a callable parameter may name an app function, unless it is a literal null.
            if ($param !== null && self::callableParam($param) && ! ($arg->value instanceof Expr\ConstFetch && $arg->value->name->toLowerString() === 'null')) {
                return false;
            }
        }

        return true;
    }

    private static function callableParam(\ReflectionParameter $param): bool
    {
        return str_contains(strtolower((string) $param->getType()), 'callable') || str_contains(strtolower($param->getName()), 'callback') || str_contains(strtolower($param->getName()), 'handler');
    }

    // A closure, arrow function, first-class callable, [obj, 'm'] array, or an identifier-shaped or `::`/`@` string.
    private static function callableShaped(Expr $value): bool
    {
        if ($value instanceof Expr\Closure || $value instanceof Expr\ArrowFunction || ($value instanceof Expr\CallLike && $value->isFirstClassCallable())) {
            return true;
        }
        if ($value instanceof Node\Scalar\String_) {
            $text = ltrim($value->value, '\\');

            // Any identifier may name an app function: function_exists() only sees this process.
            return str_contains($text, '::') || str_contains($text, '@') || preg_match('/^[A-Za-z_][A-Za-z0-9_\\\\]*$/', $text) === 1;
        }

        return $value instanceof Expr\Array_ && count($value->items) === 2 && ($value->items[1]->value ?? null) instanceof Node\Scalar\String_;
    }

    private static function isSafeFacade(string $class): bool
    {
        $short = self::short($class);

        return in_array($short, self::SAFE_FACADES, true) && ($class === $short || $class === self::FACADES_NS.$short);
    }

    private static function isFacade(string $class): bool
    {
        return str_starts_with($class, self::FACADES_NS) || in_array($class, self::FACADES, true);
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
                foreach ($call->isFirstClassCallable() ? [] : $call->getArgs() as $arg) {
                    $mass = $mass || $this->isMassInput($arg->value, $body, $this->massVars[$node->id] ?? []);
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
            return [$this->symbols->getClass($class) === null && ! self::isFacade($class) && ! in_array(strtolower($class), ['self', 'static', 'parent'], true), null];
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

    /**
     * Mass input appears anywhere inside the expression, except under only()/validated()/safe().
     *
     * @param  array<string, true>  $massVars  callee parameters that receive mass input
     */
    private function isMassInput(Node $expr, FunctionBody $body, array $massVars, int $depth = 0): bool
    {
        if ($depth > 6 || $expr instanceof Expr\Closure || $expr instanceof Expr\ArrowFunction) {
            return false;
        }
        if ($expr instanceof Expr && in_array(AuthExpressions::name($expr), self::NOT_MASS, true) && ! $expr instanceof Expr\FuncCall) {
            return false;
        }
        if ($expr instanceof Expr && $this->isMassRead($expr, $body)) {
            return true;
        }
        if ($expr instanceof Expr\Variable && is_string($expr->name)) {
            return isset($massVars[$expr->name]) || $this->isMassVariable($expr->name, $body, $massVars, $depth + 1);
        }
        foreach ($expr->getSubNodeNames() as $sub) {
            $child = $expr->$sub;
            foreach (is_array($child) ? $child : [$child] as $c) {
                if ($c instanceof Node && $this->isMassInput($c, $body, $massVars, $depth + 1)) {
                    return true;
                }
            }
        }

        return false;
    }

    /** @param array<string, true> $massVars */
    private function isMassVariable(string $name, FunctionBody $body, array $massVars, int $depth): bool
    {
        // Any assignment, compound or not, that contains a mass read makes the variable mass input.
        foreach ($body->assignmentsTo($name) as $assign) {
            if ($this->isMassInput($assign->expr, $body, $massVars, $depth)) {
                return true;
            }
        }

        return false;
    }

    // all()/input()/post()/collect()/query() with no keys, except(), toArray(), getContent(), json()->all() on the request, request() or the Request facade.
    private function isMassRead(Expr $expr, FunctionBody $body): bool
    {
        $name = AuthExpressions::name($expr);
        $noArgs = $expr instanceof Expr\CallLike && ! $expr->isFirstClassCallable() && $expr->getRawArgs() === [];
        $reads = in_array($name, ['except', 'toarray', 'getcontent'], true) || ($noArgs && in_array($name, self::MASS_READS, true));
        if (! $reads) {
            return false;
        }
        if ($expr instanceof Expr\StaticCall) {
            return self::isRequestFacade($expr->class);
        }
        if (! AuthExpressions::isCall($expr)) {
            return false;
        }
        $receiver = $expr->var;
        if ($name === 'all' && AuthExpressions::isCall($receiver) && AuthExpressions::name($receiver) === 'json') {
            $receiver = $receiver->var;
        }

        return $this->isRequestReceiver($receiver, $body);
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
                if (! $call instanceof Expr\FuncCall || $call->isFirstClassCallable()) {
                    continue;
                }
                $args = $call->getArgs();
                $where = sprintf('%s (%s:%d)', $this->print($call), $node->file, $call->getStartLine());
                if (AuthExpressions::name($call) !== 'unserialize') {
                    // array_map('unserialize', ...) and other string callables.
                    foreach ($args as $arg) {
                        if ($arg->value instanceof Node\Scalar\String_ && strtolower(ltrim($arg->value->value, '\\')) === 'unserialize') {
                            $hits[] = $where.' passes unserialize as a callable';
                        }
                    }

                    continue;
                }
                if ($args !== [] && self::isConstant($args[0]->value)) {
                    continue;
                }
                $limited = isset($args[1]) && self::disallowsClasses($args[1]->value);
                $hits[] = $where.($limited ? '; allowed_classes => false limits object injection but is still reviewed' : '');
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
            $this->exclude($key, Category::WorkflowBypass, 'every status write follows a guard on the same field of the same receiver', implode('; ', array_unique($guards)));
        }
    }

    /** @return list<array{Node, ?string, string, string}> write or call, status field (null: any status field), receiver text, description */
    private function workflowTriggers(FunctionBody $body): array
    {
        $out = [];
        foreach ($body->calls as $call) {
            $name = self::callName($call);
            if (! AuthExpressions::isCall($call) && ! $call instanceof Expr\StaticCall) {
                continue;
            }
            $receiver = $call instanceof Expr\StaticCall ? ($call->class instanceof Node\Name ? $call->class->toString() : '?') : $this->print($call->var);
            if (in_array($name, self::STATUS_WRITES, true)) {
                foreach (AuthExpressions::args($call) as $arg) {
                    foreach ($arg instanceof Expr\Array_ ? $arg->items : [] as $item) {
                        if ($item->key instanceof Node\Scalar\String_ && self::isStatusField($item->key->value)) {
                            $out[] = [$call, $item->key->value, $receiver, $this->print($call)];
                        }
                    }
                }
            }
            if (in_array($name, self::WORKFLOW_CALLS, true) || str_starts_with($name, 'transition')) {
                $out[] = [$call, null, $receiver, $this->print($call)];
            }
        }
        foreach ((new NodeFinder())->findInstanceOf($body->stmts, Expr\Assign::class) as $assign) {
            $var = $assign->var;
            if (($var instanceof Expr\PropertyFetch || $var instanceof Expr\NullsafePropertyFetch) && $var->name instanceof Node\Identifier && self::isStatusField($var->name->toString())) {
                $out[] = [$assign, $var->name->toString(), $this->print($var->var), $this->print($assign)];
            }
        }

        return $out;
    }

    // An unconditional abort_*/throw_* or blocking `if` before the write that compares the same field of the same receiver.
    private function statusGuard(FunctionBody $body, Node $at, ?string $field, string $receiver): ?Node
    {
        $finder = new NodeFinder();
        $candidates = $finder->find($body->stmts, static fn (Node $n): bool => ($n instanceof Expr\FuncCall && in_array(AuthExpressions::name($n), self::GUARDS, true)) || $n instanceof Stmt\If_);
        foreach ($candidates as $guard) {
            if ($guard->getEndFilePos() >= $at->getStartFilePos() || ! $body->positions->isUnconditional($guard) || $this->reassigned($body, $receiver, $guard, $at)) {
                continue;
            }
            if ($guard instanceof Stmt\If_) {
                // if (cond) { block } refuses when cond holds, like abort_if.
                $qualifies = self::blocks($guard->stmts) && $this->guardQualifies($guard->cond, false, $field, $receiver);
            } else {
                $condition = AuthExpressions::args($guard)[0] ?? null;
                $qualifies = $condition !== null && $this->guardQualifies($condition, str_ends_with((string) AuthExpressions::name($guard), '_unless'), $field, $receiver);
            }
            if ($qualifies) {
                return $guard;
            }
        }

        return null;
    }

    /**
     * The any/every rule: unless(A && B) and if(A || B) need any operand to compare the field, unless(A || B) and
     * if(A && B) every operand; `!` flips.
     */
    private function guardQualifies(Expr $condition, bool $unless, ?string $field, string $receiver): bool
    {
        if ($condition instanceof Expr\BooleanNot) {
            return $this->guardQualifies($condition->expr, ! $unless, $field, $receiver);
        }
        $and = $condition instanceof Expr\BinaryOp\BooleanAnd || $condition instanceof Expr\BinaryOp\LogicalAnd;
        $or = $condition instanceof Expr\BinaryOp\BooleanOr || $condition instanceof Expr\BinaryOp\LogicalOr;
        if ($condition instanceof Expr\BinaryOp && ($and || $or)) {
            $left = $this->guardQualifies($condition->left, $unless, $field, $receiver);
            $right = $this->guardQualifies($condition->right, $unless, $field, $receiver);

            return $and === $unless ? ($left || $right) : ($left && $right);
        }

        return $this->comparesField($condition, $field, $receiver);
    }

    // The receiver's variable (or the receiver itself) is written between the guard and the write, or in a loop around the write.
    private function reassigned(FunctionBody $body, string $receiver, Node $guard, Node $at): bool
    {
        $loops = (new NodeFinder())->find($body->stmts, static fn (Node $n): bool => ($n instanceof Stmt\For_ || $n instanceof Stmt\Foreach_ || $n instanceof Stmt\While_ || $n instanceof Stmt\Do_)
            && $n->getStartFilePos() <= $at->getStartFilePos() && $at->getEndFilePos() <= $n->getEndFilePos());
        $root = preg_match('/^\$[A-Za-z_][A-Za-z0-9_]*/', $receiver, $m) === 1 ? $m[0] : null;
        foreach ((new NodeFinder())->find($body->stmts, static fn (Node $n): bool => $n instanceof Expr\Assign || $n instanceof Expr\AssignOp || $n instanceof Expr\AssignRef || $n instanceof Stmt\Foreach_) as $write) {
            \assert($write instanceof Expr\Assign || $write instanceof Expr\AssignOp || $write instanceof Expr\AssignRef || $write instanceof Stmt\Foreach_);
            $targets = $write instanceof Stmt\Foreach_ ? array_filter([$write->valueVar, $write->keyVar]) : [$write->var];
            $hit = false;
            foreach ($targets as $target) {
                $text = $this->print($target);
                $hit = $hit || $text === $receiver || ($root !== null && ($text === $root || str_contains($text, $root.'[') || ($target instanceof Expr\List_ || $target instanceof Expr\Array_) && str_contains($text, $root)));
            }
            if (! $hit) {
                continue;
            }
            $pos = $write->getStartFilePos();
            if ($pos > $guard->getStartFilePos() && $pos < $at->getStartFilePos()) {
                return true;
            }
            foreach ($loops as $loop) {
                if ($loop->getStartFilePos() <= $pos && $pos <= $loop->getEndFilePos()) {
                    return true;
                }
            }
        }

        return false;
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

    // One comparison (===, ==, !==, !=, in_array) of the same field on the same receiver.
    private function comparesField(Expr $condition, ?string $field, string $receiver): bool
    {
        $isComparison = $condition instanceof Expr\BinaryOp\Identical || $condition instanceof Expr\BinaryOp\NotIdentical
            || $condition instanceof Expr\BinaryOp\Equal || $condition instanceof Expr\BinaryOp\NotEqual;
        if (! $isComparison && ! AuthExpressions::isFunc($condition, 'in_array')) {
            return false;
        }
        $operands = $condition instanceof Expr\BinaryOp ? [$condition->left, $condition->right] : array_slice(AuthExpressions::args($condition), 0, 1);
        foreach ($operands as $operand) {
            if (! ($operand instanceof Expr\PropertyFetch || $operand instanceof Expr\NullsafePropertyFetch) || ! $operand->name instanceof Node\Identifier) {
                continue;
            }
            $name = $operand->name->toString();
            if (($field !== null ? $name === $field : self::isStatusField($name)) && $this->print($operand->var) === $receiver) {
                return true;
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
        if ($category !== null) {
            $this->decided[$category->value] = true;
        }
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
