<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Framework\Laravel;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\NodeFinder;
use PhpParser\PrettyPrinter\Standard;
use TusharKhan\SemanticSec\Parsing\Symbols\ClassSymbol;
use TusharKhan\SemanticSec\Parsing\Symbols\MethodSymbol;
use TusharKhan\SemanticSec\Parsing\Symbols\RelationResolver;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;

/** Finds the depth-0 authorization checks that protect a route (SPEC §6). */
final class AuthCheckExtractor
{
    private const SCALARS = ['int', 'string', 'array', 'bool', 'float', 'mixed', 'callable', 'iterable', 'object', 'void', 'null', 'false', 'true', 'never', 'self', 'static', 'parent'];

    private const RESOURCE_ABILITIES = ['index' => 'viewAny', 'show' => 'view', 'create' => 'create', 'store' => 'create', 'edit' => 'update', 'update' => 'update', 'destroy' => 'delete'];

    private const GATE_FACADES = ['Illuminate\\Support\\Facades\\Gate', 'Gate'];

    private const GATE_METHODS = ['authorize', 'allows', 'denies', 'check', 'any', 'none', 'inspect'];

    // Ability calls that throw on denial; the others only return a result.
    private const THROWING = ['authorize', 'authorizeforuser'];

    private const GUARDS = ['abort_if', 'abort_unless', 'throw_if', 'throw_unless'];

    // Non-throwing ability calls whose true result means "denied".
    private const DENYING = ['denies', 'none', 'cannot', 'cant'];

    private const MAX_SOURCE = 120;

    private readonly ConstantEvaluator $eval;

    private readonly Standard $printer;

    /** @var array<string, true> lower-cased bare names */
    private array $helperNames = [];

    /** @var array<string, true> lower-cased Class::method */
    private array $helperSymbols = [];

    /** @param list<string> $authHelpers */
    public function __construct(
        private readonly SymbolTable $symbols,
        private readonly MiddlewareRegistry $middleware,
        private readonly PolicyRegistry $policies,
        private readonly ControllerMiddlewareReader $controllerMiddleware,
        array $authHelpers,
        private readonly ?RelationResolver $relations = null,
        private readonly ?string $authUserModel = null,
    ) {
        $this->eval = new ConstantEvaluator();
        $this->printer = new Standard();
        foreach ($authHelpers as $helper) {
            $helper = strtolower(ltrim($helper, '\\'));
            if (str_contains($helper, '::')) {
                $this->helperSymbols[$helper] = true;
            } else {
                $this->helperNames[$helper] = true;
            }
        }
    }

    /** @return array{0: RouteEntry, 1: list<string>} */
    public function extract(RouteEntry $route): array
    {
        $warnings = [];
        $action = $route->action;
        $class = null;
        $method = null;
        $closure = null;
        if ($action->closure instanceof Expr\Closure || $action->closure instanceof Expr\ArrowFunction) {
            $closure = $action->closure;
        } elseif ($action->class !== null && $action->method !== null) {
            $class = $this->symbols->getClass($action->class);
            $method = $class === null ? null : $this->symbols->findMethod($class->name, $action->method);
            if ($method === null) {
                $warnings[] = sprintf('%s:%d: action %s not found', $route->file, $route->line, $action->symbol());
            }
        }

        if ($method === null && $closure === null) {
            $covered = [];

            return [$route->withChecks($this->middlewareChecks($route, $warnings, $covered)), $warnings];
        }

        // Laravel binds and resolves by native types only, never docblocks.
        $paramNodes = $closure !== null ? $closure->params : $method->node->params;
        $paramTypes = self::nativeTypes($paramNodes);
        $file = $method !== null ? $method->file : $route->file;
        [$parameters, $variables] = $this->bindModels($route->parameters, $paramTypes);
        $route = $route->withParameters($parameters);

        // Route parameters whose bound model an authorization-strength check covers.
        $covered = [];
        $middleware = $this->middlewareChecks($route, $warnings, $covered);
        $resource = $class !== null ? $this->resourceChecks($route, $class, $method, $warnings, $covered) : [];
        $formRequest = $this->formRequestChecks($route, $paramNodes, $paramTypes, $file);
        $body = $closure !== null
            ? ($closure instanceof Expr\Closure ? $closure->stmts : [$closure->expr])
            : ($method->node->stmts ?? []);
        $context = new AuthExpressions($this->symbols, $paramTypes, $body);
        [$bodyChecks, $coveredVariables] = $this->bodyChecks($body, $context, new BodyPositions($body), $file, $class, array_flip($variables));
        foreach ($variables as $parameter => $variable) {
            if (isset($coveredVariables[$variable])) {
                $covered[$parameter] = true;
            }
        }

        $checks = [...$middleware, ...$this->scopeChecks($route, $covered), ...$resource, ...$formRequest, ...$bodyChecks];

        return [$route->withChecks($checks), $warnings];
    }

    /**
     * @param  list<string>  $warnings
     * @param  array<string, true>  $covered
     * @return list<AuthCheck>
     */
    private function middlewareChecks(RouteEntry $route, array &$warnings, array &$covered): array
    {
        $declared = $route->middleware;
        if ($route->action->class !== null && $route->action->method !== null) {
            [$fromController, $w] = $this->controllerMiddleware->forAction($route->action->class, $route->action->method);
            array_push($warnings, ...$w);
            array_push($declared, ...$fromController);
        }
        // Laravel excludes by exact resolved name; an unresolved exclusion may remove anything.
        $unresolved = in_array(RouteEntry::UNRESOLVED, $route->withoutMiddleware, true);
        $excluded = $this->middleware->expand(array_values(array_diff($route->withoutMiddleware, [RouteEntry::UNRESOLVED])));
        $checks = [];
        foreach ($this->middleware->expand($declared) as $m) {
            if (in_array($m, $excluded, true)) {
                continue;
            }
            $kind = $this->middleware->kind($m);
            if ($kind === MiddlewareKind::Authentication) {
                $check = [AuthCheckKind::Authentication, AuthStrength::Authentication, 'middleware '.$m];
            } elseif ($kind === MiddlewareKind::Ability) {
                $ability = $this->middleware->ability($m);
                $parameter = $this->routeParameter($route, $ability['arguments'][0] ?? null);
                $model = $parameter !== null ? $parameter->boundModel : self::classArgument($ability['arguments'][0] ?? null);
                $reason = $ability === null ? null : $this->trivialReason($model, [$ability['ability']], false);
                if ($reason === null && $parameter !== null && ! $unresolved) {
                    $covered[$parameter->name] = true;
                }
                $check = [AuthCheckKind::RouteAbility, $reason === null ? AuthStrength::Authorization : AuthStrength::None, 'middleware '.$m.($reason === null ? '' : ': '.$reason), $parameter?->name];
            } else {
                continue;
            }
            if ($unresolved) {
                $check = [$check[0], AuthStrength::None, $check[2].' (may be removed by unresolved withoutMiddleware)', $check[3] ?? null];
            }
            $checks[] = new AuthCheck($check[0], $check[1], $check[2], $route->file, $route->line, $check[1] === AuthStrength::Authorization ? ($check[3] ?? null) : null);
        }

        return $checks;
    }

    // Authorize::getModel reads $request->route($argument): exact name only.
    private function routeParameter(RouteEntry $route, ?string $argument): ?RouteParameter
    {
        if ($argument === null) {
            return null;
        }
        foreach ($route->parameters as $p) {
            if ($p->name === $argument) {
                return $p;
            }
        }

        return null;
    }

    private static function classArgument(?string $argument): ?string
    {
        return $argument !== null && str_contains($argument, '\\') ? ltrim($argument, '\\') : null;
    }

    // Mirrors Laravel 12 Str::snake.
    private static function snake(string $value): string
    {
        if (ctype_lower($value)) {
            return $value;
        }
        $value = (string) preg_replace('/\s+/u', '', ucwords($value));

        return mb_strtolower((string) preg_replace('/(.)(?=[A-Z])/u', '$1_', $value), 'UTF-8');
    }

    /**
     * Binds a route parameter to the action parameter of the same name or its snake_case form (ImplicitRouteBinding).
     *
     * @param  list<RouteParameter>  $parameters
     * @param  array<string, ?string>  $types
     * @return array{0: list<RouteParameter>, 1: array<string, string>} parameters, and route parameter => action variable
     */
    private function bindModels(array $parameters, array $types): array
    {
        $out = [];
        $variables = [];
        foreach ($parameters as $p) {
            $variable = null;
            foreach ($types as $name => $type) {
                $class = $type !== null && ! in_array(strtolower($type), self::SCALARS, true);
                // Laravel binds class-typed action parameters only, by exact or snake name.
                if ($class && ($name === $p->name || self::snake($name) === $p->name) && ($variable === null || $name === $p->name)) {
                    $variable = $name;
                }
            }
            if ($variable === null) {
                $out[] = $p;

                continue;
            }
            $variables[$p->name] = $variable;
            $out[] = new RouteParameter($p->name, $p->field, $p->optional, ltrim((string) $types[$variable], '\\'), $p->domain);
        }

        return [$out, $variables];
    }

    /**
     * A bound child scoped to its URL parent is only as strong as the check on that parent.
     *
     * @param  array<string, true>  $covered
     * @return list<AuthCheck>
     */
    private function scopeChecks(RouteEntry $route, array $covered): array
    {
        if ($route->scopeBindings === false) {
            return [];
        }
        $checks = [];
        foreach ($route->parameters as $i => $p) {
            $parent = $route->parameters[$i - 1] ?? null;
            if ($parent === null || $p->boundModel === null || $parent->boundModel === null || ($route->scopeBindings !== true && $p->field === null)) {
                continue;
            }
            if (! isset($covered[$parent->name])) {
                $checks[] = new AuthCheck(AuthCheckKind::QueryScope, AuthStrength::None, sprintf('scoped to URL parent {%s}', $parent->name), $route->file, $route->line);

                continue;
            }
            $source = $route->scopeBindings === true ? sprintf('scopeBindings {%s} in {%s}', $p->name, $parent->name) : sprintf('implicit scoped binding {%s:%s}', $p->name, $p->field);
            $checks[] = new AuthCheck(AuthCheckKind::QueryScope, AuthStrength::Authorization, $source, $route->file, $route->line, $p->name);
        }

        return $checks;
    }

    /**
     * @param  list<string>  $warnings
     * @param  array<string, true>  $covered
     * @return list<AuthCheck>
     */
    private function resourceChecks(RouteEntry $route, ClassSymbol $class, MethodSymbol $method, array &$warnings, array &$covered): array
    {
        $ability = self::RESOURCE_ABILITIES[strtolower($method->name)] ?? null;
        $checks = [];
        foreach ($this->constructorChain($class) as [$owner, $ctor]) {
            foreach ((new NodeFinder())->findInstanceOf($ctor->node->stmts ?? [], Expr\MethodCall::class) as $call) {
                if (! self::onThis($call) || AuthExpressions::name($call) !== 'authorizeresource') {
                    continue;
                }
                $where = sprintf('%s:%d: ', $ctor->file, $call->getStartLine());
                $args = AuthExpressions::args($call);
                if ($args === []) {
                    $warnings[] = $where.'authorizeResource arguments could not be resolved';

                    continue;
                }
                if ($this->symbols->findMethod($class->name, 'resourceAbilityMap') !== null || $this->symbols->findMethod($class->name, 'resourceMethodsWithoutModels') !== null) {
                    $warnings[] = $where.'authorizeResource with a custom ability map is not supported';

                    continue;
                }
                $allowed = isset($args[2]) ? $this->methodAllowedByOptions($args[2], $method->name, $ctor->file, $owner) : true;
                if ($allowed === null) {
                    $warnings[] = $where.'authorizeResource options could not be resolved';

                    continue;
                }
                if (! $allowed) {
                    continue;
                }
                if ($ability === null) {
                    continue;
                }
                $model = $this->eval->string($args[0], $ctor->file, $owner);
                if ($model === null) {
                    $warnings[] = $where.'authorizeResource model could not be resolved';
                }
                $reason = $model === null ? null : $this->trivialReason(ltrim($model, '\\'), [$ability], false);
                $parameter = isset($args[1]) ? $this->eval->string($args[1], $ctor->file, $owner) : ($model === null ? null : self::snake(self::short($model)));
                // index/create/store authorize the class, never the bound instance.
                $covers = $parameter !== null && ! in_array(strtolower($method->name), ['index', 'create', 'store'], true) ? $parameter : null;
                if ($reason === null && $covers !== null) {
                    $covered[$covers] = true;
                }
                $covers = $this->routeParameter($route, $covers)?->name;
                $source = sprintf('authorizeResource(%s) %s -> %s', $model === null ? '?' : self::short($model).'::class', $method->name, $ability);
                $checks[] = new AuthCheck(AuthCheckKind::ControllerAbility, $reason === null ? AuthStrength::Authorization : AuthStrength::None, $source.($reason === null ? '' : ': '.$reason), $ctor->file, $call->getStartLine(), $reason === null ? $covers : null);
            }
        }

        return $checks;
    }

    /** Whether only/except options let the method through; null when they cannot be resolved. */
    private function methodAllowedByOptions(Expr $options, string $method, string $file, ClassSymbol $owner): ?bool
    {
        if (! $options instanceof Expr\Array_) {
            return null;
        }
        $method = strtolower($method);
        $allowed = true;
        foreach ($options->items as $item) {
            $key = $item->key === null ? null : $this->eval->string($item->key, $file, $owner);
            if ($key === null) {
                return null;
            }
            if ($key !== 'only' && $key !== 'except') {
                continue;
            }
            $values = [];
            foreach ($item->value instanceof Expr\Array_ ? $item->value->items : [$item] as $inner) {
                $value = $inner->unpack ? null : $this->eval->string($inner->value, $file, $owner);
                if ($value === null) {
                    return null;
                }
                $values[] = strtolower($value);
            }
            if (($key === 'only') !== in_array($method, $values, true)) {
                $allowed = false;
            }
        }

        return $allowed;
    }

    /** @return list<array{ClassSymbol, MethodSymbol}> constructors that actually run, base first */
    private function constructorChain(ClassSymbol $class): array
    {
        $chain = [];
        $seen = [];
        for ($c = $class; $c !== null && ! isset($seen[$c->name]); $c = $c->parent === null ? null : $this->symbols->getClass($c->parent)) {
            $seen[$c->name] = true;
            $ctor = $c->methods['__construct'] ?? null;
            if ($ctor === null) {
                continue;
            }
            $chain[] = [$c, $ctor];
            $callsParent = (new NodeFinder())->findFirst($ctor->node->stmts ?? [], static fn (Node $n): bool => $n instanceof Expr\StaticCall
                && $n->class instanceof Node\Name && strtolower($n->class->toString()) === 'parent' && AuthExpressions::name($n) === '__construct') !== null;
            if (! $callsParent) {
                break;
            }
        }

        return array_reverse($chain);
    }

    /**
     * @param  array<Node\Param>  $params
     * @param  array<string, ?string>  $types
     * @return list<AuthCheck>
     */
    private function formRequestChecks(RouteEntry $route, array $params, array $types, string $file): array
    {
        $checks = [];
        foreach ($params as $param) {
            if (! $param->var instanceof Expr\Variable || ! is_string($param->var->name)) {
                continue;
            }
            $type = $types[$param->var->name] ?? null;
            if ($type === null || ! AuthExpressions::isFormRequest($this->symbols, $type)) {
                continue;
            }
            $authorize = $this->symbols->findMethod($type, 'authorize');
            $name = 'FormRequest '.self::short($type);
            [$strength, $reference] = $authorize === null || PolicyRegistry::allowsAll($authorize) ? [AuthStrength::None, null] : $this->authorizeStrength($authorize);
            $source = match (true) {
                $authorize === null => $name.' has no authorize()',
                PolicyRegistry::allowsAll($authorize) => $name.'::authorize returns true',
                $strength === AuthStrength::Authorization => $name.'::authorize',
                $strength === AuthStrength::Authentication => $name.'::authorize only checks login',
                default => $name.'::authorize has no authorization logic',
            };
            $covers = $strength === AuthStrength::Authorization ? $this->routeParameter($route, $reference)?->name : null;
            $checks[] = new AuthCheck(AuthCheckKind::FormRequest, $strength, $source, $file, $param->getStartLine(), $covers);
        }

        return $checks;
    }

    /**
     * Authorization for an enforced ability call, role call or auth comparison; Authentication for login-only checks.
     *
     * @return array{AuthStrength, ?string} strength, and the $this->route('<p>') parameter that evidence reads
     */
    private function authorizeStrength(MethodSymbol $authorize): array
    {
        $stmts = $authorize->node->stmts ?? [];
        $context = new AuthExpressions($this->symbols, self::nativeTypes($authorize->node->params), $stmts, true);
        $positions = new BodyPositions($stmts);
        $leaf = fn (Expr $e, bool $allow): bool => $this->decidingAbility($e, $context) || $context->isRoleCall($e) || $context->guardQualifies($e, $allow);
        $found = false;
        $reference = null;
        foreach ((new NodeFinder())->find($stmts, static fn (Node $n): bool => $n instanceof Expr) as $node) {
            \assert($node instanceof Expr);
            $ability = $this->abilityCall($node, $context);
            $comparison = $node instanceof Expr\BinaryOp && $context->isAuthComparison($node, null);
            if (($ability === null && ! $comparison && ! $context->isRoleCall($node)) || ! $positions->isUnconditional($node, $ability === null || ! $ability[3])) {
                continue;
            }
            // Gate::inspect returns an always-truthy Response; only `return Gate::inspect(..)` enforces it.
            $inspect = $ability !== null && AuthExpressions::name($node) === 'inspect';
            $polarities = match (true) {
                $ability !== null => [! in_array(AuthExpressions::name($node), self::DENYING, true)],
                $comparison => [$node instanceof Expr\BinaryOp\Identical || $node instanceof Expr\BinaryOp\Equal],
                default => [true, false],
            };
            $decides = false;
            foreach ($polarities as $trueAllows) {
                $decides = $decides || $positions->isConditionPosition($node, true, $leaf, $trueAllows, true);
            }
            if (($ability !== null && $ability[3]) || ($inspect ? $positions->parent($node) instanceof Node\Stmt\Return_ : $decides)) {
                $found = true;
                $operands = $ability !== null ? AuthExpressions::args($node) : ($node instanceof Expr\BinaryOp ? [$node->left, $node->right] : []);
                $reference ??= self::routeRead($operands, $context);
            }
        }
        if ($found) {
            return [AuthStrength::Authorization, $reference];
        }
        $login = false;
        foreach ($stmts as $stmt) {
            // A route() read kept in a variable decides nothing.
            if ($stmt instanceof Node\Stmt\Expression && $stmt->expr instanceof Expr\Assign && self::routeName($stmt->expr->expr) !== null) {
                continue;
            }
            $only = $stmt instanceof Node\Stmt\Return_ && $stmt->expr !== null ? $context->loginOnly($stmt->expr) : null;
            if ($only === null) {
                return [AuthStrength::None, null];
            }
            $login = $login || $only;
        }

        return [$login ? AuthStrength::Authentication : AuthStrength::None, null];
    }

    /**
     * The parameter read by $this->route('<p>') inside the operands, directly or via a variable only ever assigned that read.
     *
     * @param  list<Expr>  $operands
     */
    private static function routeRead(array $operands, AuthExpressions $context): ?string
    {
        foreach ((new NodeFinder())->find($operands, static fn (Node $n): bool => $n instanceof Expr\MethodCall || $n instanceof Expr\Variable) as $node) {
            if ($node instanceof Expr\MethodCall && ($name = self::routeName($node)) !== null) {
                return $name;
            }
            if ($node instanceof Expr\Variable) {
                $names = array_unique(array_map(static fn (Expr $v): ?string => self::routeName($v), $context->assignedValues($node) ?? []));
                if (count($names) === 1 && $names[0] !== null) {
                    return $names[0];
                }
            }
        }

        return null;
    }

    private static function routeName(Expr $expr): ?string
    {
        $arg = $expr instanceof Expr\MethodCall ? (AuthExpressions::args($expr)[0] ?? null) : null;

        return $expr instanceof Expr\MethodCall && self::onThis($expr) && AuthExpressions::name($expr) === 'route' && $arg instanceof Node\Scalar\String_ ? $arg->value : null;
    }

    /**
     * @param  array<Node>  $body
     * @param  array<string, string>  $parameters  action variable => the route parameter bound to it
     * @return array{0: list<AuthCheck>, 1: array<string, true>} checks, and action variables an ability call covers
     */
    private function bodyChecks(array $body, AuthExpressions $context, BodyPositions $positions, string $file, ?ClassSymbol $class, array $parameters): array
    {
        $finder = new NodeFinder();
        $nodes = $finder->find($body, static fn (Node $n): bool => $n instanceof Expr\CallLike);
        // Maps each chain receiver to the call made on it.
        $inner = [];
        foreach ($nodes as $node) {
            if (AuthExpressions::isCall($node)) {
                $inner[spl_object_id($node->var)] = $node;
            }
        }
        $checks = [];
        $covered = [];
        $leaf = fn (Expr $e, bool $allow): bool => $this->decidingAbility($e, $context) || $context->guardQualifies($e, $allow);
        foreach ($nodes as $node) {
            \assert($node instanceof Expr);
            $ability = $this->abilityCall($node, $context);
            // A check that some path can skip protects nothing.
            if (! $positions->isUnconditional($node, $ability !== null && ! $ability[3])) {
                continue;
            }
            $add = static function (AuthCheckKind $kind, AuthStrength $strength, string $source, ?string $covers = null, ?string $model = null) use (&$checks, $file, $node): void {
                $checks[] = new AuthCheck($kind, $strength, $source, $file, $node->getStartLine(), $strength === AuthStrength::Authorization ? $covers : null, $model);
            };
            // A non-throwing check counts only where its result decides a blocking branch or a guard.
            if ($ability !== null && ($ability[3] || ($this->decidingAbility($node, $context) && $positions->isConditionPosition($node, false, $leaf, ! in_array(AuthExpressions::name($node), self::DENYING, true))))) {
                [$abilityArg, $modelArg, $any] = $ability;
                $reason = $this->abilityReason($abilityArg, $modelArg, $any, $context, $file, $class);
                $variable = $modelArg instanceof Expr\Array_ ? ($modelArg->items[0]->value ?? null) : $modelArg;
                $untouched = $variable instanceof Expr\Variable && is_string($variable->name) && $context->isUntouchedParam($variable->name, $variable->getStartFilePos());
                $add(AuthCheckKind::ControllerAbility, $reason === null ? AuthStrength::Authorization : AuthStrength::None, $this->describe($node).($reason === null ? '' : ': '.$reason), $untouched ? ($parameters[$variable->name] ?? null) : null);
                if ($reason === null && $untouched) {
                    $covered[$variable->name] = true;
                }
            }
            if ($node instanceof Expr\FuncCall && in_array(AuthExpressions::name($node), self::GUARDS, true)) {
                $condition = AuthExpressions::args($node)[0] ?? null;
                if ($condition !== null && $context->guardQualifies($condition, str_ends_with((string) AuthExpressions::name($node), '_unless'))) {
                    $add(AuthCheckKind::AbortGuard, AuthStrength::Authorization, $this->describe($node), self::guardSubject($condition, $context, $parameters));
                }
            }
            $where = $context->isWhereScope($node);
            if (((! isset($inner[spl_object_id($node)]) && $context->isRelationRead($node)) || $where) && ! self::chainHasOrWhere($node, $inner)) {
                $add(AuthCheckKind::QueryScope, AuthStrength::Authorization, $this->describe($node), null, $where ? self::scopedModel($node) : $this->relationModel($node, $context));
            }
            if ($this->isHelper($node, $class)) {
                $add(AuthCheckKind::CustomHelper, AuthStrength::Authorization, $this->describe($node));
            }
        }

        return [$checks, $covered];
    }

    /**
     * The route parameter a single-comparison guard reads as `$x->prop`, where `$x` is the untouched bound variable.
     *
     * @param  array<string, string>  $parameters
     */
    private static function guardSubject(Expr $condition, AuthExpressions $context, array $parameters): ?string
    {
        while ($condition instanceof Expr\BooleanNot) {
            $condition = $condition->expr;
        }
        if (! $condition instanceof Expr\BinaryOp || ! $context->isAuthComparison($condition, null)) {
            return null;
        }
        foreach ([$condition->left, $condition->right] as $side) {
            $var = $side instanceof Expr\PropertyFetch || $side instanceof Expr\NullsafePropertyFetch ? $side->var : null;
            if ($var instanceof Expr\Variable && is_string($var->name) && isset($parameters[$var->name]) && $context->isUntouchedParam($var->name, $var->getStartFilePos())) {
                return $parameters[$var->name];
            }
        }

        return null;
    }

    // X for X::where*(..) and X::query()->...->where(..); null for other roots.
    private static function scopedModel(Expr $node): ?string
    {
        while (AuthExpressions::isCall($node)) {
            $node = $node->var;
        }
        $root = $node instanceof Expr\StaticCall ? (AuthExpressions::name($node) ?? '') : '';

        return $node instanceof Expr\StaticCall && $node->class instanceof Node\Name && ($root === 'query' || str_starts_with($root, 'where')) ? self::modelName($node->class) : null;
    }

    // The related model of a relation read rooted at the auth user (`->team->projects()->find(..)`), hop by hop.
    private function relationModel(Expr $node, AuthExpressions $context): ?string
    {
        if ($this->relations === null || $this->authUserModel === null) {
            return null;
        }
        $hops = [];
        while (! $context->isAuthUser($node)) {
            $isFetch = $node instanceof Expr\PropertyFetch || $node instanceof Expr\NullsafePropertyFetch;
            if (! $isFetch && ! AuthExpressions::isCall($node)) {
                return null;
            }
            if (! $node->name instanceof Node\Identifier) {
                return null;
            }
            array_unshift($hops, [$isFetch, $node->name->toString()]);
            $node = $node->var;
        }
        $relations = [];
        foreach ($hops as [$isFetch, $name]) {
            $relations[] = $name;
            if (! $isFetch) {
                return $this->relations->followChain($this->authUserModel, $relations);
            }
        }

        return null;
    }

    /**
     * An orWhere anywhere in the chain widens the query past the scope.
     *
     * @param  array<int, Expr>  $inner
     */
    private static function chainHasOrWhere(Expr $node, array $inner): bool
    {
        while (isset($inner[spl_object_id($node)])) {
            $node = $inner[spl_object_id($node)];
        }
        for (; ; $node = $node->var) {
            if (str_starts_with(AuthExpressions::name($node) ?? '', 'orwhere')) {
                return true;
            }
            if (! AuthExpressions::isCall($node)) {
                return false;
            }
        }
    }

    // An ability call whose boolean result can decide a condition (Gate::inspect's Response is always truthy).
    private function decidingAbility(Expr $node, AuthExpressions $context): bool
    {
        return $this->abilityCall($node, $context) !== null && AuthExpressions::name($node) !== 'inspect';
    }

    /** @return array{0: ?Expr, 1: ?Expr, 2: bool, 3: bool}|null ability arg, model arg, any-semantics, throws on denial */
    private function abilityCall(Expr $node, AuthExpressions $context): ?array
    {
        $name = AuthExpressions::name($node);
        $args = AuthExpressions::args($node);
        $throws = in_array($name, self::THROWING, true);
        if ($node instanceof Expr\MethodCall && self::onThis($node) && $throws) {
            $offset = $name === 'authorize' ? 0 : 1;

            return [$args[$offset] ?? null, $args[$offset + 1] ?? null, false, true];
        }
        if ($node instanceof Expr\StaticCall && $node->class instanceof Node\Name && in_array(ltrim($node->class->toString(), '\\'), self::GATE_FACADES, true)
            && in_array($name, self::GATE_METHODS, true)) {
            return [$args[0] ?? null, $args[1] ?? null, $name === 'any', $name === 'authorize'];
        }
        // Only the authenticated user: an injected $user parameter is an empty model or caller-chosen.
        if (AuthExpressions::isCall($node) && in_array($name, ['can', 'cannot', 'cant'], true) && $context->isAuthUser($node->var)) {
            return [$args[0] ?? null, $args[1] ?? null, false, false];
        }

        return null;
    }

    /** Why the ability call is trivially allowed, or null when it may deny. */
    private function abilityReason(?Expr $abilityArg, ?Expr $modelArg, bool $any, AuthExpressions $context, string $file, ?ClassSymbol $class): ?string
    {
        if ($abilityArg === null || $modelArg === null) {
            return null;
        }
        $abilities = [];
        foreach ($abilityArg instanceof Expr\Array_ ? array_map(static fn (Node\ArrayItem $i): Expr => $i->value, $abilityArg->items) : [$abilityArg] as $expr) {
            $ability = $this->eval->string($expr, $file, $class);
            if ($ability === null) {
                return null;
            }
            $abilities[] = $ability;
        }

        return $this->trivialReason($this->modelOf($modelArg, $context, $modelArg->getStartFilePos()), $abilities, $any);
    }

    /** @param list<string> $abilities */
    private function trivialReason(?string $model, array $abilities, bool $any): ?string
    {
        $policy = $model === null ? null : $this->policies->policyFor($model);
        if ($policy === null || $abilities === []) {
            return null;
        }
        $before = $this->symbols->findMethod($policy, 'before');
        if ($before !== null && PolicyRegistry::allowsAll($before)) {
            return self::short($policy).'::before returns true';
        }
        $trivial = [];
        foreach ($abilities as $ability) {
            $ability = self::abilityMethod($ability);
            if ($this->policies->isTrivial($policy, $ability)) {
                $trivial[] = $ability;
            }
        }
        if ($trivial === [] || (! $any && count($trivial) !== count($abilities))) {
            return null;
        }

        return self::short($policy).'::'.$trivial[0].' returns true';
    }

    // Gate turns kebab-case abilities into camelCase policy methods.
    private static function abilityMethod(string $ability): string
    {
        return str_contains($ability, '-') ? lcfirst(str_replace(' ', '', ucwords(str_replace('-', ' ', $ability)))) : $ability;
    }

    /** The model class an ability argument refers to, or null when unknown. */
    private function modelOf(Expr $expr, AuthExpressions $context, int $pos, int $depth = 0): ?string
    {
        if ($depth > 4) {
            return null;
        }
        if ($expr instanceof Expr\Array_) {
            $first = $expr->items[0] ?? null;

            return $first === null ? null : $this->modelOf($first->value, $context, $pos, $depth + 1);
        }
        if ($expr instanceof Expr\ClassConstFetch && $expr->class instanceof Node\Name && $expr->name instanceof Node\Identifier && strtolower($expr->name->toString()) === 'class') {
            return self::modelName($expr->class);
        }
        if ($expr instanceof Node\Scalar\String_) {
            return str_contains($expr->value, '\\') ? ltrim($expr->value, '\\') : null;
        }
        if ($expr instanceof Expr\Variable && is_string($expr->name)) {
            $value = $context->lastAssignment($expr->name, $pos);
            if ($value === null) {
                $type = $context->paramType($expr->name);

                return $type === null || in_array(strtolower($type), self::SCALARS, true) ? null : ltrim($type, '\\');
            }
            if ($value instanceof Expr\New_) {
                return $value->class instanceof Node\Name ? self::modelName($value->class) : null;
            }
            if ($value instanceof Expr\Variable) {
                return $this->modelOf($value, $context, $value->getStartFilePos(), $depth + 1);
            }

            return self::queriedModel($value);
        }

        return null;
    }

    // X::find*|first*(..), or X::where*|query(..)->...->find*|first*|sole(..) with no fetch or read in between.
    private static function queriedModel(Expr $expr): ?string
    {
        $calls = [];
        $node = $expr;
        while (AuthExpressions::isCall($node)) {
            array_unshift($calls, AuthExpressions::name($node) ?? '');
            $node = $node->var;
        }
        if (! $node instanceof Expr\StaticCall || ! $node->class instanceof Node\Name) {
            return null;
        }
        $root = AuthExpressions::name($node) ?? '';
        $fetches = static fn (string $n): bool => str_starts_with($n, 'find') || str_starts_with($n, 'first') || $n === 'sole';
        if ($calls === []) {
            return $fetches($root) ? self::modelName($node->class) : null;
        }
        $outer = array_pop($calls);
        if (! $fetches($outer) || ! (str_starts_with($root, 'where') || $root === 'query') || array_filter($calls, static fn (string $n): bool => $fetches($n) || in_array($n, AuthExpressions::READS, true)) !== []) {
            return null;
        }

        return self::modelName($node->class);
    }

    private static function modelName(Node\Name $name): ?string
    {
        $text = ltrim($name->toString(), '\\');

        return in_array(strtolower($text), ['self', 'static', 'parent'], true) ? null : $text;
    }

    private function isHelper(Expr $node, ?ClassSymbol $class): bool
    {
        if ($this->helperNames === [] && $this->helperSymbols === []) {
            return false;
        }
        $name = AuthExpressions::name($node);
        if ($name === null) {
            return false;
        }
        if (isset($this->helperNames[$name])) {
            return true;
        }
        if ($node instanceof Expr\StaticCall && $node->class instanceof Node\Name) {
            return isset($this->helperSymbols[strtolower(ltrim($node->class->toString(), '\\')).'::'.$name]);
        }
        if ($node instanceof Expr\MethodCall && $class !== null && self::onThis($node)) {
            $method = $this->symbols->findMethod($class->name, $name);

            return $method !== null && isset($this->helperSymbols[strtolower($method->class).'::'.$name]);
        }

        return false;
    }

    /**
     * @param  array<Node\Param>  $params
     * @return array<string, ?string>
     */
    private static function nativeTypes(array $params): array
    {
        $out = [];
        foreach ($params as $param) {
            if ($param->var instanceof Expr\Variable && is_string($param->var->name)) {
                $out[$param->var->name] = self::typeName($param->type);
            }
        }

        return $out;
    }

    private static function typeName(?Node $type): ?string
    {
        if ($type instanceof Node\NullableType) {
            return self::typeName($type->type);
        }
        if ($type instanceof Node\UnionType || $type instanceof Node\IntersectionType) {
            foreach ($type->types as $inner) {
                $name = self::typeName($inner);
                if ($name !== null && ! in_array($name, self::SCALARS, true)) {
                    return $name;
                }
            }

            return null;
        }
        if ($type instanceof Node\Name) {
            return ltrim($type->toString(), '\\');
        }

        return $type instanceof Node\Identifier ? strtolower($type->toString()) : null;
    }

    private static function onThis(Expr\MethodCall $call): bool
    {
        return $call->var instanceof Expr\Variable && $call->var->name === 'this';
    }

    private function describe(Expr $node): string
    {
        $text = (string) preg_replace('/\\\\?(?:[A-Za-z_][A-Za-z0-9_]*\\\\)+([A-Za-z_][A-Za-z0-9_]*)/', '$1', $this->printer->prettyPrintExpr($node));
        $text = (string) preg_replace('/\s+/', ' ', $text);

        return strlen($text) > self::MAX_SOURCE ? substr($text, 0, self::MAX_SOURCE - 3).'...' : $text;
    }

    private static function short(string $class): string
    {
        $pos = strrpos($class, '\\');

        return $pos === false ? $class : substr($class, $pos + 1);
    }
}
