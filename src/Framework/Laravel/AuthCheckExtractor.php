<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Framework\Laravel;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\NodeFinder;
use PhpParser\PrettyPrinter\Standard;
use TusharKhan\SemanticSec\Parsing\Symbols\ClassSymbol;
use TusharKhan\SemanticSec\Parsing\Symbols\MethodSymbol;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;

/** Finds the depth-0 authorization checks that protect a route (SPEC §6). */
final class AuthCheckExtractor
{
    private const SCALARS = ['int', 'string', 'array', 'bool', 'float', 'mixed', 'callable', 'iterable', 'object', 'void', 'null', 'false', 'true', 'never', 'self', 'static', 'parent'];

    private const RESOURCE_ABILITIES = ['index' => 'viewAny', 'show' => 'view', 'create' => 'create', 'store' => 'create', 'edit' => 'update', 'update' => 'update', 'destroy' => 'delete'];

    private const GATE_FACADES = ['Illuminate\\Support\\Facades\\Gate', 'Gate'];

    private const GATE_METHODS = ['authorize', 'allows', 'denies', 'check', 'any', 'none', 'inspect'];

    private const GUARDS = ['abort_if', 'abort_unless', 'throw_if', 'throw_unless'];

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
            return [$route->withChecks($this->middlewareChecks($route, $warnings)), $warnings];
        }

        $paramTypes = $closure !== null ? self::closureParams($closure) : $method->params;
        $route = $route->withParameters($this->bindModels($route->parameters, $paramTypes));
        $bound = [];
        foreach ($route->parameters as $p) {
            if ($p->boundModel !== null) {
                $bound[$p->name] = $p->boundModel;
            }
        }

        $checks = $this->middlewareChecks($route, $warnings);
        array_push($checks, ...$this->routeLevelChecks($route));
        if ($class !== null) {
            array_push($checks, ...$this->resourceChecks($class, $method, $warnings));
            array_push($checks, ...$this->formRequestChecks($method));
        }

        $file = $method !== null ? $method->file : $route->file;
        $body = $closure !== null
            ? ($closure instanceof Expr\Closure ? $closure->stmts : [$closure->expr])
            : ($method->node->stmts ?? []);
        $context = new AuthExpressions($this->symbols, $paramTypes, $body);
        array_push($checks, ...$this->bodyChecks($body, $context, $file, $class, $bound));

        return [$route->withChecks($checks), $warnings];
    }

    /**
     * @param  list<string>  $warnings
     * @return list<AuthCheck>
     */
    private function middlewareChecks(RouteEntry $route, array &$warnings): array
    {
        $declared = $route->middleware;
        if ($route->action->class !== null && $route->action->method !== null) {
            [$fromController, $w] = $this->controllerMiddleware->forAction($route->action->class, $route->action->method);
            array_push($warnings, ...$w);
            array_push($declared, ...$fromController);
        }
        // Laravel excludes by exact resolved name.
        $excluded = $this->middleware->expand($route->withoutMiddleware);
        $checks = [];
        foreach ($this->middleware->expand($declared) as $m) {
            if (in_array($m, $excluded, true)) {
                continue;
            }
            $kind = $this->middleware->kind($m);
            if ($kind === MiddlewareKind::Authentication) {
                $checks[] = new AuthCheck(AuthCheckKind::Authentication, AuthStrength::Authentication, 'middleware '.$m, $route->file, $route->line);
            } elseif ($kind === MiddlewareKind::Ability) {
                $ability = $this->middleware->ability($m);
                $reason = $ability === null ? null : $this->trivialReason($this->middlewareModel($route, $ability['arguments'][0] ?? null), [$ability['ability']], false);
                $checks[] = new AuthCheck(AuthCheckKind::RouteAbility, $reason === null ? AuthStrength::Authorization : AuthStrength::None, 'middleware '.$m.($reason === null ? '' : ': '.$reason), $route->file, $route->line);
            }
        }

        return $checks;
    }

    // A can: argument names a route parameter (its bound model) or a class.
    private function middlewareModel(RouteEntry $route, ?string $argument): ?string
    {
        if ($argument === null) {
            return null;
        }
        foreach ($route->parameters as $p) {
            if ($p->name === $argument) {
                return $p->boundModel;
            }
        }

        return str_contains($argument, '\\') ? ltrim($argument, '\\') : null;
    }

    /**
     * @param  list<RouteParameter>  $parameters
     * @param  array<string, ?string>  $types
     * @return list<RouteParameter>
     */
    private function bindModels(array $parameters, array $types): array
    {
        return array_map(function (RouteParameter $p) use ($types): RouteParameter {
            $type = $types[$p->name] ?? null;
            if ($type === null || in_array(strtolower($type), self::SCALARS, true)) {
                return $p;
            }

            return new RouteParameter($p->name, $p->field, $p->optional, ltrim($type, '\\'));
        }, $parameters);
    }

    /** @return list<AuthCheck> */
    private function routeLevelChecks(RouteEntry $route): array
    {
        if ($route->scopeBindings) {
            return [new AuthCheck(AuthCheckKind::QueryScope, AuthStrength::Authorization, 'scopeBindings', $route->file, $route->line)];
        }
        $checks = [];
        foreach ($route->parameters as $i => $p) {
            // Laravel scopes a custom-keyed child binding to the model right before it.
            if ($i > 0 && $p->field !== null && $p->boundModel !== null && $route->parameters[$i - 1]->boundModel !== null) {
                $checks[] = new AuthCheck(AuthCheckKind::QueryScope, AuthStrength::Authorization, sprintf('implicit scoped binding {%s:%s}', $p->name, $p->field), $route->file, $route->line);
            }
        }

        return $checks;
    }

    /**
     * @param  list<string>  $warnings
     * @return list<AuthCheck>
     */
    private function resourceChecks(ClassSymbol $class, MethodSymbol $method, array &$warnings): array
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
                if (isset($args[2]) && ! $this->methodAllowedByOptions($args[2], $method->name, $ctor->file, $owner)) {
                    if (! $args[2] instanceof Expr\Array_) {
                        $warnings[] = $where.'authorizeResource options could not be resolved';
                    }

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
                $source = sprintf('authorizeResource(%s) %s -> %s', $model === null ? '?' : self::short($model).'::class', $method->name, $ability);
                $checks[] = new AuthCheck(AuthCheckKind::ControllerAbility, $reason === null ? AuthStrength::Authorization : AuthStrength::None, $source.($reason === null ? '' : ': '.$reason), $ctor->file, $call->getStartLine());
            }
        }

        return $checks;
    }

    // Unresolvable options count as excluding the method.
    private function methodAllowedByOptions(Expr $options, string $method, string $file, ClassSymbol $owner): bool
    {
        if (! $options instanceof Expr\Array_) {
            return false;
        }
        $method = strtolower($method);
        foreach ($options->items as $item) {
            $key = $item->key === null ? null : $this->eval->string($item->key, $file, $owner);
            if ($key !== 'only' && $key !== 'except') {
                return false;
            }
            $values = [];
            foreach ($item->value instanceof Expr\Array_ ? $item->value->items : [$item] as $inner) {
                $value = $this->eval->string($inner->value, $file, $owner);
                if ($value === null) {
                    return false;
                }
                $values[] = strtolower($value);
            }
            if (($key === 'only') !== in_array($method, $values, true)) {
                return false;
            }
        }

        return true;
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

    /** @return list<AuthCheck> */
    private function formRequestChecks(MethodSymbol $method): array
    {
        $context = new AuthExpressions($this->symbols, [], []);
        $checks = [];
        foreach ($method->node->params as $param) {
            if (! $param->var instanceof Expr\Variable || ! is_string($param->var->name)) {
                continue;
            }
            $type = $method->params[$param->var->name] ?? null;
            if ($type === null || ! $context->isFormRequest($type)) {
                continue;
            }
            $authorize = $this->symbols->findMethod($type, 'authorize');
            $name = 'FormRequest '.self::short($type);
            [$strength, $source] = match (true) {
                $authorize === null => [AuthStrength::None, $name.' has no authorize()'],
                PolicyRegistry::allowsAll($authorize) => [AuthStrength::None, $name.'::authorize returns true'],
                default => [AuthStrength::Authorization, $name.'::authorize'],
            };
            $checks[] = new AuthCheck(AuthCheckKind::FormRequest, $strength, $source, $method->file, $param->getStartLine());
        }

        return $checks;
    }

    /**
     * @param  array<Node>  $body
     * @param  array<string, string>  $bound  route parameter => bound model
     * @return list<AuthCheck>
     */
    private function bodyChecks(array $body, AuthExpressions $context, string $file, ?ClassSymbol $class, array $bound): array
    {
        $nodes = (new NodeFinder())->find($body, static fn (Node $n): bool => $n instanceof Expr\CallLike);
        $inner = [];
        foreach ($nodes as $node) {
            if (AuthExpressions::isCall($node)) {
                $inner[spl_object_id($node->var)] = true;
            }
        }
        $checks = [];
        foreach ($nodes as $node) {
            \assert($node instanceof Expr);
            $add = static function (AuthCheckKind $kind, AuthStrength $strength, string $source) use (&$checks, $file, $node): void {
                $checks[] = new AuthCheck($kind, $strength, $source, $file, $node->getStartLine());
            };
            $ability = $this->abilityCall($node, $context, $bound);
            if ($ability !== null) {
                [$abilityArg, $modelArg, $any] = $ability;
                $reason = $this->abilityReason($abilityArg, $modelArg, $any, $context, $file, $class);
                $add(AuthCheckKind::ControllerAbility, $reason === null ? AuthStrength::Authorization : AuthStrength::None, $this->describe($node).($reason === null ? '' : ': '.$reason));
            }
            if ($node instanceof Expr\FuncCall && in_array(AuthExpressions::name($node), self::GUARDS, true)) {
                $condition = AuthExpressions::args($node)[0] ?? null;
                if ($condition !== null && $context->containsAuth($condition)) {
                    $add(AuthCheckKind::AbortGuard, AuthStrength::Authorization, $this->describe($node));
                }
            }
            if ((! isset($inner[spl_object_id($node)]) && $context->isRelationRead($node)) || $context->isWhereScope($node)) {
                $add(AuthCheckKind::QueryScope, AuthStrength::Authorization, $this->describe($node));
            }
            if ($this->isHelper($node, $class)) {
                $add(AuthCheckKind::CustomHelper, AuthStrength::Authorization, $this->describe($node));
            }
        }

        return $checks;
    }

    /**
     * @param  array<string, string>  $bound
     * @return array{0: ?Expr, 1: ?Expr, 2: bool}|null ability arg, model arg, any-semantics
     */
    private function abilityCall(Expr $node, AuthExpressions $context, array $bound): ?array
    {
        $name = AuthExpressions::name($node);
        $args = AuthExpressions::args($node);
        if ($node instanceof Expr\MethodCall && self::onThis($node) && ($name === 'authorize' || $name === 'authorizeforuser')) {
            $offset = $name === 'authorize' ? 0 : 1;

            return [$args[$offset] ?? null, $args[$offset + 1] ?? null, false];
        }
        if ($node instanceof Expr\StaticCall && $node->class instanceof Node\Name && in_array(ltrim($node->class->toString(), '\\'), self::GATE_FACADES, true)
            && in_array($name, self::GATE_METHODS, true)) {
            return [$args[0] ?? null, $args[1] ?? null, $name === 'any'];
        }
        if (AuthExpressions::isCall($node) && in_array($name, ['can', 'cannot', 'cant'], true)) {
            $receiver = $node->var;
            // A route-bound $user is chosen by the caller, so its can() proves nothing.
            $userParam = $receiver instanceof Expr\Variable && $receiver->name === 'user' && $context->hasParam('user') && ! isset($bound['user'])
                && $context->lastAssignment('user', $receiver->getStartFilePos()) === null;
            if ($userParam || $context->isAuthUser($receiver)) {
                return [$args[0] ?? null, $args[1] ?? null, false];
            }
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

    // X::find*(..), X::first*(..), or X::where*|query(..)->...->first*|find*|sole(..)
    private static function queriedModel(Expr $expr): ?string
    {
        $outer = AuthExpressions::name($expr) ?? '';
        $node = $expr;
        while (AuthExpressions::isCall($node)) {
            $node = $node->var;
        }
        if (! $node instanceof Expr\StaticCall || ! $node->class instanceof Node\Name) {
            return null;
        }
        $root = AuthExpressions::name($node) ?? '';
        $fetches = static fn (string $n): bool => str_starts_with($n, 'find') || str_starts_with($n, 'first') || $n === 'sole';
        if ($node === $expr) {
            return $fetches($root) ? self::modelName($node->class) : null;
        }

        return (str_starts_with($root, 'where') || $root === 'query' || $fetches($root)) && $fetches($outer) ? self::modelName($node->class) : null;
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

    /** @return array<string, ?string> */
    private static function closureParams(Expr\Closure|Expr\ArrowFunction $closure): array
    {
        $out = [];
        foreach ($closure->params as $param) {
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
