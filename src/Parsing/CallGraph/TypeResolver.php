<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Parsing\CallGraph;

use PhpParser\Node;
use PhpParser\Node\Expr;
use TusharKhan\SemanticSec\Framework\Laravel\AuthExpressions;
use TusharKhan\SemanticSec\Parsing\Symbols\MethodSymbol;
use TusharKhan\SemanticSec\Parsing\Symbols\RelationResolver;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;

/** The static class of an expression inside one function body (SPEC §8); null whenever it is not proven. */
final class TypeResolver
{
    private const MODEL_BASES = [
        'Illuminate\\Database\\Eloquent\\Model',
        'Illuminate\\Foundation\\Auth\\User',
        'Illuminate\\Database\\Eloquent\\Relations\\Pivot',
        'Illuminate\\Database\\Eloquent\\Relations\\MorphPivot',
    ];

    private const FACADE = 'Illuminate\\Support\\Facades\\Facade';

    private const APP_FACADES = ['Illuminate\\Support\\Facades\\App', 'App'];

    // Eloquent calls that return one model of the queried class.
    private const SINGLE = ['find', 'findorfail', 'findornew', 'first', 'firstorfail', 'firstornew', 'firstorcreate', 'firstwhere', 'sole', 'make', 'create', 'updateorcreate'];

    // Builder calls that keep the query on the same model.
    private const BUILDER = [
        'query', 'with', 'without', 'withcount', 'withtrashed', 'onlytrashed', 'withouttrashed', 'orderby', 'orderbydesc',
        'latest', 'oldest', 'select', 'addselect', 'distinct', 'join', 'leftjoin', 'rightjoin', 'has', 'orhas', 'doesnthave',
        'lockforupdate', 'sharedlock', 'limit', 'take', 'skip', 'offset', 'groupby', 'having',
    ];

    private const BUILTINS = [
        'int', 'string', 'array', 'bool', 'float', 'mixed', 'callable', 'iterable', 'object', 'void', 'null',
        'false', 'true', 'never', 'scalar', 'resource', 'numeric', 'self', 'static', 'parent',
    ];

    /** @var \WeakMap<Node\FunctionLike, array<string, FunctionScope>> */
    private \WeakMap $scopes;

    public function __construct(private readonly SymbolTable $symbols, private readonly RelationResolver $relations, private readonly ?string $authUserModel)
    {
        $this->scopes = new \WeakMap();
    }

    public function typeOf(Expr $expr, PathNode $context): ?string
    {
        return match (true) {
            $expr instanceof Expr\Variable => $this->variableType($expr, $context),
            $expr instanceof Expr\PropertyFetch, $expr instanceof Expr\NullsafePropertyFetch => $this->propertyFetchType($expr, $context),
            $expr instanceof Expr\MethodCall, $expr instanceof Expr\NullsafeMethodCall => $this->methodCallType($expr, $context),
            $expr instanceof Expr\StaticCall => $this->staticCallType($expr, $context),
            $expr instanceof Expr\FuncCall => $this->funcCallType($expr, $context),
            $expr instanceof Expr\New_ => $expr->class instanceof Node\Name ? $this->className($expr->class, $context) : null,
            default => null,
        };
    }

    private function variableType(Expr\Variable $var, PathNode $context): ?string
    {
        if (! is_string($var->name)) {
            return null;
        }
        if ($var->name === 'this') {
            return $this->thisClass($context);
        }
        $scope = $this->scope($context);
        if ($scope === null) {
            return null;
        }
        $key = $var->name."\0".$var->getStartFilePos();
        if (! array_key_exists($key, $scope->memo)) {
            $scope->memo[$key] = null;
            $scope->memo[$key] = $this->assignedType($var->name, $var, $scope, $context);
        }

        return $scope->memo[$key];
    }

    // Every assignment (and the parameter, if any) must give the same class, and one must run on every path.
    private function assignedType(string $name, Expr\Variable $var, FunctionScope $scope, PathNode $context): ?string
    {
        $pos = $var->getStartFilePos();
        $isParam = array_key_exists($name, $scope->params);
        if ($scope->auth->isUntouchedParam($name, $pos)) {
            return $scope->params[$name];
        }
        $values = $scope->auth->assignedValues($var);
        if ($values === null) {
            return null;
        }
        $types = $isParam ? [$scope->params[$name]] : [];
        foreach ($values as $value) {
            $types[] = $this->typeOf($value, $context) ?? $scope->docType($value);
        }
        $unique = array_unique($types, SORT_REGULAR);
        if (count($unique) !== 1 || $unique[0] === null) {
            return null;
        }

        return $isParam || $scope->assignedUnconditionally($name, $pos) ? $unique[0] : null;
    }

    private function propertyFetchType(Expr\PropertyFetch|Expr\NullsafePropertyFetch $expr, PathNode $context): ?string
    {
        if (! $expr->name instanceof Node\Identifier) {
            return null;
        }
        $class = $this->typeOf($expr->var, $context);
        if ($class === null) {
            return null;
        }
        $name = $expr->name->toString();
        $property = $this->symbols->findProperty($class, $name);
        if ($property !== null) {
            return $this->classLike($property->type);
        }
        if ($this->isModel($class)) {
            $related = $this->relations->relatedClass($class, $name);
            if ($related !== null) {
                return $related;
            }
        }
        foreach ($this->symbols->lineage($class) as $symbol) {
            if (isset($symbol->docProperties[$name])) {
                return $this->classLike($symbol->docProperties[$name]);
            }
        }

        return null;
    }

    private function methodCallType(Expr\MethodCall|Expr\NullsafeMethodCall $expr, PathNode $context): ?string
    {
        if (! $expr->name instanceof Node\Identifier || $expr->isFirstClassCallable()) {
            return null;
        }
        $scope = $this->scope($context);
        if ($scope !== null && $scope->auth->isAuthUser($expr)) {
            return $this->authUserModel;
        }
        $name = $expr->name->toLowerString();
        if (in_array($name, self::SINGLE, true)) {
            $model = $this->builderModel($expr->var, $context);
            if ($model !== null) {
                return $this->findsMany($expr, $name) ? null : $model;
            }
        }
        // app()->make(X::class)
        if ($name === 'make' && AuthExpressions::isFunc($expr->var, 'app') && $expr->var instanceof Expr\FuncCall && $expr->var->args === []) {
            return $this->classArgument($expr, $context);
        }
        $class = $this->typeOf($expr->var, $context);

        return $class === null ? null : $this->methodReturn($class, $name);
    }

    private function staticCallType(Expr\StaticCall $expr, PathNode $context): ?string
    {
        if (! $expr->class instanceof Node\Name || ! $expr->name instanceof Node\Identifier || $expr->isFirstClassCallable()) {
            return null;
        }
        $scope = $this->scope($context);
        if ($scope !== null && $scope->auth->isAuthUser($expr)) {
            return $this->authUserModel;
        }
        $name = $expr->name->toLowerString();
        if (in_array(ltrim($expr->class->toString(), '\\'), self::APP_FACADES, true)) {
            return $name === 'make' ? $this->classArgument($expr, $context) : null;
        }
        $class = $this->className($expr->class, $context);
        if ($class === null || $this->symbols->isSubclassOf($class, self::FACADE)) {
            return null;
        }
        $method = $this->symbols->findMethod($class, $name);
        if ($method !== null) {
            return $method->static ? $this->classLike($method->returnType) : null;
        }
        if ($this->isModel($class) && in_array($name, self::SINGLE, true)) {
            return $this->findsMany($expr, $name) ? null : $class;
        }

        return null;
    }

    private function funcCallType(Expr\FuncCall $expr, PathNode $context): ?string
    {
        if (AuthExpressions::isFunc($expr, 'app') || AuthExpressions::isFunc($expr, 'resolve')) {
            return $this->classArgument($expr, $context);
        }
        $scope = $this->scope($context);

        return $scope !== null && $scope->auth->isAuthUser($expr) ? $this->authUserModel : null;
    }

    // The model an Eloquent query or relation expression reads, when the chain keeps it a query on one model.
    private function builderModel(Expr $expr, PathNode $context): ?string
    {
        if ($expr instanceof Expr\StaticCall && $expr->class instanceof Node\Name && $expr->name instanceof Node\Identifier) {
            $class = $this->className($expr->class, $context);

            return $class !== null && $this->isModel($class) && $this->keepsQuery($class, $expr->name->toLowerString()) ? $class : null;
        }
        if (! AuthExpressions::isCall($expr) || ! $expr->name instanceof Node\Identifier) {
            return null;
        }
        $name = $expr->name->toLowerString();
        $inner = $this->builderModel($expr->var, $context);
        if ($inner !== null) {
            return $this->keepsQuery($inner, $name) ? $inner : null;
        }
        // $model->relation() starts a query on the related model.
        $owner = $this->typeOf($expr->var, $context);

        return $owner !== null && $this->isModel($owner) ? $this->relations->relatedClass($owner, $name) : null;
    }

    private function keepsQuery(string $model, string $name): bool
    {
        return in_array($name, self::BUILDER, true) || str_starts_with($name, 'where') || str_starts_with($name, 'orwhere')
            || $this->symbols->findMethod($model, 'scope'.$name) !== null;
    }

    // find([..]) / findOrFail([..]) return a collection.
    private function findsMany(Expr\CallLike $call, string $name): bool
    {
        $first = $call->getArgs()[0] ?? null;

        return in_array($name, ['find', 'findorfail', 'findornew'], true) && $first !== null && $first->value instanceof Expr\Array_;
    }

    private function methodReturn(string $class, string $name): ?string
    {
        if ($this->isModel($class)) {
            $related = $this->relations->relatedClass($class, $name);
            if ($related !== null) {
                return $related;
            }
        }
        $method = $this->symbols->findMethod($class, $name);
        if ($method !== null) {
            return $this->classLike($method->returnType);
        }
        foreach ($this->symbols->lineage($class) as $symbol) {
            if (isset($symbol->docMethods[$name])) {
                return $this->classLike($symbol->docMethods[$name]);
            }
        }

        return null;
    }

    // app(X::class), resolve(X::class), App::make(X::class)
    private function classArgument(Expr\CallLike $call, PathNode $context): ?string
    {
        $args = AuthExpressions::args($call);
        $first = $args[0] ?? null;
        if (! $first instanceof Expr\ClassConstFetch || ! $first->class instanceof Node\Name
            || ! $first->name instanceof Node\Identifier || $first->name->toLowerString() !== 'class') {
            return null;
        }

        return $this->className($first->class, $context);
    }

    private function className(Node\Name $name, PathNode $context): ?string
    {
        return match ($name->toLowerString()) {
            'self' => $this->selfClass($context),
            'parent' => ($self = $this->selfClass($context)) === null ? null : $this->symbols->getClass($self)?->parent,
            // A late-static class may be any subclass.
            'static' => null,
            default => ltrim($name->toString(), '\\'),
        };
    }

    // `self` in a trait means the using class, which is unknown here.
    private function selfClass(PathNode $context): ?string
    {
        $class = $this->thisClass($context);

        return $class === null || $this->symbols->getClass($class)?->kind === 'trait' ? null : $class;
    }

    private function thisClass(PathNode $context): ?string
    {
        if ($context->closure !== null) {
            $static = ($context->closure instanceof Expr\Closure || $context->closure instanceof Expr\ArrowFunction) && $context->closure->static;

            return $static ? null : $context->closureClass;
        }

        return $context->method?->class;
    }

    private function isModel(string $class): bool
    {
        foreach (self::MODEL_BASES as $base) {
            if ($this->symbols->isSubclassOf($class, $base)) {
                return true;
            }
        }

        return false;
    }

    private function classLike(?string $type): ?string
    {
        return $type === null || in_array(strtolower($type), self::BUILTINS, true) ? null : ltrim($type, '\\');
    }

    private function scope(PathNode $context): ?FunctionScope
    {
        $fn = $context->closure ?? $context->method?->node;
        if ($fn === null) {
            return null;
        }
        $key = (string) $context->closureClass;
        $cached = $this->scopes[$fn] ?? [];
        if (! isset($cached[$key])) {
            $params = $context->closure !== null ? $this->closureParams($context->closure, $context) : $this->methodParams($context->method);
            $body = $fn->getStmts() ?? [];
            $thisClass = $this->thisClass($context);
            $auth = new AuthExpressions($this->symbols, $params, $body, AuthExpressions::isFormRequest($this->symbols, $thisClass));
            $cached[$key] = new FunctionScope($auth, $params, $body, $this->docVars($context));
            $this->scopes[$fn] = $cached;
        }

        return $cached[$key];
    }

    /** @return array<string, ?string> */
    private function methodParams(?MethodSymbol $method): array
    {
        return array_map($this->classLike(...), $method->params ?? []);
    }

    /** @return array<string, ?string> */
    private function closureParams(Node\FunctionLike $closure, PathNode $context): array
    {
        $out = [];
        foreach ($closure->getParams() as $param) {
            if ($param->var instanceof Expr\Variable && is_string($param->var->name)) {
                $type = $param->type instanceof Node\NullableType ? $param->type->type : $param->type;
                $out[$param->var->name] = $type instanceof Node\Name ? $this->className($type, $context) : null;
            }
        }

        return $out;
    }

    /** @return array<int, array<string, string>> */
    private function docVars(PathNode $context): array
    {
        if ($context->closure === null) {
            return $context->method->docVars ?? [];
        }
        // A closure's tags were collected with its enclosing method.
        $pos = $context->closure->getStartFilePos();
        foreach ($context->closureClass === null ? [] : $this->symbols->getClass($context->closureClass)->methods ?? [] as $method) {
            if ($method->file === $context->file && $method->node->getStartFilePos() <= $pos && $pos <= $method->node->getEndFilePos()) {
                return $method->docVars;
            }
        }

        return [];
    }
}
