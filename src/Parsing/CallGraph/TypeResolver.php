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
        $name = $var->name;

        return $scope->remember($name."\0".$var->getStartFilePos(), fn (): ?string => $this->assignedType($name, $var, $scope, $context));
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
                // A to-many relation reads as a collection.
                return $this->relations->isToOne($class, $name) === true ? $related : null;
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
            return self::defaultGuard($expr) ? $this->authUserModel : null;
        }
        $name = $expr->name->toLowerString();
        if (in_array($name, self::SINGLE, true)) {
            $model = $this->builderModel($expr->var, $context);
            if ($model !== null) {
                return $this->findsByScalar($expr, $name, $context) ? $model : null;
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
            return self::defaultGuard($expr) ? $this->authUserModel : null;
        }
        $name = $expr->name->toLowerString();
        if (in_array(ltrim($expr->class->toString(), '\\'), self::APP_FACADES, true)) {
            return $name === 'make' ? $this->classArgument($expr, $context) : null;
        }
        $class = $this->className($expr->class, $context);
        if ($class === null || $this->symbols->isSubclassOf($class, self::FACADE)) {
            return null;
        }
        $keyword = in_array($expr->class->toLowerString(), ['self', 'parent'], true);
        $method = $this->symbols->findMethod($class, $name);
        if ($method !== null) {
            if ($method->static) {
                // self::/parent:: forward the late-static class, which may be a subclass.
                return $this->methodResult($method, $class, $keyword ? null : $class);
            }

            // self::m() / parent::m() on an instance method call it on $this.
            return $keyword ? $this->methodResult($method, $class, null) : null;
        }
        if ($this->isModel($class) && in_array($name, self::SINGLE, true)) {
            return $this->findsByScalar($expr, $name, $context) ? $class : null;
        }

        return null;
    }

    private function funcCallType(Expr\FuncCall $expr, PathNode $context): ?string
    {
        if (AuthExpressions::isFunc($expr, 'app') || AuthExpressions::isFunc($expr, 'resolve')) {
            return $this->classArgument($expr, $context);
        }
        $scope = $this->scope($context);

        return $scope !== null && $scope->auth->isAuthUser($expr) && self::defaultGuard($expr) ? $this->authUserModel : null;
    }

    // Only the default guard is known to hold $authUserModel: auth()->user(), Auth::user(), Auth::guard()->user(), $request->user().
    private static function defaultGuard(Expr $expr): bool
    {
        if (AuthExpressions::isFunc($expr, 'optional')) {
            $args = AuthExpressions::args($expr);

            return count($args) === 1 && self::defaultGuard($args[0]);
        }
        if ($expr instanceof Expr\StaticCall) {
            return $expr->args === [];
        }
        if (! AuthExpressions::isCall($expr) || $expr->args !== []) {
            return false;
        }
        $receiver = $expr->var;
        while (AuthExpressions::isCall($receiver) || $receiver instanceof Expr\StaticCall || $receiver instanceof Expr\FuncCall) {
            if ($receiver->args !== []) {
                return false;
            }
            if ($receiver instanceof Expr\StaticCall || $receiver instanceof Expr\FuncCall) {
                return true;
            }
            $receiver = $receiver->var;
        }

        return $receiver instanceof Expr\Variable;
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

    // find()/findOrFail()/findOrNew() give one model only for a key proven scalar; an array (or anything unproven) gives a collection.
    private function findsByScalar(Expr\CallLike $call, string $name, PathNode $context): bool
    {
        if (! in_array($name, ['find', 'findorfail', 'findornew'], true)) {
            return true;
        }
        $args = AuthExpressions::args($call);

        return $args !== [] && $this->isScalar($args[0], $context, 0);
    }

    private function isScalar(Expr $expr, PathNode $context, int $depth): bool
    {
        if ($expr instanceof Node\Scalar\Int_ || $expr instanceof Node\Scalar\Float_ || $expr instanceof Node\Scalar\String_
            || $expr instanceof Node\Scalar\InterpolatedString || $expr instanceof Expr\BinaryOp\Concat
            || $expr instanceof Expr\Cast\Int_ || $expr instanceof Expr\Cast\Double || $expr instanceof Expr\Cast\String_) {
            return true;
        }
        $scope = $this->scope($context);
        if ($scope === null || $depth > 4) {
            return false;
        }
        if ($scope->auth->isAuthId($expr)) {
            return true;
        }
        if (! $expr instanceof Expr\Variable || ! is_string($expr->name)) {
            return false;
        }
        $name = $expr->name;
        $pos = $expr->getStartFilePos();
        if ($scope->auth->hasParam($name) && ! isset($scope->scalarParams[$name])) {
            return false;
        }
        if ($scope->auth->isUntouchedParam($name, $pos)) {
            return true;
        }
        $values = $scope->auth->assignedValues($expr);
        foreach ($values ?? [] as $value) {
            if (! $this->isScalar($value, $context, $depth + 1)) {
                return false;
            }
        }

        return $values !== null;
    }

    private function methodReturn(string $class, string $name): ?string
    {
        // $model->relation() is a Relation builder, not a model.
        if ($this->isModel($class) && $this->relations->relatedClass($class, $name) !== null) {
            return null;
        }
        $method = $this->symbols->findMethod($class, $name);
        if ($method !== null) {
            return $this->methodResult($method, $class, $class);
        }
        foreach ($this->symbols->lineage($class) as $symbol) {
            if (isset($symbol->docMethods[$name])) {
                return $this->classLike($symbol->docMethods[$name]);
            }
        }

        return null;
    }

    /**
     * The class a call returns, given the receiver's class and the late-static class (null when unknown).
     */
    private function methodResult(MethodSymbol $method, string $receiver, ?string $static): ?string
    {
        if ($method->returnAmbiguous) {
            return null;
        }
        if ($method->returnsStatic) {
            return $static;
        }
        if ($method->returnsSelf) {
            // `self` is the declaring class or a subclass; only the declaring class itself is proven.
            return $method->class === $receiver && $this->symbols->getClass($receiver)?->kind !== 'trait' ? $receiver : null;
        }

        return $this->classLike($method->returnType);
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
        $class = $context->method?->class;

        // In a trait, $this is the using class, known only when the caller names it.
        return $class !== null && $this->symbols->getClass($class)?->kind === 'trait' ? $context->closureClass : $class;
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
            $cached[$key] = new FunctionScope($auth, $params, $body, $this->docVars($context), self::scalarParams($fn));
            $this->scopes[$fn] = $cached;
        }

        return $cached[$key];
    }

    /** @return array<string, true> parameters declared int, string or float (optionally nullable) */
    private static function scalarParams(Node\FunctionLike $fn): array
    {
        $out = [];
        foreach ($fn->getParams() as $param) {
            $type = $param->type instanceof Node\NullableType ? $param->type->type : $param->type;
            $members = $type instanceof Node\UnionType ? $type->types : [$type];
            $scalar = $type !== null && ! $param->variadic && ! $param->byRef;
            foreach ($members as $member) {
                $scalar = $scalar && $member instanceof Node\Identifier && in_array($member->toLowerString(), ['int', 'string', 'float', 'null'], true);
            }
            if ($scalar && $param->var instanceof Expr\Variable && is_string($param->var->name)) {
                $out[$param->var->name] = true;
            }
        }

        return $out;
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
