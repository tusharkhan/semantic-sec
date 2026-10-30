<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Framework\Laravel;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\NodeFinder;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;

/** Recognises authenticated-user, auth-id, relation-read and where-scope expressions inside one action body. */
final class AuthExpressions
{
    public const READS = ['find', 'findorfail', 'findmany', 'first', 'firstorfail', 'firstwhere', 'sole', 'get', 'paginate', 'simplepaginate', 'cursorpaginate', 'cursor', 'exists', 'doesntexist', 'count', 'pluck', 'value'];

    public const WRITES = ['create', 'createmany', 'update', 'updateorcreate', 'firstorcreate', 'firstornew', 'save', 'savemany', 'delete', 'forcedelete', 'insert', 'upsert', 'attach', 'sync', 'detach', 'associate', 'increment', 'decrement', 'touch'];

    // Calls on the user that are not relations.
    private const NOT_RELATIONS = ['can', 'cannot', 'cant', 'getkey', 'tokencan', 'fresh', 'refresh', 'load', 'tojson', 'toarray', 'only', 'getattribute'];

    private const AUTH_FACADES = ['Illuminate\\Support\\Facades\\Auth', 'Auth'];

    private const REQUEST = 'Illuminate\\Http\\Request';

    private const FORM_REQUEST = 'Illuminate\\Foundation\\Http\\FormRequest';

    /** @var array<string, list<array{int, Expr}>> var => [assignment end position, value] in source order */
    private array $assignments = [];

    /**
     * @param  array<string, ?string>  $paramTypes  action parameter name => type
     * @param  array<Node>  $body
     */
    public function __construct(private readonly SymbolTable $symbols, private readonly array $paramTypes, array $body, private readonly bool $thisIsRequest = false)
    {
        foreach ((new NodeFinder())->findInstanceOf($body, Expr\Assign::class) as $assign) {
            if ($assign->var instanceof Expr\Variable && is_string($assign->var->name)) {
                $this->assignments[$assign->var->name][] = [$assign->getEndFilePos(), $assign->expr];
            }
        }
    }

    public function paramType(string $name): ?string
    {
        return $this->paramTypes[$name] ?? null;
    }

    public function hasParam(string $name): bool
    {
        return array_key_exists($name, $this->paramTypes);
    }

    /** The last value assigned to $name that ends before $pos, or null. */
    public function lastAssignment(string $name, int $pos): ?Expr
    {
        $found = null;
        foreach ($this->assignments[$name] ?? [] as [$end, $value]) {
            if ($end < $pos) {
                $found = $value;
            }
        }

        return $found;
    }

    public function isAuthUser(Expr $expr): bool
    {
        if ($expr instanceof Expr\StaticCall) {
            return self::isAuthFacade($expr->class) && self::name($expr) === 'user';
        }
        if ($expr instanceof Expr\Variable) {
            $value = is_string($expr->name) && $expr->name !== 'this' ? $this->lastAssignment($expr->name, $expr->getStartFilePos()) : null;

            return $value !== null && $this->isAuthUser($value);
        }
        if (! self::isCall($expr) || self::name($expr) !== 'user') {
            return false;
        }
        $var = $expr->var;

        return self::isGuard($var) || self::isFunc($var, 'request') || $this->isRequestVariable($var);
    }

    public function isAuthId(Expr $expr): bool
    {
        if ($expr instanceof Expr\StaticCall) {
            return self::isAuthFacade($expr->class) && self::name($expr) === 'id';
        }
        if ($expr instanceof Expr\PropertyFetch || $expr instanceof Expr\NullsafePropertyFetch) {
            return $expr->name instanceof Node\Identifier && $expr->name->toString() === 'id' && $this->isAuthUser($expr->var);
        }
        if ($expr instanceof Expr\Variable) {
            $value = is_string($expr->name) && $expr->name !== 'this' ? $this->lastAssignment($expr->name, $expr->getStartFilePos()) : null;

            return $value !== null && $this->isAuthId($value);
        }
        if (! self::isCall($expr)) {
            return false;
        }
        $name = self::name($expr);

        return ($name === 'id' && self::isGuard($expr->var)) || ($name === 'getkey' && $this->isAuthUser($expr->var));
    }

    /** True when the subtree holds an authenticated-user or auth-id expression. */
    public function containsAuth(Node $node): bool
    {
        return (new NodeFinder())->findFirst([$node], fn (Node $n): bool => $n instanceof Expr && ($this->isAuthUser($n) || $this->isAuthId($n))) !== null;
    }

    /** A chain rooted at the auth user whose first call is a relation and a later call is a read. */
    public function isRelationRead(Expr $outer): bool
    {
        $calls = [];
        $node = $outer;
        while (! $this->isAuthUser($node)) {
            if (! self::isCall($node)) {
                return false;
            }
            $name = self::name($node);
            if ($name === null) {
                return false;
            }
            array_unshift($calls, $name);
            $node = $node->var;
        }
        $relation = array_shift($calls);
        if ($relation === null || in_array($relation, [...self::READS, ...self::WRITES, ...self::NOT_RELATIONS], true) || str_starts_with($relation, 'where')) {
            return false;
        }
        foreach ($calls as $call) {
            if (in_array($call, self::READS, true) || str_starts_with($call, 'where')) {
                return true;
            }
        }

        return false;
    }

    /** `where|orWhere(col, [op,] <auth id>)` or `whereBelongsTo(<auth user>)`. */
    public function isWhereScope(Expr $expr): bool
    {
        if (! self::isCall($expr) && ! $expr instanceof Expr\StaticCall) {
            return false;
        }
        $args = self::args($expr);
        $name = self::name($expr);
        if ($name === 'wherebelongsto') {
            return isset($args[0]) && $this->isAuthUser($args[0]);
        }
        if ($name !== 'where' && $name !== 'orwhere') {
            return false;
        }
        $value = match (count($args)) {
            2 => $args[1],
            3 => $args[2],
            default => null,
        };

        return $value !== null && $this->isAuthId($value);
    }

    public function descendsFrom(?string $class, string $base): bool
    {
        $seen = [];
        while ($class !== null && ! isset($seen[$class])) {
            $class = ltrim($class, '\\');
            if ($class === $base) {
                return true;
            }
            $seen[$class] = true;
            $class = $this->symbols->getClass($class)?->parent;
        }

        return false;
    }

    public function isFormRequest(?string $class): bool
    {
        return $this->descendsFrom($class, self::FORM_REQUEST);
    }

    /** @phpstan-assert-if-true Expr\MethodCall|Expr\NullsafeMethodCall $expr */
    public static function isCall(Node $expr): bool
    {
        return $expr instanceof Expr\MethodCall || $expr instanceof Expr\NullsafeMethodCall;
    }

    /** Lower-cased identifier name of a method, static or function call. */
    public static function name(Node $expr): ?string
    {
        $name = match (true) {
            $expr instanceof Expr\MethodCall, $expr instanceof Expr\NullsafeMethodCall, $expr instanceof Expr\StaticCall => $expr->name,
            $expr instanceof Expr\FuncCall => $expr->name,
            default => null,
        };
        if ($name instanceof Node\Identifier || $name instanceof Node\Name) {
            return strtolower(ltrim($name->toString(), '\\'));
        }

        return null;
    }

    /** @return list<Expr> positional arguments; empty if any is named or unpacked */
    public static function args(Node $expr): array
    {
        if (! $expr instanceof Expr\CallLike || $expr->isFirstClassCallable()) {
            return [];
        }
        $out = [];
        foreach ($expr->getArgs() as $arg) {
            if ($arg->name !== null || $arg->unpack) {
                return [];
            }
            $out[] = $arg->value;
        }

        return $out;
    }

    public static function isAuthFacade(Node $class): bool
    {
        return $class instanceof Node\Name && in_array(ltrim($class->toString(), '\\'), self::AUTH_FACADES, true);
    }

    public static function isFunc(Node $expr, string $function): bool
    {
        return $expr instanceof Expr\FuncCall && self::name($expr) === $function;
    }

    // auth(), auth('x'), auth()->guard(..), Auth::guard(..)
    private static function isGuard(Node $expr): bool
    {
        if (self::isFunc($expr, 'auth')) {
            return true;
        }
        if ($expr instanceof Expr\StaticCall) {
            return self::isAuthFacade($expr->class) && self::name($expr) === 'guard';
        }

        return self::isCall($expr) && self::name($expr) === 'guard' && self::isFunc($expr->var, 'auth');
    }

    private function isRequestVariable(Expr $var): bool
    {
        if (! $var instanceof Expr\Variable || ! is_string($var->name)) {
            return false;
        }
        if ($var->name === 'this') {
            return $this->thisIsRequest;
        }
        $type = $this->paramTypes[$var->name] ?? null;

        return $var->name === 'request' || $this->descendsFrom($type, self::REQUEST) || $this->isFormRequest($type);
    }
}
