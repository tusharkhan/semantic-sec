<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Framework\Laravel;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use PhpParser\NodeFinder;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;

/** Recognises authenticated-user, auth-id, relation-read and where-scope expressions inside one action body. */
final class AuthExpressions
{
    public const READS = ['find', 'findorfail', 'findmany', 'first', 'firstorfail', 'firstwhere', 'sole', 'get', 'paginate', 'simplepaginate', 'cursorpaginate', 'cursor', 'exists', 'doesntexist', 'count', 'pluck', 'value'];

    public const WRITES = ['create', 'createmany', 'update', 'updateorcreate', 'firstorcreate', 'firstornew', 'save', 'savemany', 'delete', 'forcedelete', 'insert', 'upsert', 'attach', 'sync', 'detach', 'associate', 'increment', 'decrement', 'touch'];

    // Calls on the user that are not relations.
    private const NOT_RELATIONS = ['can', 'cannot', 'cant', 'getkey', 'tokencan', 'fresh', 'refresh', 'load', 'tojson', 'toarray', 'only', 'getattribute'];

    // Calls that leave the user's relation scope.
    private const SCOPE_RESETS = ['newquery', 'query', 'newmodelquery', 'replicate', 'getmodel', 'getrelated', 'newmodelinstance', 'make'];

    // Calls on the user that only tell whether someone is logged in.
    private const LOGIN_CALLS = ['check', 'guest', 'id', 'getkey', 'getauthidentifier'];

    private const AUTH_FACADES = ['Illuminate\\Support\\Facades\\Auth', 'Auth'];

    private const REQUEST = 'Illuminate\\Http\\Request';

    private const FORM_REQUEST = 'Illuminate\\Foundation\\Http\\FormRequest';

    /** @var array<string, list<array{int, Expr}>> var => [assignment end position, value] in source order */
    private array $assignments = [];

    /** @var array<string, true> variables written other than by a plain top-level assignment */
    private array $tainted = [];

    /**
     * @param  array<string, ?string>  $paramTypes  action parameter name => native type
     * @param  array<Node>  $body
     * @param  bool  $thisIsRequest  inside a FormRequest, where $this->user() is the authenticated user
     */
    public function __construct(private readonly SymbolTable $symbols, private readonly array $paramTypes, array $body, private readonly bool $thisIsRequest = false)
    {
        $visitor = new class () extends NodeVisitorAbstract {
            /** @var array<string, list<array{int, Expr}>> */
            public array $assignments = [];

            /** @var array<string, true> */
            public array $tainted = [];

            private int $depth = 0;

            public function enterNode(Node $node): null
            {
                if (self::opensScope($node)) {
                    $this->depth++;
                    foreach ($node instanceof Expr\Closure ? $node->uses : [] as $use) {
                        if ($use->byRef) {
                            $this->taint($use->var);
                        }
                    }
                }
                if ($node instanceof Expr\Assign) {
                    if ($this->depth === 0 && $node->var instanceof Expr\Variable && is_string($node->var->name)) {
                        $this->assignments[$node->var->name][] = [$node->getEndFilePos(), $node->expr];
                    } else {
                        $this->taint($node->var);
                    }
                } elseif ($node instanceof Expr\AssignRef) {
                    $this->taint($node->var);
                    $this->taint($node->expr);
                } elseif ($node instanceof Expr\AssignOp || $node instanceof Expr\PreInc || $node instanceof Expr\PostInc
                    || $node instanceof Expr\PreDec || $node instanceof Expr\PostDec) {
                    $this->taint($node->var);
                } elseif ($node instanceof Stmt\Foreach_) {
                    $this->taint($node->valueVar);
                    if ($node->keyVar !== null) {
                        $this->taint($node->keyVar);
                    }
                } elseif ($node instanceof Stmt\Global_ || $node instanceof Stmt\Unset_) {
                    foreach ($node->vars as $var) {
                        $this->taint($var);
                    }
                } elseif ($node instanceof Stmt\Static_) {
                    foreach ($node->vars as $var) {
                        $this->taint($var->var);
                    }
                } elseif ($node instanceof Stmt\Catch_ && $node->var !== null) {
                    $this->taint($node->var);
                }

                return null;
            }

            public function leaveNode(Node $node): null
            {
                if (self::opensScope($node)) {
                    $this->depth--;
                }

                return null;
            }

            private static function opensScope(Node $node): bool
            {
                return $node instanceof Expr\Closure || $node instanceof Expr\ArrowFunction || $node instanceof Stmt\Function_ || $node instanceof Stmt\ClassLike;
            }

            private function taint(Node $target): void
            {
                $vars = $target instanceof Expr\Variable ? [$target] : (new NodeFinder())->findInstanceOf([$target], Expr\Variable::class);
                foreach ($vars as $var) {
                    if (is_string($var->name)) {
                        $this->tainted[$var->name] = true;
                    }
                }
            }
        };
        (new NodeTraverser($visitor))->traverse($body);
        $this->assignments = $visitor->assignments;
        $this->tainted = $visitor->tainted;
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
        $values = $this->assignmentsBefore($name, $pos);

        return $values === [] ? null : $values[count($values) - 1];
    }

    /** True for an action parameter that is never reassigned or rebound before $pos. */
    public function isUntouchedParam(string $name, int $pos): bool
    {
        return $this->hasParam($name) && ! isset($this->tainted[$name]) && $this->lastAssignment($name, $pos) === null;
    }

    public function isAuthUser(Expr $expr): bool
    {
        if ($expr instanceof Expr\StaticCall) {
            return self::isAuthFacade($expr->class) && self::name($expr) === 'user';
        }
        if ($expr instanceof Expr\Variable) {
            return $this->variableIs($expr, $this->isAuthUser(...));
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
            return $this->variableIs($expr, $this->isAuthId(...));
        }
        if (! self::isCall($expr)) {
            return false;
        }
        $name = self::name($expr);

        return ($name === 'id' && self::isGuard($expr->var)) || ($name === 'getkey' && $this->isAuthUser($expr->var));
    }

    /** True when the subtree compares an auth-user or auth-id operand for (in)equality with something other than null/true/false. */
    public function comparesAuth(Node $node): bool
    {
        return (new NodeFinder())->findFirst([$node], fn (Node $n): bool => $n instanceof Expr && $this->isAuthComparison($n, null)) !== null;
    }

    /**
     * Whether a guard condition proves the user matches. *_unless want an equality ($equal), *_if an inequality;
     * `!` flips; unless(A && B) / if(A || B) need any operand, unless(A || B) / if(A && B) every operand.
     */
    public function guardQualifies(Expr $cond, bool $equal): bool
    {
        if ($cond instanceof Expr\BooleanNot) {
            return $this->guardQualifies($cond->expr, ! $equal);
        }
        $and = $cond instanceof Expr\BinaryOp\BooleanAnd || $cond instanceof Expr\BinaryOp\LogicalAnd;
        $or = $cond instanceof Expr\BinaryOp\BooleanOr || $cond instanceof Expr\BinaryOp\LogicalOr;
        if ($cond instanceof Expr\BinaryOp && ($and || $or)) {
            $left = $this->guardQualifies($cond->left, $equal);
            $right = $this->guardQualifies($cond->right, $equal);

            return $and === $equal ? ($left || $right) : ($left && $right);
        }

        return $this->isAuthComparison($cond, $equal);
    }

    /**
     * Login-only boolean expression (auth()->check(), $this->user() !== null, ...).
     *
     * @return bool|null true if it checks login, false if it is only literals, null if it does anything else
     */
    public function loginOnly(Expr $expr): ?bool
    {
        if ($expr instanceof Expr\BooleanNot) {
            return $this->loginOnly($expr->expr);
        }
        if ($expr instanceof Expr\BinaryOp\BooleanAnd || $expr instanceof Expr\BinaryOp\BooleanOr
            || $expr instanceof Expr\BinaryOp\LogicalAnd || $expr instanceof Expr\BinaryOp\LogicalOr) {
            $left = $this->loginOnly($expr->left);
            $right = $this->loginOnly($expr->right);

            return $left === null || $right === null ? null : $left || $right;
        }
        if (self::isConst($expr, ['true', 'false'])) {
            return false;
        }
        if ($expr instanceof Expr\Cast\Bool_) {
            return $this->isAuthUser($expr->expr) ? true : null;
        }
        if ($this->isAuthUser($expr)) {
            return true;
        }
        if (self::isFunc($expr, 'is_null')) {
            $args = self::args($expr);

            return count($args) === 1 && $this->isAuth($args[0]) ? true : null;
        }
        if ($expr instanceof Expr\BinaryOp\Identical || $expr instanceof Expr\BinaryOp\NotIdentical
            || $expr instanceof Expr\BinaryOp\Equal || $expr instanceof Expr\BinaryOp\NotEqual) {
            return ($this->isAuth($expr->left) && self::isConst($expr->right, ['null'])) || ($this->isAuth($expr->right) && self::isConst($expr->left, ['null'])) ? true : null;
        }
        $name = self::name($expr);
        if ($expr instanceof Expr\StaticCall) {
            return self::isAuthFacade($expr->class) && in_array($name, ['check', 'guest'], true) ? true : null;
        }

        return self::isCall($expr) && in_array($name, ['check', 'guest'], true) && self::isGuard($expr->var) ? true : null;
    }

    /** A method call on the authenticated user other than a login check or an ability call (->isAdmin(), ->hasRole()). */
    public function isRoleCall(Expr $expr): bool
    {
        return self::isCall($expr) && ! in_array(self::name($expr), [...self::LOGIN_CALLS, 'can', 'cannot', 'cant'], true) && $this->isAuthUser($expr->var);
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
        if (array_intersect($calls, self::SCOPE_RESETS) !== []) {
            return false;
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

    /** `where(col, [=,] <auth id>)` or `whereBelongsTo(<auth user>)`. */
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
        if ($name !== 'where') {
            return false;
        }
        $value = match (count($args)) {
            2 => $args[1],
            3 => $args[1] instanceof Node\Scalar\String_ && $args[1]->value === '=' ? $args[2] : null,
            default => null,
        };

        return $value !== null && $this->isAuthId($value);
    }

    public static function isFormRequest(SymbolTable $symbols, ?string $class): bool
    {
        return Ancestry::descendsFrom($symbols, $class, [self::FORM_REQUEST]);
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

    /** @return list<Expr> */
    private function assignmentsBefore(string $name, int $pos): array
    {
        $found = [];
        foreach ($this->assignments[$name] ?? [] as [$end, $value]) {
            if ($end < $pos) {
                $found[] = $value;
            }
        }

        return $found;
    }

    /**
     * A variable is an auth expression only when every earlier assignment is one and nothing else writes it.
     *
     * @param  callable(Expr): bool  $test
     */
    private function variableIs(Expr\Variable $var, callable $test): bool
    {
        if (! is_string($var->name) || $var->name === 'this' || isset($this->tainted[$var->name])) {
            return false;
        }
        $values = $this->assignmentsBefore($var->name, $var->getStartFilePos());
        foreach ($values as $value) {
            if (! $test($value)) {
                return false;
            }
        }

        return $values !== [];
    }

    /** An (in)equality between an auth operand and a non-literal; a null $equal accepts either polarity. */
    private function isAuthComparison(Expr $n, ?bool $equal): bool
    {
        $isEqual = $n instanceof Expr\BinaryOp\Identical || $n instanceof Expr\BinaryOp\Equal;
        $isNotEqual = $n instanceof Expr\BinaryOp\NotIdentical || $n instanceof Expr\BinaryOp\NotEqual;
        if (! $n instanceof Expr\BinaryOp || ! ($isEqual || $isNotEqual) || ($equal !== null && $equal !== $isEqual)) {
            return false;
        }

        return ($this->isAuth($n->left) && ! self::isLiteral($n->right)) || ($this->isAuth($n->right) && ! self::isLiteral($n->left));
    }

    // A null/true/false comparison only checks that someone is logged in.
    private static function isLiteral(Expr $expr): bool
    {
        return self::isConst($expr, ['null', 'true', 'false']);
    }

    /** @param list<string> $names */
    private static function isConst(Expr $expr, array $names): bool
    {
        return $expr instanceof Expr\ConstFetch && in_array(strtolower($expr->name->toString()), $names, true);
    }

    private function isAuth(Expr $expr): bool
    {
        return $this->isAuthUser($expr) || $this->isAuthId($expr);
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

        return $var->name === 'request' || Ancestry::descendsFrom($this->symbols, $this->paramTypes[$var->name] ?? null, [self::REQUEST, self::FORM_REQUEST]);
    }
}
