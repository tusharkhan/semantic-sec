<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Framework\Laravel;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;

/** Answers whether a node in one action body always runs, and whether its value is enforced as a condition. */
final class BodyPositions
{
    private const GUARDS = ['abort_if', 'abort_unless', 'throw_if', 'throw_unless'];

    /** @var array<int, Node> child object id => parent */
    private array $parents = [];

    /** @param array<Node> $body */
    public function __construct(private readonly array $body)
    {
        $visitor = new class () extends NodeVisitorAbstract {
            /** @var array<int, Node> */
            public array $parents = [];

            /** @var list<Node> */
            private array $stack = [];

            public function enterNode(Node $node): null
            {
                $top = $this->stack[count($this->stack) - 1] ?? null;
                if ($top !== null) {
                    $this->parents[spl_object_id($node)] = $top;
                }
                $this->stack[] = $node;

                return null;
            }

            public function leaveNode(Node $node): null
            {
                array_pop($this->stack);

                return null;
            }
        };
        (new NodeTraverser($visitor))->traverse($body);
        $this->parents = $visitor->parents;
    }

    public function parent(Node $node): ?Node
    {
        return $this->parents[spl_object_id($node)] ?? null;
    }

    /**
     * True when nothing between the node and the body root can skip it, including an earlier early-return `if`.
     * $judged: the node is a leaf the any/every rule judges (a non-throwing ability call), so a short-circuited
     * operand inside a condition is left to that rule.
     */
    public function isUnconditional(Node $node, bool $judged = false): bool
    {
        for ($child = $node, $parent = $this->parent($node); ; $child = $parent, $parent = $this->parent($parent)) {
            $siblings = $parent === null ? $this->body : (property_exists($parent, 'stmts') && is_array($parent->stmts) ? $parent->stmts : []);
            if (self::bypassedBefore($siblings, $child)) {
                return false;
            }
            if ($parent === null) {
                return true;
            }
            if ($this->isConditionalSlot($parent, $child, $judged)) {
                return false;
            }
        }
    }

    /**
     * True when the node's boolean result decides a branch, a guard, or (when $returns) the returned value.
     * Through && / || a branch never counts (polarity unknown); a guard or return applies F4's any/every rule,
     * asking $leaf whether each other operand qualifies.
     *
     * @param  (callable(Expr, bool): bool)|null  $leaf  operand, whether true must mean "allowed"
     * @param  ?bool  $trueAllows  set for a non-throwing ability call: an `if` it decides must then gate a blocking path
     */
    public function isConditionPosition(Node $node, bool $returns, ?callable $leaf = null, ?bool $trueAllows = null): bool
    {
        $found = $this->conditionRoot($node);
        if ($found === null) {
            return false;
        }
        [$root, $slot, $compound] = $found;
        if ($slot instanceof Stmt\Return_ && ! $returns) {
            return false;
        }
        if ($slot instanceof Node\Arg || $slot instanceof Stmt\Return_) {
            if ($leaf === null) {
                return ! $compound;
            }
            // return true and *_unless(true) mean "allowed"; *_if(true) means "denied".
            $guard = $this->parent($slot);
            $allow = $slot instanceof Stmt\Return_ || ($guard !== null && str_ends_with((string) AuthExpressions::name($guard), '_unless'));

            return $root instanceof Expr && $this->decides($root, $allow, $leaf);
        }
        if ($slot instanceof Stmt\If_ && $trueAllows !== null && ! $compound) {
            return $this->ifBlocks($slot, $this->polarity($node, $root) === $trueAllows);
        }

        return ! $compound;
    }

    // Whether the condition is true exactly when the node is true, through `!`, `(bool)` and true/false comparisons.
    private function polarity(Node $node, Node $root): bool
    {
        $same = true;
        for ($child = $node; $child !== $root && ($parent = $this->parent($child)) !== null; $child = $parent) {
            if ($parent instanceof Expr\BooleanNot) {
                $same = ! $same;
            } elseif ($parent instanceof Expr\BinaryOp && ($literal = self::boolLiteralSide($parent)) !== null) {
                $equal = $parent instanceof Expr\BinaryOp\Identical || $parent instanceof Expr\BinaryOp\Equal;
                $same = $same === ($equal === $literal[1]);
            }
        }

        return $same;
    }

    /** True when the denied path of the `if` blocks: its body when a true condition means denied, else its other branches or what follows it. */
    private function ifBlocks(Stmt\If_ $if, bool $trueAllows): bool
    {
        if (! $trueAllows) {
            return self::blocks($if->stmts);
        }
        if ($if->else !== null) {
            foreach ([...array_map(static fn (Stmt\ElseIf_ $e): array => $e->stmts, $if->elseifs), $if->else->stmts] as $stmts) {
                if (! self::blocks($stmts)) {
                    return false;
                }
            }

            return true;
        }
        if ($if->elseifs !== [] || ! self::leaves($if->stmts)) {
            return false;
        }
        $parent = $this->parent($if);
        $siblings = $parent === null ? $this->body : (property_exists($parent, 'stmts') && is_array($parent->stmts) ? $parent->stmts : []);
        $after = array_slice($siblings, (int) array_search($if, $siblings, true) + 1);
        foreach ($after as $stmt) {
            if (self::isBlocking($stmt)) {
                return true;
            }
            if (self::hasBypass($stmt)) {
                return false;
            }
        }

        return false;
    }

    /** @param array<Node> $stmts */
    private static function blocks(array $stmts): bool
    {
        foreach ($stmts as $stmt) {
            if (self::isBlocking($stmt)) {
                return true;
            }
        }

        return false;
    }

    /** @param array<Node> $stmts */
    private static function leaves(array $stmts): bool
    {
        foreach ($stmts as $stmt) {
            if ($stmt instanceof Stmt\Return_ || self::isBlocking($stmt)) {
                return true;
            }
        }

        return false;
    }

    // abort(..), abort_if/unless, throw, exit, or a return of an error response or redirect.
    private static function isBlocking(Node $stmt): bool
    {
        if ($stmt instanceof Stmt\Return_) {
            $root = $stmt->expr;
            while ($root !== null && AuthExpressions::isCall($root)) {
                $root = $root->var;
            }

            return self::isErrorValue($stmt->expr) || ($root instanceof Expr\FuncCall && in_array(AuthExpressions::name($root), ['redirect', 'to_route', 'back'], true));
        }
        if (! $stmt instanceof Stmt\Expression) {
            return false;
        }
        $expr = $stmt->expr;

        return $expr instanceof Expr\Throw_ || $expr instanceof Expr\Exit_
            || ($expr instanceof Expr\FuncCall && in_array(AuthExpressions::name($expr), ['abort', 'abort_if', 'abort_unless'], true));
    }

    /** @param callable(Expr, bool): bool $leaf */
    private function decides(Expr $e, bool $allow, callable $leaf): bool
    {
        if ($e instanceof Expr\BooleanNot) {
            return $this->decides($e->expr, ! $allow, $leaf);
        }
        if ($e instanceof Expr\Cast\Bool_) {
            return $this->decides($e->expr, $allow, $leaf);
        }
        $and = $e instanceof Expr\BinaryOp\BooleanAnd || $e instanceof Expr\BinaryOp\LogicalAnd;
        $or = $e instanceof Expr\BinaryOp\BooleanOr || $e instanceof Expr\BinaryOp\LogicalOr;
        if ($e instanceof Expr\BinaryOp && ($and || $or)) {
            $left = $this->decides($e->left, $allow, $leaf);
            $right = $this->decides($e->right, $allow, $leaf);

            return $and === $allow ? ($left || $right) : ($left && $right);
        }
        if ($e instanceof Expr\BinaryOp && ($literal = self::boolLiteralSide($e)) !== null) {
            [$other, $true] = $literal;
            $equal = $e instanceof Expr\BinaryOp\Identical || $e instanceof Expr\BinaryOp\Equal;

            return $this->decides($other, $equal === $true ? $allow : ! $allow, $leaf);
        }

        return $leaf($e, $allow);
    }

    /** @return array{Expr, bool}|null the non-literal side and whether the literal is true */
    private static function boolLiteralSide(Expr\BinaryOp $e): ?array
    {
        if (! ($e instanceof Expr\BinaryOp\Identical || $e instanceof Expr\BinaryOp\NotIdentical
            || $e instanceof Expr\BinaryOp\Equal || $e instanceof Expr\BinaryOp\NotEqual)) {
            return null;
        }
        foreach ([[$e->left, $e->right], [$e->right, $e->left]] as [$lit, $other]) {
            if ($lit instanceof Expr\ConstFetch && in_array($name = strtolower($lit->name->toString()), ['true', 'false'], true)) {
                return [$other, $name === 'true'];
            }
        }

        return null;
    }

    /** @return array{Node, Node, bool}|null the condition root, its slot, and whether && / || was crossed */
    private function conditionRoot(Node $node): ?array
    {
        $child = $node;
        $compound = false;
        $parent = $this->parent($child);
        while ($parent !== null && self::isGlue($parent, $child)) {
            $compound = $compound || $parent instanceof Expr\BinaryOp\BooleanAnd || $parent instanceof Expr\BinaryOp\BooleanOr
                || $parent instanceof Expr\BinaryOp\LogicalAnd || $parent instanceof Expr\BinaryOp\LogicalOr;
            $child = $parent;
            $parent = $this->parent($child);
        }
        $isSlot = match (true) {
            $parent instanceof Stmt\If_, $parent instanceof Stmt\ElseIf_, $parent instanceof Stmt\While_,
            $parent instanceof Expr\Ternary, $parent instanceof Expr\Match_ => $parent->cond === $child,
            $parent instanceof Node\MatchArm => in_array($child, $parent->conds ?? [], true),
            $parent instanceof Node\Arg => $this->isGuardCondition($parent, $child),
            $parent instanceof Stmt\Return_ => $parent->expr === $child,
            default => false,
        };

        return $isSlot ? [$child, $parent, $compound] : null;
    }

    /**
     * An earlier sibling statement that returns a non-error value (or exits) anywhere inside lets a request skip what follows.
     *
     * @param  array<Node>  $siblings
     */
    private static function bypassedBefore(array $siblings, Node $child): bool
    {
        // Only statements before the child in its own list; an `if` condition never sees its own body.
        if (! in_array($child, $siblings, true)) {
            return false;
        }
        foreach ($siblings as $stmt) {
            if ($stmt === $child) {
                return false;
            }
            if (self::hasBypass($stmt)) {
                return true;
            }
        }

        return false;
    }

    // A non-error return or exit anywhere inside the node, outside nested functions and classes.
    private static function hasBypass(Node $node): bool
    {
        if (($node instanceof Stmt\Return_ && ! self::isErrorValue($node->expr)) || $node instanceof Expr\Exit_) {
            return true;
        }
        if ($node instanceof Expr\Closure || $node instanceof Expr\ArrowFunction || $node instanceof Stmt\Function_ || $node instanceof Stmt\ClassLike) {
            return false;
        }
        foreach ($node->getSubNodeNames() as $name) {
            foreach (is_array($node->$name) ? $node->$name : [$node->$name] as $sub) {
                if ($sub instanceof Node && self::hasBypass($sub)) {
                    return true;
                }
            }
        }

        return false;
    }

    // abort(..), response(.., 4xx/5xx) or redirect()/to_route() to login; anything else is a normal response.
    private static function isErrorValue(?Expr $expr): bool
    {
        if ($expr === null) {
            return false;
        }
        $calls = [];
        for ($node = $expr; AuthExpressions::isCall($node); $node = $node->var) {
            $calls[] = $node;
        }
        $calls[] = $node;
        $root = AuthExpressions::name($node);
        if ($node instanceof Expr\FuncCall && $root === 'abort') {
            return true;
        }
        if ($node instanceof Expr\FuncCall && in_array($root, ['response', 'redirect', 'to_route'], true)) {
            foreach ($calls as $call) {
                foreach (AuthExpressions::args($call) as $arg) {
                    if ($root === 'response' && $arg instanceof Node\Scalar\Int_ && $arg->value >= 400) {
                        return true;
                    }
                    if ($root !== 'response' && $arg instanceof Node\Scalar\String_ && str_contains(strtolower($arg->value), 'login')) {
                        return true;
                    }
                }
                if ($root === 'redirect' && AuthExpressions::name($call) === 'guest') {
                    return true;
                }
            }
        }

        return false;
    }

    private function isGuardCondition(Node\Arg $arg, Node $child): bool
    {
        $call = $this->parent($arg);

        return $arg->value === $child && $call instanceof Expr\FuncCall && ($call->args[0] ?? null) === $arg
            && in_array(AuthExpressions::name($call), self::GUARDS, true);
    }

    // Operators that pass a boolean through to the enclosing condition.
    private static function isGlue(Node $parent, Node $child): bool
    {
        if ($parent instanceof Expr\BooleanNot || $parent instanceof Expr\Cast\Bool_
            || $parent instanceof Expr\BinaryOp\BooleanAnd || $parent instanceof Expr\BinaryOp\BooleanOr
            || $parent instanceof Expr\BinaryOp\LogicalAnd || $parent instanceof Expr\BinaryOp\LogicalOr) {
            return true;
        }

        return $parent instanceof Expr\BinaryOp && (self::boolLiteralSide($parent)[0] ?? null) === $child;
    }

    private function isConditionalSlot(Node $parent, Node $child, bool $judged): bool
    {
        return match (true) {
            $parent instanceof Stmt\If_ => in_array($child, $parent->stmts, true) || in_array($child, $parent->elseifs, true) || $parent->else === $child,
            $parent instanceof Stmt\ElseIf_, $parent instanceof Stmt\Else_,
            $parent instanceof Stmt\For_, $parent instanceof Stmt\Foreach_, $parent instanceof Stmt\While_,
            $parent instanceof Stmt\Do_, $parent instanceof Stmt\Case_, $parent instanceof Stmt\Catch_ => in_array($child, $parent->stmts, true),
            $parent instanceof Stmt\TryCatch => $parent->catches !== [] && in_array($child, $parent->stmts, true),
            // Only the first arm's conditions always evaluate.
            $parent instanceof Expr\Match_ => $child instanceof Node\MatchArm && array_search($child, $parent->arms, true) !== 0,
            $parent instanceof Node\MatchArm => $parent->body === $child || (int) array_search($child, $parent->conds ?? [], true) > 0,
            $parent instanceof Expr\Ternary => $parent->if === $child || $parent->else === $child,
            // A short-circuited operand is conditional, unless it is a judged leaf inside a condition.
            $parent instanceof Expr\BinaryOp\BooleanAnd, $parent instanceof Expr\BinaryOp\BooleanOr,
            $parent instanceof Expr\BinaryOp\LogicalAnd, $parent instanceof Expr\BinaryOp\LogicalOr => $parent->right === $child && ! ($judged && $this->conditionRoot($parent) !== null),
            $parent instanceof Expr\BinaryOp\Coalesce => $parent->right === $child,
            $parent instanceof Expr\AssignOp\Coalesce => $parent->expr === $child,
            $parent instanceof Expr\Closure, $parent instanceof Expr\ArrowFunction, $parent instanceof Stmt\Function_,
            $parent instanceof Stmt\ClassMethod, $parent instanceof Stmt\Class_ => true,
            default => false,
        };
    }
}
