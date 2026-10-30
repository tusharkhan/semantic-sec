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
    public function __construct(array $body)
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

    /** True when nothing between the node and the body root can skip it. */
    public function isUnconditional(Node $node): bool
    {
        for ($child = $node, $parent = $this->parent($node); $parent !== null; $child = $parent, $parent = $this->parent($parent)) {
            if (self::isConditionalSlot($parent, $child)) {
                return false;
            }
        }

        return true;
    }

    /** True when the node's boolean result decides a branch, a guard, or (when $returns) the returned value. */
    public function isConditionPosition(Node $node, bool $returns): bool
    {
        $child = $node;
        $parent = $this->parent($child);
        while ($parent !== null && self::isGlue($parent, $child)) {
            $child = $parent;
            $parent = $this->parent($child);
        }

        return match (true) {
            $parent instanceof Stmt\If_, $parent instanceof Stmt\ElseIf_, $parent instanceof Stmt\While_,
            $parent instanceof Expr\Ternary, $parent instanceof Expr\Match_ => $parent->cond === $child,
            $parent instanceof Node\MatchArm => in_array($child, $parent->conds ?? [], true),
            $parent instanceof Node\Arg => $this->isGuardCondition($parent, $child),
            $parent instanceof Stmt\Return_ => $returns && $parent->expr === $child,
            default => false,
        };
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
        if ($parent instanceof Expr\BinaryOp\Identical || $parent instanceof Expr\BinaryOp\NotIdentical
            || $parent instanceof Expr\BinaryOp\Equal || $parent instanceof Expr\BinaryOp\NotEqual) {
            $other = $parent->left === $child ? $parent->right : $parent->left;

            return $other instanceof Expr\ConstFetch && in_array(strtolower($other->name->toString()), ['true', 'false'], true);
        }

        return false;
    }

    private static function isConditionalSlot(Node $parent, Node $child): bool
    {
        return match (true) {
            $parent instanceof Stmt\If_, $parent instanceof Stmt\ElseIf_, $parent instanceof Stmt\Else_,
            $parent instanceof Stmt\For_, $parent instanceof Stmt\Foreach_, $parent instanceof Stmt\While_,
            $parent instanceof Stmt\Do_, $parent instanceof Stmt\Case_, $parent instanceof Stmt\Catch_ => in_array($child, $parent->stmts, true),
            $parent instanceof Stmt\TryCatch => $parent->catches !== [] && in_array($child, $parent->stmts, true),
            $parent instanceof Node\MatchArm => $parent->body === $child,
            $parent instanceof Expr\Ternary => $parent->if === $child || $parent->else === $child,
            $parent instanceof Expr\BinaryOp\BooleanAnd, $parent instanceof Expr\BinaryOp\BooleanOr,
            $parent instanceof Expr\BinaryOp\LogicalAnd, $parent instanceof Expr\BinaryOp\LogicalOr,
            $parent instanceof Expr\BinaryOp\Coalesce => $parent->right === $child,
            $parent instanceof Expr\AssignOp\Coalesce => $parent->expr === $child,
            $parent instanceof Expr\Closure, $parent instanceof Expr\ArrowFunction, $parent instanceof Stmt\Function_,
            $parent instanceof Stmt\ClassMethod, $parent instanceof Stmt\Class_ => true,
            default => false,
        };
    }
}
