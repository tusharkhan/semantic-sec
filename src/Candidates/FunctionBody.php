<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Candidates;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\NodeFinder;
use TusharKhan\SemanticSec\Framework\Laravel\AuthExpressions;
use TusharKhan\SemanticSec\Framework\Laravel\BodyPositions;
use TusharKhan\SemanticSec\Parsing\CallGraph\PathNode;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;

/** @internal One function body on an execution path: statements, variable facts, positions and calls. */
final class FunctionBody
{
    /** @var array<Node> */
    public readonly array $stmts;

    public readonly AuthExpressions $auth;

    public readonly BodyPositions $positions;

    /** @var list<Expr\MethodCall|Expr\NullsafeMethodCall|Expr\StaticCall|Expr\FuncCall|Expr\New_> */
    public readonly array $calls;

    /** @var array<string, ?string> parameter name => native class type */
    public readonly array $params;

    /** @var array<string, list<Expr\Assign|Expr\AssignOp|Expr\AssignRef>>|null variable name => assignments to it, built on first use */
    private ?array $assignments = null;

    public function __construct(SymbolTable $symbols, PathNode $node)
    {
        $fn = $node->closure ?? $node->method?->node;
        $this->stmts = match (true) {
            $fn === null => [],
            $fn instanceof Expr\ArrowFunction => [$fn->expr],
            default => $fn->getStmts() ?? [],
        };
        $params = [];
        foreach ($fn === null ? [] : $fn->getParams() as $param) {
            if ($param->var instanceof Expr\Variable && is_string($param->var->name)) {
                $params[$param->var->name] = self::typeName($param->type);
            }
        }
        $this->params = $params;
        $this->auth = new AuthExpressions($symbols, $params, $this->stmts, AuthExpressions::isFormRequest($symbols, $node->method?->class));
        $this->positions = new BodyPositions($this->stmts);
        $calls = [];
        foreach ((new NodeFinder())->find($this->stmts, static fn (Node $n): bool => $n instanceof Expr\MethodCall || $n instanceof Expr\NullsafeMethodCall
            || $n instanceof Expr\StaticCall || $n instanceof Expr\FuncCall || $n instanceof Expr\New_) as $call) {
            \assert($call instanceof Expr\MethodCall || $call instanceof Expr\NullsafeMethodCall || $call instanceof Expr\StaticCall || $call instanceof Expr\FuncCall || $call instanceof Expr\New_);
            $calls[] = $call;
        }
        $this->calls = $calls;
    }

    /** @return list<Expr\Assign|Expr\AssignOp|Expr\AssignRef> every plain, compound or reference assignment to $name */
    public function assignmentsTo(string $name): array
    {
        if ($this->assignments === null) {
            $this->assignments = [];
            foreach ((new NodeFinder())->find($this->stmts, static fn (Node $n): bool => ($n instanceof Expr\Assign || $n instanceof Expr\AssignOp || $n instanceof Expr\AssignRef)
                && $n->var instanceof Expr\Variable && is_string($n->var->name)) as $assign) {
                \assert(($assign instanceof Expr\Assign || $assign instanceof Expr\AssignOp || $assign instanceof Expr\AssignRef) && $assign->var instanceof Expr\Variable && is_string($assign->var->name));
                $this->assignments[$assign->var->name][] = $assign;
            }
        }

        return $this->assignments[$name] ?? [];
    }

    private static function typeName(?Node $type): ?string
    {
        if ($type instanceof Node\NullableType) {
            return self::typeName($type->type);
        }

        return $type instanceof Node\Name ? ltrim($type->toString(), '\\') : null;
    }
}
