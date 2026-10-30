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

    public function __construct(SymbolTable $symbols, public readonly PathNode $node)
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

    private static function typeName(?Node $type): ?string
    {
        if ($type instanceof Node\NullableType) {
            return self::typeName($type->type);
        }

        return $type instanceof Node\Name ? ltrim($type->toString(), '\\') : null;
    }
}
