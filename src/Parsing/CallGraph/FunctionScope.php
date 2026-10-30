<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Parsing\CallGraph;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use TusharKhan\SemanticSec\Framework\Laravel\AuthExpressions;

/** @internal Variable facts about one function body, shared by TypeResolver lookups. */
final class FunctionScope
{
    /** @var array<int, string> spl id of an assigned value => its statement's `@var` type */
    private array $docTypes = [];

    /** @var array<string, ?string> "name\0pos" => resolved type */
    private array $memo = [];

    /**
     * @param  array<string, ?string>  $params  name => class type
     * @param  array<Stmt>  $body
     * @param  array<int, array<string, string>>  $docVars  statement start position => var => type
     * @param  array<string, true>  $scalarParams  parameters declared int, string or float
     */
    public function __construct(public readonly AuthExpressions $auth, public readonly array $params, private readonly array $body, array $docVars, public readonly array $scalarParams = [])
    {
        if ($docVars === []) {
            return;
        }
        foreach ((new \PhpParser\NodeFinder())->findInstanceOf($body, Stmt\Expression::class) as $stmt) {
            $assign = $stmt->expr;
            if ($assign instanceof Expr\Assign && $assign->var instanceof Expr\Variable && is_string($assign->var->name)
                && isset($docVars[$stmt->getStartFilePos()][$assign->var->name])) {
                $this->docTypes[spl_object_id($assign->expr)] = $docVars[$stmt->getStartFilePos()][$assign->var->name];
            }
        }
    }

    /**
     * The memoised type of a variable read; a read already being resolved gives null, so self-references stop.
     *
     * @param  callable(): ?string  $resolve
     */
    public function remember(string $key, callable $resolve): ?string
    {
        if (! array_key_exists($key, $this->memo)) {
            $this->memo[$key] = null;
            $this->memo[$key] = $resolve();
        }

        return $this->memo[$key];
    }

    public function docType(Expr $assignedValue): ?string
    {
        return $this->docTypes[spl_object_id($assignedValue)] ?? null;
    }

    // True when a plain `$name = …;` statement runs on every path to $pos.
    public function assignedUnconditionally(string $name, int $pos): bool
    {
        return self::dominates($this->body, $name, $pos);
    }

    /** @param array<Node> $stmts */
    private static function dominates(array $stmts, string $name, int $pos): bool
    {
        foreach ($stmts as $stmt) {
            if ($stmt->getStartFilePos() > $pos) {
                return false;
            }
            if ($stmt->getEndFilePos() < $pos) {
                if ($stmt instanceof Stmt\Expression && $stmt->expr instanceof Expr\Assign
                    && $stmt->expr->var instanceof Expr\Variable && $stmt->expr->var->name === $name) {
                    return true;
                }

                continue;
            }
            foreach (self::childLists($stmt) as $list) {
                if (self::dominates($list, $name, $pos)) {
                    return true;
                }
            }

            return false;
        }

        return false;
    }

    /** @return list<array<Node>> statement lists directly under a statement (bodies, else, catch, cases) */
    private static function childLists(Node $stmt): array
    {
        if ($stmt instanceof Node\FunctionLike || $stmt instanceof Stmt\ClassLike) {
            return [];
        }
        $out = [];
        foreach ($stmt->getSubNodeNames() as $sub) {
            $child = $stmt->$sub;
            if ($child instanceof Stmt) {
                $out[] = [$child];
            } elseif (is_array($child) && $child !== [] && array_filter($child, static fn ($c): bool => ! $c instanceof Stmt) === []) {
                $out[] = $child;
            }
        }

        return $out;
    }
}
