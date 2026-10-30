<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Parsing\CallGraph;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor;
use PhpParser\NodeVisitorAbstract;
use PhpParser\PrettyPrinter\Standard;
use TusharKhan\SemanticSec\Framework\Laravel\BodyPositions;
use TusharKhan\SemanticSec\Framework\Laravel\RouteEntry;
use TusharKhan\SemanticSec\Parsing\Symbols\MethodSymbol;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;

/** Breadth-first execution path from a route action (SPEC §8); targets come from static types only, never guesses. */
final class CallGraphBuilder
{
    private const FACADE = 'Illuminate\\Support\\Facades\\Facade';

    private const FACADE_NAMESPACE = 'Illuminate\\Support\\Facades\\';

    private const DYNAMIC_FUNCTIONS = ['call_user_func', 'call_user_func_array', 'forward_static_call', 'forward_static_call_array'];

    private const MAX_TEXT = 160;

    private readonly Standard $printer;

    /** @var list<array{prefix: string, file: string, line: int, text: string, suffix: string}> */
    private array $records = [];

    /** @var array<int, int> spl id of a recorded call => its record index */
    private array $recordOf = [];

    /** @var array<int, BodyPositions> spl id of a nested function => positions of its own body */
    private array $nestedPositions = [];

    /** @param array<string, ?string> $facadeMap facade name or FQN => facade id like "facade:Auth" */
    public function __construct(
        private readonly SymbolTable $symbols,
        private readonly TypeResolver $types,
        private readonly array $facadeMap,
        private readonly int $maxDepth,
    ) {
        $this->printer = new Standard();
    }

    public function build(RouteEntry $route): ExecutionPath
    {
        $this->records = [];
        $entry = $this->entry($route);
        $nodes = [$entry];
        $visited = [$entry->id => true];
        for ($i = 0; $i < count($nodes); $i++) {
            $node = $nodes[$i];
            if ($node->depth >= $this->maxDepth) {
                continue;
            }
            foreach ($this->callees($node) as [$method, $receiver, $site]) {
                $id = $method->id();
                if (isset($visited[$id])) {
                    continue;
                }
                $visited[$id] = true;
                $bound = $receiver !== null && $receiver !== $method->class ? $receiver : null;
                $nodes[] = new PathNode($id, $method, null, $method->file, $method->startLine, $method->endLine, $node->depth + 1, $site, $node->id, $bound);
            }
        }
        $unresolved = array_map(static fn (array $r): string => sprintf('%s%s:%d: %s%s', $r['prefix'], $r['file'], $r['line'], $r['text'], $r['suffix']), $this->records);
        $this->records = [];

        return new ExecutionPath($nodes, array_values(array_unique($unresolved)));
    }

    private function entry(RouteEntry $route): PathNode
    {
        $action = $route->action;
        if ($action->closure instanceof Node\FunctionLike) {
            $closure = $action->closure;
            $id = sprintf('closure@%s:%d', $route->file, $closure->getStartLine());

            return new PathNode($id, null, $closure, $route->file, $closure->getStartLine(), $closure->getEndLine(), 0, null, null);
        }
        $method = $action->class !== null && $action->method !== null ? $this->symbols->findMethod($action->class, $action->method) : null;
        if ($method !== null) {
            $bound = ltrim($action->class, '\\');

            return new PathNode($method->id(), $method, null, $method->file, $method->startLine, $method->endLine, 0, null, null, $bound !== $method->class ? $bound : null);
        }
        $symbol = $action->symbol() ?? ($action->class ?? '?').'::'.($action->method ?? '?');
        $this->records[] = ['prefix' => '', 'file' => $route->file, 'line' => $route->line, 'text' => 'action '.$symbol.' not found', 'suffix' => ''];

        return new PathNode($symbol, null, null, $route->file, $route->line, $route->line, 0, null, null);
    }

    /** @return list<array{MethodSymbol, ?string, CallSite}> resolved callees in source order, with the class `$this` is bound to */
    private function callees(PathNode $node): array
    {
        $fn = $node->closure ?? $node->method?->node;
        if ($fn === null) {
            return [];
        }
        $this->recordOf = [];
        $this->nestedPositions = [];
        $stmts = $fn->getStmts() ?? [];
        $positions = new BodyPositions($stmts);
        $out = [];
        foreach (self::calls($stmts) as $call) {
            $target = $this->resolve($call, $node, $positions);
            if ($target !== null) {
                $out[] = [$target[0], $target[1], new CallSite($node->file, $call->getStartLine(), $this->isConditional($call, $positions))];
            }
        }

        return $out;
    }

    /**
     * Calls in evaluation order (inner before outer), including nested closures but not nested classes or functions.
     *
     * @param  array<Node>  $stmts
     * @return list<Expr\CallLike>
     */
    private static function calls(array $stmts): array
    {
        $visitor = new class () extends NodeVisitorAbstract {
            /** @var list<Expr\CallLike> */
            public array $calls = [];

            public function enterNode(Node $node): ?int
            {
                return $node instanceof Stmt\ClassLike || $node instanceof Stmt\Function_ ? NodeVisitor::DONT_TRAVERSE_CHILDREN : null;
            }

            public function leaveNode(Node $node): null
            {
                if ($node instanceof Expr\MethodCall || $node instanceof Expr\NullsafeMethodCall || $node instanceof Expr\StaticCall || $node instanceof Expr\FuncCall) {
                    $this->calls[] = $node;
                }

                return null;
            }
        };
        (new NodeTraverser($visitor))->traverse($stmts);

        return $visitor->calls;
    }

    /** @return array{MethodSymbol, ?string}|null the method to traverse and the class `$this` is bound to, or null after recording why not */
    private function resolve(Expr\CallLike $call, PathNode $node, BodyPositions $positions): ?array
    {
        if ($call instanceof Expr\FuncCall) {
            $name = $call->name instanceof Node\Name ? strtolower($call->name->getLast()) : null;
            if ($name === null || in_array($name, self::DYNAMIC_FUNCTIONS, true)) {
                $this->record($call, $node, 'dynamic call');
            }

            return null;
        }
        if ($call instanceof Expr\StaticCall) {
            return $this->resolveStatic($call, $node, $positions);
        }
        if (! $call instanceof Expr\MethodCall && ! $call instanceof Expr\NullsafeMethodCall) {
            return null;
        }
        if (! $call->name instanceof Node\Identifier) {
            $this->record($call, $node, 'dynamic call');

            return null;
        }
        $class = $this->types->typeOf($call->var, $this->contextFor($call->var, $call, $node, $positions));
        if ($class === null) {
            $this->recordUnknown($call, $call->var, $node);

            return null;
        }
        // $this inside a method reached through a subclass is bound to that subclass.
        $isThis = $call->var instanceof Expr\Variable && $call->var->name === 'this';
        if ($isThis && $node->closureClass !== null && $this->symbols->isSubclassOf($node->closureClass, $class)) {
            $class = $node->closureClass;
        }

        return $this->lookup($call, $node, $class, $call->name->toString(), $class);
    }

    /** @return array{MethodSymbol, ?string}|null */
    private function resolveStatic(Expr\StaticCall $call, PathNode $node, BodyPositions $positions): ?array
    {
        if (! $call->class instanceof Node\Name || ! $call->name instanceof Node\Identifier) {
            $this->record($call, $node, 'dynamic call');

            return null;
        }
        $name = $call->name->toString();
        $keyword = $call->class->toLowerString();
        if (in_array($keyword, ['self', 'static', 'parent'], true)) {
            $bound = $this->boundClass($node, $call, $positions);
            $self = $node->method !== null && $this->symbols->getClass($node->method->class)?->kind !== 'trait' ? $node->method->class : $bound;
            $class = match ($keyword) {
                'self' => $self,
                'static' => $bound,
                default => $self === null ? null : $this->symbols->getClass($self)?->parent,
            };
            if ($class === null) {
                $this->record($call, $node, 'receiver type unknown');

                return null;
            }

            return $this->lookup($call, $node, ltrim($class, '\\'), $name, $bound ?? $class);
        }
        $class = ltrim($call->class->toString(), '\\');
        $facade = $this->facade($class);
        if ($facade !== null) {
            $this->recordOf[spl_object_id($call)] = count($this->records);
            $this->records[] = ['prefix' => 'facade:'.$facade.' ', 'file' => $node->file, 'line' => $call->getStartLine(), 'text' => $this->print($call), 'suffix' => ''];

            return null;
        }

        return $this->lookup($call, $node, $class, $name, $class);
    }

    /** @return array{MethodSymbol, ?string}|null */
    private function lookup(Expr\CallLike $call, PathNode $node, string $class, string $name, ?string $receiver): ?array
    {
        $symbol = $this->symbols->getClass($class);
        if ($symbol === null) {
            $this->record($call, $node, $class.' is not in the project');

            return null;
        }
        $method = $this->symbols->findMethod($class, $name);
        if ($symbol->kind === 'interface' || ($method !== null && $method->node->stmts === null)) {
            $impls = $this->symbols->implementations($class);
            sort($impls);
            if (count($impls) !== 1) {
                $this->record($call, $node, $impls === []
                    ? 'no implementation of '.$class.' in the project'
                    : sprintf('%s has %d implementations: %s', $class, count($impls), implode(', ', $impls)));

                return null;
            }
            $impl = $this->symbols->findMethod($impls[0], $name);
            if ($impl === null || $impl->node->stmts === null) {
                $this->record($call, $node, $impls[0].'::'.$name.' not found');

                return null;
            }
            $this->records[] = ['prefix' => '', 'file' => $node->file, 'line' => $call->getStartLine(), 'text' => $this->print($call), 'suffix' => ' → assumed sole implementation '.$impls[0]];

            return [$impl, $impls[0]];
        }
        if ($method === null) {
            $this->record($call, $node, $class.'::'.$name.' not found');

            return null;
        }
        if (str_starts_with($method->file, 'vendor/')) {
            $this->record($call, $node, $method->class.' is not in the project');

            return null;
        }

        return [$method, $receiver];
    }

    // An unknown receiver that is itself a recorded call extends that record to the whole chain.
    private function recordUnknown(Expr\CallLike $call, Expr $receiver, PathNode $node): void
    {
        $index = $this->recordOf[spl_object_id($receiver)] ?? null;
        if ($index === null) {
            $this->record($call, $node, 'receiver type unknown');

            return;
        }
        $this->records[$index]['text'] = $this->print($call);
        $this->recordOf[spl_object_id($call)] = $index;
    }

    private function record(Expr\CallLike $call, PathNode $node, string $reason): void
    {
        $this->recordOf[spl_object_id($call)] = count($this->records);
        $this->records[] = ['prefix' => '', 'file' => $node->file, 'line' => $call->getStartLine(), 'text' => $this->print($call), 'suffix' => ' → '.$reason];
    }

    private function print(Expr $expr): string
    {
        $text = (string) preg_replace('/\s+/', ' ', $this->printer->prettyPrintExpr($expr));

        return mb_strlen($text) > self::MAX_TEXT ? mb_substr($text, 0, self::MAX_TEXT - 1).'…' : $text;
    }

    // The facade's short name when $class is one; never a class to traverse.
    private function facade(string $class): ?string
    {
        if (array_key_exists($class, $this->facadeMap)) {
            $id = $this->facadeMap[$class];

            return $id !== null && str_starts_with($id, 'facade:') ? substr($id, 7) : self::shortName($class);
        }
        if (str_starts_with($class, self::FACADE_NAMESPACE) || $this->symbols->isSubclassOf($class, self::FACADE)) {
            return self::shortName($class);
        }

        return null;
    }

    private static function shortName(string $class): string
    {
        $pos = strrpos($class, '\\');

        return $pos === false ? $class : substr($class, $pos + 1);
    }

    // The class `$this` is bound to at the call, through any enclosing closures.
    private function boundClass(PathNode $node, Node $at, BodyPositions $positions): ?string
    {
        for ($p = $positions->parent($at); $p !== null; $p = $positions->parent($p)) {
            if (($p instanceof Expr\Closure || $p instanceof Expr\ArrowFunction) && $p->static) {
                return null;
            }
        }

        return $this->thisClass($node);
    }

    private function thisClass(PathNode $node): ?string
    {
        if ($node->method === null || $node->closureClass !== null) {
            return $node->closureClass;
        }

        return $this->symbols->getClass($node->method->class)?->kind === 'trait' ? null : $node->method->class;
    }

    // The function whose scope types $receiver: the innermost nested closure, or an outer one for a captured variable.
    private function contextFor(Expr $receiver, Node $at, PathNode $node, BodyPositions $positions): PathNode
    {
        $fn = self::enclosingClosure($at, $positions);
        if ($fn === null) {
            return $node;
        }
        $root = self::rootVariable($receiver);
        if ($root !== null && $root !== 'this' && self::captures($fn, $root)) {
            return $this->contextFor($receiver, $fn, $node, $positions);
        }

        return new PathNode(sprintf('closure@%s:%d', $node->file, $fn->getStartLine()), null, $fn, $node->file, $fn->getStartLine(), $fn->getEndLine(), $node->depth, null, null, $this->thisClass($node));
    }

    private static function enclosingClosure(Node $at, BodyPositions $positions): Expr\Closure|Expr\ArrowFunction|null
    {
        for ($p = $positions->parent($at); $p !== null; $p = $positions->parent($p)) {
            if ($p instanceof Expr\Closure || $p instanceof Expr\ArrowFunction) {
                return $p;
            }
        }

        return null;
    }

    // A variable the nested function takes from its parent scope: a `use` of a closure, or any non-parameter of an arrow function.
    private static function captures(Expr\Closure|Expr\ArrowFunction $fn, string $name): bool
    {
        if ($fn instanceof Expr\Closure) {
            foreach ($fn->uses as $use) {
                if ($use->var->name === $name) {
                    return true;
                }
            }

            return false;
        }
        foreach ($fn->params as $param) {
            if ($param->var instanceof Expr\Variable && $param->var->name === $name) {
                return false;
            }
        }

        return true;
    }

    private static function rootVariable(Expr $expr): ?string
    {
        while ($expr instanceof Expr\MethodCall || $expr instanceof Expr\NullsafeMethodCall || $expr instanceof Expr\PropertyFetch
            || $expr instanceof Expr\NullsafePropertyFetch || $expr instanceof Expr\ArrayDimFetch) {
            $expr = $expr->var;
        }

        return $expr instanceof Expr\Variable && is_string($expr->name) ? $expr->name : null;
    }

    // Inside an if/loop/try or a nested closure; a DB::transaction callback runs exactly when the transaction call does.
    private function isConditional(Node $call, BodyPositions $positions): bool
    {
        $fn = self::enclosingClosure($call, $positions);
        if ($fn === null) {
            return ! $positions->isUnconditional($call);
        }
        $transaction = $this->transactionOf($fn, $positions);
        if ($transaction === null) {
            return true;
        }
        $id = spl_object_id($fn);
        $this->nestedPositions[$id] ??= new BodyPositions($fn->getStmts());

        return ! $this->nestedPositions[$id]->isUnconditional($call) || $this->isConditional($transaction, $positions);
    }

    private function transactionOf(Expr\Closure|Expr\ArrowFunction $fn, BodyPositions $positions): ?Expr\StaticCall
    {
        $arg = $positions->parent($fn);
        $call = $arg === null ? null : $positions->parent($arg);
        if (! $arg instanceof Node\Arg || ! $call instanceof Expr\StaticCall || ($call->args[0] ?? null) !== $arg
            || ! $call->class instanceof Node\Name || ! $call->name instanceof Node\Identifier || $call->name->toLowerString() !== 'transaction') {
            return null;
        }

        return $this->facade(ltrim($call->class->toString(), '\\')) === 'DB' ? $call : null;
    }
}
