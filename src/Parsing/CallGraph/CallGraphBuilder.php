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
use TusharKhan\SemanticSec\Parsing\Symbols\FunctionSymbol;
use TusharKhan\SemanticSec\Parsing\Symbols\MethodSymbol;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;

/** Breadth-first execution path from a route action (SPEC §8); targets come from static types only, never guesses. */
final class CallGraphBuilder
{
    private const FACADE = 'Illuminate\\Support\\Facades\\Facade';

    private const FACADE_NAMESPACE = 'Illuminate\\Support\\Facades\\';

    private const MODEL_BASES = [
        'Illuminate\\Database\\Eloquent\\Model',
        'Illuminate\\Foundation\\Auth\\User',
        'Illuminate\\Database\\Eloquent\\Relations\\Pivot',
        'Illuminate\\Database\\Eloquent\\Relations\\MorphPivot',
    ];

    private const DYNAMIC_FUNCTIONS = ['call_user_func', 'call_user_func_array', 'forward_static_call', 'forward_static_call_array'];

    // Laravel helpers that never reach project code worth following.
    private const HELPERS = [
        'response', 'collect', 'auth', 'request', 'abort', 'abort_if', 'abort_unless', 'now', 'today', 'view', 'redirect', 'back',
        'config', 'env', 'app', 'resolve', 'route', 'url', 'session', 'old', 'trans', '__', 'logger', 'info', 'optional', 'tap',
        'data_get', 'throw_if', 'throw_unless', 'dispatch', 'event', 'cache', 'bcrypt',
    ];

    private const SINKS = ['unserialize'];

    private const MAX_TEXT = 160;

    private readonly Standard $printer;

    /** @var list<array{file: string, line: int, kind: string, text: string, suffix: string}> */
    private array $records = [];

    /** @var array<int, int> spl id of a recorded call => its record index */
    private array $recordOf = [];

    /** @var array<int, BodyPositions> spl id of a nested function => positions of its own body */
    private array $nestedPositions = [];

    /** @var array<string, list<string>> class => concrete subclasses and implementations, sorted */
    private array $implementations = [];

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
                $this->recordDepthLimit($node);

                continue;
            }
            foreach ($this->callees($node) as [$method, $bound, $site, $assumed, $text]) {
                if ($method instanceof FunctionSymbol) {
                    $id = $method->id();
                } else {
                    $bound = $bound !== null && $bound !== $method->class ? $bound : null;
                    $id = $bound === null ? $method->id() : $bound.'::'.$method->name;
                }
                if (isset($visited[$id])) {
                    $this->records[] = ['file' => $site->file, 'line' => $site->line, 'kind' => 'already-visited', 'text' => $text, 'suffix' => ' → '.$id];

                    continue;
                }
                $visited[$id] = true;
                $nodes[] = $method instanceof FunctionSymbol
                    ? new PathNode($id, null, $method->node, $method->file, $method->node->getStartLine(), $method->node->getEndLine(), $node->depth + 1, $site, $node->id, null, $node->assumed || $assumed)
                    : new PathNode($id, $method, null, $method->file, $method->startLine, $method->endLine, $node->depth + 1, $site, $node->id, $bound, $node->assumed || $assumed);
            }
        }
        $unresolved = array_map(static fn (array $r): string => sprintf('%s:%d: [%s] %s%s', $r['file'], $r['line'], $r['kind'], $r['text'], $r['suffix']), $this->records);
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
            $bound = $bound !== $method->class ? $bound : null;

            return new PathNode($bound === null ? $method->id() : $bound.'::'.$method->name, $method, null, $method->file, $method->startLine, $method->endLine, 0, null, null, $bound);
        }
        $symbol = $action->symbol() ?? ($action->class ?? '?').'::'.($action->method ?? '?');
        $this->records[] = ['file' => $route->file, 'line' => $route->line, 'kind' => 'not-found', 'text' => 'action '.$symbol, 'suffix' => ''];

        return new PathNode($symbol, null, null, $route->file, $route->line, $route->line, 0, null, null);
    }

    // A node at the depth limit whose calls are not followed.
    private function recordDepthLimit(PathNode $node): void
    {
        $fn = $node->closure ?? $node->method?->node;
        if ($fn !== null && self::calls($fn->getStmts() ?? []) !== []) {
            $this->records[] = ['file' => $node->file, 'line' => $node->startLine, 'kind' => 'depth-limit', 'text' => $node->id, 'suffix' => ''];
        }
    }

    /** @return list<array{MethodSymbol|FunctionSymbol, ?string, CallSite, bool, string}> callees in source order: method or app function, bound class, site, assumed, call text */
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
                $out[] = [$target[0], $target[1], new CallSite($node->file, $call->getStartLine(), $this->isConditional($call, $positions)), $target[2], $this->print($call)];
            }
        }

        return $out;
    }

    /**
     * Calls and `new` in evaluation order (inner before outer), including nested closures but not nested classes or functions.
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
                if ($node instanceof Expr\MethodCall || $node instanceof Expr\NullsafeMethodCall || $node instanceof Expr\StaticCall
                    || $node instanceof Expr\FuncCall || ($node instanceof Expr\New_ && ! $node->class instanceof Stmt\Class_)) {
                    $this->calls[] = $node;
                }

                return null;
            }
        };
        (new NodeTraverser($visitor))->traverse($stmts);

        return $visitor->calls;
    }

    /** @return array{MethodSymbol|FunctionSymbol, ?string, bool}|null the method or app function to traverse, the class `$this` is bound to and whether it is assumed; null after recording why not */
    private function resolve(Expr\CallLike $call, PathNode $node, BodyPositions $positions): ?array
    {
        if ($call instanceof Expr\FuncCall) {
            $function = $this->projectFunction($call);
            if ($function !== null) {
                return [$function, null, false];
            }
            $this->recordFunction($call, $node);

            return null;
        }
        if ($call instanceof Expr\New_) {
            return $this->resolveNew($call, $node, $positions);
        }
        if ($call instanceof Expr\StaticCall) {
            return $this->resolveStatic($call, $node, $positions);
        }
        if (! $call instanceof Expr\MethodCall && ! $call instanceof Expr\NullsafeMethodCall) {
            return null;
        }
        if (! $call->name instanceof Node\Identifier) {
            $this->record($call, $node, 'dynamic');

            return null;
        }
        $class = $this->types->typeOf($call->var, $this->contextFor($call->var, $call, $node, $positions));
        if ($class === null) {
            $this->recordUnknown($call, $call->var, $node);

            return null;
        }
        // $this inside a method reached through a subclass is bound to that subclass; only the route class itself is exact.
        $isThis = $call->var instanceof Expr\Variable && $call->var->name === 'this';
        if ($isThis && $node->closureClass !== null && $this->symbols->isSubclassOf($node->closureClass, $class)) {
            $class = $node->closureClass;
        }

        return $this->lookup($call, $node, $class, $call->name->toString(), $isThis && $node->depth === 0);
    }

    // The project's own definition of a called function: the namespaced candidate first, then the global name, as PHP does.
    private function projectFunction(Expr\FuncCall $call): ?FunctionSymbol
    {
        if (! $call->name instanceof Node\Name) {
            return null;
        }
        $namespaced = $call->name->getAttribute('namespacedName');
        foreach ([$namespaced instanceof Node\Name ? $namespaced->toString() : null, $call->name->toString()] as $name) {
            $function = $name === null ? null : $this->symbols->getFunction($name);
            if ($function !== null) {
                return $function;
            }
        }

        return null;
    }

    private function recordFunction(Expr\FuncCall $call, PathNode $node): void
    {
        if (! $call->name instanceof Node\Name) {
            $this->record($call, $node, 'dynamic');

            return;
        }
        $name = strtolower(ltrim($call->name->toString(), '\\'));
        if (in_array($name, self::DYNAMIC_FUNCTIONS, true)) {
            $this->record($call, $node, 'dynamic');
        } elseif (in_array($name, self::SINKS, true)) {
            $this->record($call, $node, 'sink');
        } elseif (! in_array($name, self::HELPERS, true) && ! (function_exists($name) && (new \ReflectionFunction($name))->isInternal())) {
            $this->record($call, $node, 'function');
        }
    }

    /** @return array{MethodSymbol, ?string, bool}|null */
    private function resolveNew(Expr\New_ $new, PathNode $node, BodyPositions $positions): ?array
    {
        if (! $new->class instanceof Node\Name) {
            if ($new->class instanceof Expr) {
                $this->record($new, $node, 'dynamic');
            }

            return null;
        }
        $class = $this->keywordClass($new->class, $node, $new, $positions) ?? ltrim($new->class->toString(), '\\');
        if ($this->symbols->getClass($class) === null) {
            $this->record($new, $node, 'not-in-project', $class.'::__construct');

            return null;
        }
        $ctor = $this->symbols->findMethod($class, '__construct');
        if ($ctor === null) {
            $lineage = $this->symbols->lineage($class);
            $parent = $lineage[count($lineage) - 1]->parent ?? null;
            if ($parent !== null && $this->symbols->getClass($parent) === null) {
                $this->record($new, $node, 'not-in-project', ltrim($parent, '\\').'::__construct');
            }

            return null;
        }

        return $this->vendor($ctor) ? $this->notInProject($new, $node, $ctor) : [$ctor, $class, false];
    }

    /** @return array{MethodSymbol, ?string, bool}|null */
    private function resolveStatic(Expr\StaticCall $call, PathNode $node, BodyPositions $positions): ?array
    {
        if (! $call->class instanceof Node\Name || ! $call->name instanceof Node\Identifier) {
            $this->record($call, $node, 'dynamic');

            return null;
        }
        $name = $call->name->toString();
        $keyword = $call->class->toLowerString();
        if (in_array($keyword, ['self', 'static', 'parent'], true)) {
            $class = $this->keywordClass($call->class, $node, $call, $positions);
            if ($class === null) {
                $this->record($call, $node, 'unknown-type');

                return null;
            }
            // self:: and parent:: never dispatch; static:: does, like $this.
            $bound = $this->boundClass($node, $call, $positions);

            return $this->lookup($call, $node, $class, $name, $keyword !== 'static' || $node->depth === 0, $keyword === 'static' ? null : $bound);
        }
        $class = ltrim($call->class->toString(), '\\');
        if ($this->facade($class) !== null) {
            $this->record($call, $node, 'facade');

            return null;
        }

        return $this->lookup($call, $node, $class, $name, true);
    }

    private function keywordClass(Node\Name $name, PathNode $node, Node $at, BodyPositions $positions): ?string
    {
        $keyword = $name->toLowerString();
        if (! in_array($keyword, ['self', 'static', 'parent'], true)) {
            return null;
        }
        $bound = $this->boundClass($node, $at, $positions);
        $self = $node->method !== null && $this->symbols->getClass($node->method->class)?->kind !== 'trait' ? $node->method->class : $bound;
        $class = match ($keyword) {
            'self' => $self,
            'static' => $bound,
            default => $self === null ? null : $this->symbols->getClass($self)?->parent,
        };

        return $class === null ? null : ltrim($class, '\\');
    }

    /**
     * The targets of a call on $class: exact calls take its own method; a dispatching call on an abstract type takes the sole
     * override when there is one, and on a concrete type takes its own method and flags overrides.
     *
     * @return array{MethodSymbol, ?string, bool}|null
     */
    private function lookup(Expr\CallLike $call, PathNode $node, string $class, string $name, bool $exact, ?string $bindAs = null): ?array
    {
        $symbol = $this->symbols->getClass($class);
        if ($symbol === null) {
            $this->record($call, $node, 'not-in-project', $class);

            return null;
        }
        $own = $this->symbols->findMethod($class, $name);
        $abstract = $symbol->kind === 'interface' || ($symbol->node instanceof Stmt\Class_ && $symbol->node->isAbstract())
            || ($own !== null && $own->node->stmts === null);
        if (! $abstract) {
            if ($own === null) {
                $this->recordMissing($call, $node, $class, $name);

                return null;
            }
            if ($this->vendor($own)) {
                return $this->notInProject($call, $node, $own);
            }
            $overrides = [];
            foreach ($exact ? [] : $this->implementationsOf($class) as $sub) {
                $method = $this->symbols->findMethod($sub, $name);
                if ($method !== null && $method->id() !== $own->id()) {
                    $overrides[$method->class] = true;
                }
            }
            if ($overrides !== []) {
                $this->record($call, $node, 'may-be-overridden', implode(', ', array_keys($overrides)), false);
            }

            return [$own, $bindAs ?? $class, false];
        }
        if ($exact && $own !== null && $own->node->stmts !== null) {
            return $this->vendor($own) ? $this->notInProject($call, $node, $own) : [$own, $bindAs ?? $class, false];
        }
        $targets = [];
        $labels = [];
        foreach ($this->implementationsOf($class) as $sub) {
            $method = $this->symbols->findMethod($sub, $name);
            if ($method === null || $method->node->stmts === null) {
                $labels[$sub.'::'.$name] = true;

                continue;
            }
            $targets[$method->id()][0] = $method;
            $targets[$method->id()][1][] = $sub;
            $labels[$method->id()] = true;
        }
        if (count($targets) === 1 && count($labels) === 1) {
            [$method, $subs] = array_values($targets)[0];
            $bound = count($subs) === 1 ? $subs[0] : null;
            if ($this->vendor($method)) {
                return $this->notInProject($call, $node, $method);
            }
            $this->record($call, $node, 'assumed', $bound ?? $method->class, false);

            return [$method, $bound, true];
        }
        $labels = array_keys($labels);
        sort($labels);
        $this->record($call, $node, $labels === [] ? 'not-found' : 'ambiguous', $labels === [] ? 'no implementation of '.$class.' in the project' : implode(', ', $labels));

        return null;
    }

    /** @return list<string> */
    private function implementationsOf(string $class): array
    {
        if (! isset($this->implementations[$class])) {
            $found = $this->symbols->implementations($class);
            sort($found);
            $this->implementations[$class] = $found;
        }

        return $this->implementations[$class];
    }

    private function vendor(MethodSymbol $method): bool
    {
        return str_starts_with($method->file, 'vendor/');
    }

    private function notInProject(Expr\CallLike $call, PathNode $node, MethodSymbol $method): null
    {
        $this->record($call, $node, 'not-in-project', $method->class);

        return null;
    }

    // Eloquent forwards unknown model calls to its query builder; anything else is simply missing.
    private function recordMissing(Expr\CallLike $call, PathNode $node, string $class, string $name): void
    {
        foreach (self::MODEL_BASES as $base) {
            if ($this->symbols->isSubclassOf($class, $base)) {
                $this->record($call, $node, 'eloquent');

                return;
            }
        }
        $outside = [];
        foreach ($this->symbols->lineage($class) as $symbol) {
            foreach ([$symbol->parent, ...$symbol->traits] as $ancestor) {
                if ($ancestor !== null && $this->symbols->getClass($ancestor) === null) {
                    $outside[] = ltrim($ancestor, '\\');
                }
            }
        }
        // Likely inherited from a vendor parent or trait.
        $this->record($call, $node, $outside === [] ? 'not-found' : 'not-in-project', $class.'::'.$name.($outside === [] ? '' : ' via '.implode(', ', $outside)));
    }

    // An unknown receiver that is itself a recorded call extends that record to the whole chain.
    private function recordUnknown(Expr\CallLike $call, Expr $receiver, PathNode $node): void
    {
        $index = $this->recordOf[spl_object_id($receiver)] ?? null;
        if ($index === null) {
            $this->record($call, $node, 'unknown-type');

            return;
        }
        $this->records[$index]['text'] = $this->print($call);
        $this->recordOf[spl_object_id($call)] = $index;
    }

    private function record(Expr\CallLike $call, PathNode $node, string $kind, ?string $detail = null, bool $chainable = true): void
    {
        if ($chainable) {
            $this->recordOf[spl_object_id($call)] = count($this->records);
        }
        $this->records[] = ['file' => $node->file, 'line' => $call->getStartLine(), 'kind' => $kind, 'text' => $this->print($call), 'suffix' => $detail === null ? '' : ' → '.$detail];
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

    // A nullsafe call, a call on a nullsafe chain, or a call inside the arguments of one is skipped on null.
    private static function shortCircuited(Node $call, BodyPositions $positions): bool
    {
        if ($call instanceof Expr && self::hasNullsafe($call)) {
            return true;
        }
        for ($child = $call, $parent = $positions->parent($call); $parent !== null; $child = $parent, $parent = $positions->parent($parent)) {
            if (self::isChainLink($parent) && $parent->var !== $child && self::hasNullsafe($parent)) {
                return true;
            }
        }

        return false;
    }

    /** @phpstan-assert-if-true Expr\MethodCall|Expr\NullsafeMethodCall|Expr\PropertyFetch|Expr\NullsafePropertyFetch|Expr\ArrayDimFetch $node */
    private static function isChainLink(Node $node): bool
    {
        return $node instanceof Expr\MethodCall || $node instanceof Expr\NullsafeMethodCall || $node instanceof Expr\PropertyFetch
            || $node instanceof Expr\NullsafePropertyFetch || $node instanceof Expr\ArrayDimFetch;
    }

    private static function hasNullsafe(Expr $expr): bool
    {
        for (; self::isChainLink($expr); $expr = $expr->var) {
            if ($expr instanceof Expr\NullsafeMethodCall || $expr instanceof Expr\NullsafePropertyFetch) {
                return true;
            }
        }

        return false;
    }

    // Inside an if/loop/try or a nested closure; a DB::transaction callback runs exactly when the transaction call does.
    private function isConditional(Node $call, BodyPositions $positions): bool
    {
        if (self::shortCircuited($call, $positions)) {
            return true;
        }
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
