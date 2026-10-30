<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Framework\Laravel;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt\Return_;
use PhpParser\NodeFinder;
use TusharKhan\SemanticSec\Parsing\Symbols\ClassSymbol;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;

/** Reads middleware declared inside controllers: constructor (L10-) and HasMiddleware (L11+). */
final class ControllerMiddlewareReader
{
    private const HAS_MIDDLEWARE = 'Illuminate\\Routing\\Controllers\\HasMiddleware';

    private const MIDDLEWARE = 'Illuminate\\Routing\\Controllers\\Middleware';

    public function __construct(private readonly SymbolTable $symbols, private readonly ConstantEvaluator $eval)
    {
    }

    /** @return array{0: list<string>, 1: list<string>} middleware and warnings */
    public function forAction(string $class, string $method): array
    {
        $symbol = $this->symbols->getClass($class);
        if ($symbol === null) {
            return [[], []];
        }
        $warnings = [];
        $entries = [];
        $withCtor = [];
        foreach ($this->chain($symbol) as $ancestor) {
            $ctor = $ancestor->methods['__construct'] ?? null;
            if ($ctor !== null) {
                $withCtor[] = [$ancestor, $ctor->node];
                if (! self::callsParentConstructor($ctor->node)) {
                    break;
                }
            }
        }
        foreach (array_reverse($withCtor) as [$ancestor, $node]) {
            array_push($entries, ...$this->constructorEntries($ancestor, $node, $warnings));
        }
        if ($this->implementsHasMiddleware($symbol)) {
            array_push($entries, ...$this->staticEntries($symbol, $warnings));
        }

        $out = [];
        $method = strtolower($method);
        foreach ($entries as [$name, $only, $except]) {
            if (($only === null || in_array($method, $only, true)) && ($except === null || ! in_array($method, $except, true))) {
                $out[] = $name;
            }
        }

        return [$out, $warnings];
    }

    /** @return list<ClassSymbol> class first, then ancestors present in the table */
    private function chain(ClassSymbol $class): array
    {
        $chain = [];
        for ($c = $class; $c !== null && ! isset($chain[$c->name]); $c = $c->parent === null ? null : $this->symbols->getClass($c->parent)) {
            $chain[$c->name] = $c;
        }

        return array_values($chain);
    }

    private function implementsHasMiddleware(ClassSymbol $class): bool
    {
        foreach ($this->chain($class) as $c) {
            if (in_array(self::HAS_MIDDLEWARE, array_map(static fn (string $i): string => ltrim($i, '\\'), $c->interfaces), true)) {
                return true;
            }
        }

        return false;
    }

    private static function callsParentConstructor(Node\Stmt\ClassMethod $ctor): bool
    {
        foreach ($ctor->stmts ?? [] as $stmt) {
            $call = $stmt instanceof Node\Stmt\Expression ? $stmt->expr : null;
            if ($call instanceof Expr\StaticCall && $call->class instanceof Node\Name && strtolower($call->class->toString()) === 'parent'
                && $call->name instanceof Node\Identifier && strtolower($call->name->toString()) === '__construct') {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  list<string>  $warnings
     * @return list<array{0: string, 1: ?list<string>, 2: ?list<string>}>
     */
    private function constructorEntries(ClassSymbol $class, Node\Stmt\ClassMethod $ctor, array &$warnings): array
    {
        $out = [];
        foreach ($ctor->stmts ?? [] as $stmt) {
            $top = $stmt instanceof Node\Stmt\Expression ? $this->chainRoot($stmt->expr) : null;
            if ($top === null) {
                foreach ((new NodeFinder())->findInstanceOf([$stmt], Expr\MethodCall::class) as $call) {
                    if ($call->name instanceof Node\Identifier && strtolower($call->name->toString()) === 'middleware') {
                        $warnings[] = sprintf('%s:%d: conditional controller middleware is not analysed', $class->file, $call->getStartLine());
                    }
                }

                continue;
            }
            [$root, $only, $except, $ok] = $this->readChain($stmt->expr, $top, $class, $warnings);
            $names = $this->middlewareNames($root->args[0]->value ?? null, $class, $root->getStartLine(), $warnings);
            $options = $root->args[1]->value ?? null;
            if ($options !== null && ! $options instanceof Expr\Array_) {
                $warnings[] = sprintf('%s:%d: controller middleware options could not be resolved', $class->file, $root->getStartLine());
                $ok = false;
            }
            foreach ($options instanceof Expr\Array_ ? $options->items : [] as $item) {
                $key = $item->key instanceof Expr ? $this->eval->string($item->key, $class->file, $class) : null;
                if ($item->unpack || $key === null) {
                    $warnings[] = sprintf('%s:%d: controller middleware options could not be resolved', $class->file, $item->getStartLine());
                    $ok = false;
                } elseif ($key === 'only' || $key === 'except') {
                    $list = $this->methodList([new Node\Arg($item->value)], $class, $item->getStartLine(), $warnings);
                    $ok = $ok && $list !== null;
                    if ($key === 'only') {
                        $only ??= $list;
                    } else {
                        $except ??= $list;
                    }
                }
            }
            if (! $ok) {
                continue;
            }
            foreach ($names as $mw) {
                $out[] = [$mw, $only, $except];
            }
        }

        return $out;
    }

    // The inner `$this->middleware(...)` call of a `->only()/->except()` chain, or null.
    private function chainRoot(Expr $expr): ?Expr\MethodCall
    {
        $node = $expr;
        while ($node instanceof Expr\MethodCall && $node->name instanceof Node\Identifier) {
            $name = strtolower($node->name->toString());
            if ($name === 'middleware') {
                return $node->var instanceof Expr\Variable && $node->var->name === 'this' ? $node : null;
            }
            if ($name !== 'only' && $name !== 'except') {
                return null;
            }
            $node = $node->var;
        }

        return null;
    }

    /**
     * @param  list<string>  $warnings
     * @return array{0: Expr\MethodCall, 1: ?list<string>, 2: ?list<string>, 3: bool}
     */
    private function readChain(Expr $expr, Expr\MethodCall $root, ClassSymbol $class, array &$warnings): array
    {
        $only = null;
        $except = null;
        $ok = true;
        for ($node = $expr; $node instanceof Expr\MethodCall && $node !== $root; $node = $node->var) {
            $name = $node->name instanceof Node\Identifier ? strtolower($node->name->toString()) : '';
            $list = $this->methodList($node->args, $class, $node->getStartLine(), $warnings);
            $ok = $ok && $list !== null;
            if ($name === 'only') {
                $only = $list;
            } else {
                $except = $list;
            }
        }

        return [$root, $only, $except, $ok];
    }

    /**
     * @param  list<string>  $warnings
     * @return list<array{0: string, 1: ?list<string>, 2: ?list<string>}>
     */
    private function staticEntries(ClassSymbol $class, array &$warnings): array
    {
        $method = $this->symbols->findMethod($class->name, 'middleware');
        if ($method === null) {
            return [];
        }
        $owner = $this->symbols->getClass($method->class) ?? $class;
        $return = (new NodeFinder())->findFirstInstanceOf($method->node->stmts ?? [], Return_::class);
        if (! $return instanceof Return_ || ! $return->expr instanceof Expr\Array_) {
            $warnings[] = sprintf('%s:%d: controller middleware could not be resolved', $method->file, $return?->getStartLine() ?? $method->startLine);

            return [];
        }
        $out = [];
        foreach ($return->expr->items as $item) {
            $value = $item->value;
            if (! $value instanceof Expr\New_) {
                foreach ($this->middlewareNames($value, $owner, $item->getStartLine(), $warnings) as $mw) {
                    $out[] = [$mw, null, null];
                }

                continue;
            }
            array_push($out, ...$this->middlewareObject($value, $owner, $warnings));
        }

        return $out;
    }

    /**
     * @param  list<string>  $warnings
     * @return list<array{0: string, 1: ?list<string>, 2: ?list<string>}>
     */
    private function middlewareObject(Expr\New_ $new, ClassSymbol $class, array &$warnings): array
    {
        $line = $new->getStartLine();
        if (! $new->class instanceof Node\Name || $new->class->toString() !== self::MIDDLEWARE) {
            $warnings[] = sprintf('%s:%d: controller middleware could not be resolved', $class->file, $line);

            return [];
        }
        $args = [];
        foreach ($new->args as $i => $arg) {
            if ($arg instanceof Node\Arg) {
                if ($arg->value instanceof Expr\ConstFetch && strtolower($arg->value->name->toString()) === 'null') {
                    continue;
                }
                $args[$arg->name !== null ? $arg->name->toString() : [0 => 'middleware', 1 => 'only', 2 => 'except'][$i] ?? ''] = $arg->value;
            }
        }
        $names = isset($args['middleware']) ? $this->middlewareNames($args['middleware'], $class, $line, $warnings) : [];
        $only = isset($args['only']) ? $this->methodList([new Node\Arg($args['only'])], $class, $line, $warnings) : null;
        $except = isset($args['except']) ? $this->methodList([new Node\Arg($args['except'])], $class, $line, $warnings) : null;
        if ((isset($args['only']) && $only === null) || (isset($args['except']) && $except === null)) {
            return [];
        }

        return array_map(static fn (string $n): array => [$n, $only, $except], $names);
    }

    /**
     * @param  list<string>  $warnings
     * @return list<string>
     */
    private function middlewareNames(?Expr $expr, ClassSymbol $class, int $line, array &$warnings): array
    {
        $out = [];
        foreach ($expr instanceof Expr\Array_ ? array_map(static fn (?Node\ArrayItem $i): ?Expr => $i?->value, $expr->items) : [$expr] as $item) {
            $str = $item === null ? null : $this->eval->string($item, $class->file, $class);
            if ($str === null) {
                $warnings[] = sprintf('%s:%d: controller middleware could not be resolved', $class->file, $item?->getStartLine() ?? $line);
            } else {
                $out[] = $str;
            }
        }

        return $out;
    }

    /**
     * @param  array<array-key, Node\Arg|Node\ArgPlaceholder|Node\VariadicPlaceholder>  $args
     * @param  list<string>  $warnings
     * @return list<string>|null lowercased method names, null if unresolvable
     */
    private function methodList(array $args, ClassSymbol $class, int $line, array &$warnings): ?array
    {
        $expr = ($args[0] ?? null) instanceof Node\Arg ? $args[0]->value : null;
        $out = [];
        foreach ($expr instanceof Expr\Array_ ? array_map(static fn (?Node\ArrayItem $i): ?Expr => $i?->value, $expr->items) : [$expr] as $item) {
            $str = $item === null ? null : $this->eval->string($item, $class->file, $class);
            if ($str === null) {
                $warnings[] = sprintf('%s:%d: controller middleware could not be resolved', $class->file, $line);

                return null;
            }
            $out[] = strtolower($str);
        }

        return $out;
    }
}
