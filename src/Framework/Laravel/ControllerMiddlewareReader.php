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
        foreach (array_reverse($this->chain($symbol)) as $ancestor) {
            $ctor = $ancestor->methods['__construct'] ?? null;
            if ($ctor !== null) {
                array_push($entries, ...$this->constructorEntries($ancestor, $ctor->node, $warnings));
            }
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

    /**
     * @param  list<string>  $warnings
     * @return list<array{0: string, 1: ?list<string>, 2: ?list<string>}>
     */
    private function constructorEntries(ClassSymbol $class, Node\Stmt\ClassMethod $ctor, array &$warnings): array
    {
        $calls = (new NodeFinder())->findInstanceOf($ctor->stmts ?? [], Expr\MethodCall::class);
        $inner = [];
        $out = [];
        foreach ($calls as $call) {
            if (isset($inner[spl_object_id($call)])) {
                continue;
            }
            $only = null;
            $except = null;
            $ok = true;
            $node = $call;
            while ($node instanceof Expr\MethodCall && $node->name instanceof Node\Identifier && in_array($name = strtolower($node->name->toString()), ['only', 'except'], true)) {
                $list = $this->methodList($node->args, $class, $node->getStartLine(), $warnings);
                $ok = $ok && $list !== null;
                if ($name === 'only') {
                    $only = $list;
                } else {
                    $except = $list;
                }
                $node = $node->var;
                $inner[spl_object_id($node)] = true;
            }
            if (! $node instanceof Expr\MethodCall || ! $node->name instanceof Node\Identifier || strtolower($node->name->toString()) !== 'middleware'
                || ! $node->var instanceof Expr\Variable || $node->var->name !== 'this') {
                continue;
            }
            $inner[spl_object_id($node)] = true;
            $names = $this->middlewareNames($node->args[0]->value ?? null, $class, $node->getStartLine(), $warnings);
            if (! $ok) {
                continue;
            }
            foreach ($names as $mw) {
                $out[] = [$mw, $only, $except];
            }
        }

        return $out;
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
            $entry = $this->middlewareObject($value, $owner, $warnings);
            if ($entry !== null) {
                $out[] = $entry;
            }
        }

        return $out;
    }

    /**
     * @param  list<string>  $warnings
     * @return array{0: string, 1: ?list<string>, 2: ?list<string>}|null
     */
    private function middlewareObject(Expr\New_ $new, ClassSymbol $class, array &$warnings): ?array
    {
        $line = $new->getStartLine();
        if (! $new->class instanceof Node\Name || $new->class->toString() !== self::MIDDLEWARE) {
            $warnings[] = sprintf('%s:%d: controller middleware could not be resolved', $class->file, $line);

            return null;
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
        if (count($names) !== 1 || (isset($args['only']) && $only === null) || (isset($args['except']) && $except === null)) {
            return null;
        }

        return [$names[0], $only, $except];
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
