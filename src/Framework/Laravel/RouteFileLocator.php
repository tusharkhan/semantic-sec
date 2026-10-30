<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Framework\Laravel;

use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\Expr;
use PhpParser\NodeFinder;
use TusharKhan\SemanticSec\Config\Config;
use TusharKhan\SemanticSec\Framework\DetectedFramework;
use TusharKhan\SemanticSec\Parsing\ParseResult;
use TusharKhan\SemanticSec\Parsing\Symbols\ClassSymbol;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;

/** Works out which route files a Laravel app loads, from the AST alone. */
final class RouteFileLocator
{
    private const PROVIDERS = [
        'Illuminate\\Support\\ServiceProvider',
        'Illuminate\\Foundation\\Support\\Providers\\RouteServiceProvider',
        'Illuminate\\Foundation\\Support\\Providers\\AuthServiceProvider',
        'Illuminate\\Foundation\\Support\\Providers\\EventServiceProvider',
    ];

    private const FACADE = 'Illuminate\\Support\\Facades\\Route';

    private const BOOTSTRAP = 'bootstrap/app.php';

    /** @return array{0: list<RouteFile>, 1: list<string>} */
    public function locate(ParseResult $parsed, SymbolTable $symbols, DetectedFramework $fw, Config $config, ConstantEvaluator $eval): array
    {
        $files = [];
        $warnings = [];
        $referenced = false;

        $withRouting = $this->findWithRouting($parsed);
        if ($withRouting !== null) {
            $referenced = true;
            $this->fromWithRouting($withRouting, $parsed, $eval, $files, $warnings);
        }
        // Any service provider may load route files, with or without withRouting.
        $referenced = $this->fromProviders($parsed, $symbols, $eval, $files, $warnings) || $referenced;

        if (! $referenced) {
            if ($parsed->file('routes/web.php') !== null) {
                $files[] = new RouteFile('routes/web.php', '', ['web'], null);
            }
            if ($parsed->file('routes/api.php') !== null) {
                $files[] = new RouteFile('routes/api.php', 'api', ['api'], null);
            }
        }

        foreach ($config->laravelRouteFiles as $path) {
            $path = (string) ConstantEvaluator::normalisePath($path);
            if ($parsed->file($path) === null) {
                $warnings[] = sprintf('route file %s not found', $path);

                continue;
            }
            $files[] = new RouteFile($path, '', [], null);
        }

        $seen = [];
        $unique = [];
        foreach ($files as $file) {
            if (! isset($seen[$file->path])) {
                $seen[$file->path] = true;
                $unique[] = $file;
            }
        }

        return [$unique, array_values(array_unique($warnings))];
    }

    private function findWithRouting(ParseResult $parsed): ?Expr\MethodCall
    {
        $bootstrap = $parsed->file(self::BOOTSTRAP);
        if ($bootstrap === null) {
            return null;
        }
        $call = (new NodeFinder())->findFirst($bootstrap->ast, fn (Node $n): bool => $n instanceof Expr\MethodCall
            && $n->name instanceof Node\Identifier && strtolower($n->name->toString()) === 'withrouting');

        return $call instanceof Expr\MethodCall ? $call : null;
    }

    /**
     * @param  list<RouteFile>  $files
     * @param  list<string>  $warnings
     */
    private function fromWithRouting(Expr\MethodCall $call, ParseResult $parsed, ConstantEvaluator $eval, array &$files, array &$warnings): void
    {
        $named = [];
        $before = count($warnings);
        foreach ($call->args as $arg) {
            if (! $arg instanceof Arg) {
                continue;
            }
            $line = $arg->getStartLine();
            if ($arg->unpack) {
                $warnings[] = sprintf('%s:%d: withRouting spread arguments are not analysed', self::BOOTSTRAP, $line);
            } elseif ($arg->name === null) {
                $warnings[] = sprintf('%s:%d: withRouting positional arguments are not analysed', self::BOOTSTRAP, $line);
            } elseif ($arg->name->toString() === 'using') {
                $warnings[] = sprintf('%s:%d: withRouting using: arguments are not analysed', self::BOOTSTRAP, $line);
            } else {
                $named[$arg->name->toString()] = $arg;
            }
        }

        $prefix = 'api';
        if (isset($named['apiPrefix'])) {
            $value = $eval->string($named['apiPrefix']->value, self::BOOTSTRAP);
            if ($value === null) {
                $warnings[] = sprintf('%s:%d: route prefix could not be resolved', self::BOOTSTRAP, $named['apiPrefix']->getStartLine());
            } else {
                $prefix = trim($value, '/');
            }
        }

        foreach (['web' => ['', ['web']], 'api' => [$prefix, ['api']]] as $key => [$pfx, $mw]) {
            if (! isset($named[$key])) {
                continue;
            }
            $value = $named[$key]->value;
            $exprs = $value instanceof Expr\Array_
                ? array_map(fn ($i) => $i->value, $value->items)
                : [$value];
            foreach ($exprs as $expr) {
                $path = $eval->path($expr, self::BOOTSTRAP);
                if ($path === null) {
                    $warnings[] = sprintf('%s:%d: route file path could not be resolved', self::BOOTSTRAP, $expr->getStartLine());
                } elseif ($parsed->file($path) === null) {
                    $warnings[] = sprintf('route file %s not found', $path);
                } else {
                    $files[] = new RouteFile($path, $pfx, $mw, null);
                }
            }
        }

        if (isset($named['then'])) {
            $warnings[] = sprintf('%s:%d: then: routes are not analysed', self::BOOTSTRAP, $named['then']->getStartLine());
        }
        if ($files === [] && count($warnings) === $before) {
            $warnings[] = sprintf('%s:%d: withRouting found no route files', self::BOOTSTRAP, $call->getStartLine());
        }
    }

    /**
     * @param  list<RouteFile>  $files
     * @param  list<string>  $warnings
     * @return bool whether any route file was referenced
     */
    private function fromProviders(ParseResult $parsed, SymbolTable $symbols, ConstantEvaluator $eval, array &$files, array &$warnings): bool
    {
        $referenced = false;
        $finder = new NodeFinder();
        foreach ($symbols->all() as $class) {
            if ($class->kind !== 'class' || ! Ancestry::descendsFrom($symbols, $class->parent, self::PROVIDERS)) {
                continue;
            }
            foreach ($class->methods as $method) {
                $stmts = $method->node->stmts ?? [];
                $groups = array_values(array_filter($finder->find($stmts, fn (Node $n): bool => $this->isRouteGroup($n)), fn (Node $n): bool => $n instanceof Expr\MethodCall || $n instanceof Expr\StaticCall));
                $nested = [];
                $inGroup = [];
                foreach ($groups as $group) {
                    foreach ($this->closureArgs($group) as $closure) {
                        foreach ($finder->find($closure->getStmts(), fn (Node $n): bool => $this->isRouteGroup($n)) as $inner) {
                            $nested[spl_object_id($inner)] = $inner;
                        }
                        foreach ($finder->findInstanceOf($closure->getStmts(), Expr\Include_::class) as $include) {
                            $inGroup[spl_object_id($include)] = true;
                        }
                    }
                }
                // Source order: groups, bare route-file includes and loadRoutesFrom() calls.
                $items = [];
                foreach ($groups as $group) {
                    $items[] = [$group->getStartFilePos(), function () use ($group, $nested, $class, $parsed, $eval, &$files, &$warnings): bool {
                        if (isset($nested[spl_object_id($group)])) {
                            $warnings[] = sprintf('%s:%d: nested route groups in providers are not analysed', $class->file, $group->getStartLine());

                            return false;
                        }

                        return $this->fromGroup($group, $class, $parsed, $eval, $files, $warnings);
                    }];
                }
                foreach ($finder->findInstanceOf($stmts, Expr\Include_::class) as $include) {
                    if (! isset($inGroup[spl_object_id($include)])) {
                        $items[] = [$include->getStartFilePos(), function () use ($include, $class, $parsed, $eval, &$files, &$warnings): bool {
                            return $this->addPath($include->expr, $include, $class, '', [], null, [], true, $parsed, $eval, $files, $warnings);
                        }];
                    }
                }
                foreach ($finder->findInstanceOf($stmts, Expr\MethodCall::class) as $call) {
                    $arg = $call->args[0] ?? null;
                    if ($call->var instanceof Expr\Variable && $call->var->name === 'this' && $call->name instanceof Node\Identifier
                        && strtolower($call->name->toString()) === 'loadroutesfrom' && $arg instanceof Arg) {
                        $items[] = [$call->getStartFilePos(), function () use ($arg, $call, $class, $parsed, $eval, &$files, &$warnings): bool {
                            return $this->addPath($arg->value, $call, $class, '', [], null, [], false, $parsed, $eval, $files, $warnings);
                        }];
                    }
                }
                usort($items, static fn (array $a, array $b): int => $a[0] <=> $b[0]);
                foreach ($items as [, $load]) {
                    $referenced = $load() || $referenced;
                }
            }
        }

        return $referenced;
    }

    /**
     * Adds one route file reference; a bare include counts only when it points into routes/.
     *
     * @param  list<string>  $middleware
     * @param  list<string>  $without
     * @param  list<RouteFile>  $files
     * @param  list<string>  $warnings
     */
    private function addPath(Expr $expr, Node $at, ClassSymbol $class, string $prefix, array $middleware, ?string $namespace, array $without, bool $routesOnly, ParseResult $parsed, ConstantEvaluator $eval, array &$files, array &$warnings): bool
    {
        $path = $eval->path($expr, $class->file, $class);
        if ($path === null) {
            $warnings[] = sprintf('%s:%d: route file path could not be resolved', $class->file, $at->getStartLine());

            return true;
        }
        if ($routesOnly && ! str_starts_with($path, 'routes/')) {
            return false;
        }
        if ($parsed->file($path) === null) {
            $warnings[] = sprintf('route file %s not found', $path);

            return true;
        }
        $files[] = new RouteFile($path, $prefix, $middleware, $namespace, $without);

        return true;
    }

    /** @phpstan-assert-if-true Expr\MethodCall|Expr\StaticCall $n */
    private function isRouteGroup(Node $n): bool
    {
        if ($n instanceof Expr\StaticCall) {
            return $n->name instanceof Node\Identifier && strtolower($n->name->toString()) === 'group' && $this->isRouteFacade($n);
        }
        if (! $n instanceof Expr\MethodCall || ! $n->name instanceof Node\Identifier || strtolower($n->name->toString()) !== 'group') {
            return false;
        }
        $root = $n->var;
        while ($root instanceof Expr\MethodCall) {
            $root = $root->var;
        }

        return $root instanceof Expr\StaticCall && $this->isRouteFacade($root);
    }

    /** @return list<Expr\Closure|Expr\ArrowFunction> */
    private function closureArgs(Expr\MethodCall|Expr\StaticCall $group): array
    {
        $out = [];
        foreach ($group->args as $a) {
            if ($a instanceof Arg && ($a->value instanceof Expr\Closure || $a->value instanceof Expr\ArrowFunction)) {
                $out[] = $a->value;
            }
        }

        return $out;
    }

    /**
     * @param  list<RouteFile>  $files
     * @param  list<string>  $warnings
     */
    private function fromGroup(Expr\MethodCall|Expr\StaticCall $group, ClassSymbol $class, ParseResult $parsed, ConstantEvaluator $eval, array &$files, array &$warnings): bool
    {
        $file = $class->file;
        $prefix = '';
        $middleware = [];
        $without = [];
        $namespace = null;

        if ($group instanceof Expr\StaticCall) {
            $attrs = $group->args[0] ?? null;
            $pathArg = $group->args[1] ?? null;
            if (! $pathArg instanceof Arg || ! $this->loadsFiles($pathArg->value)) {
                return false;
            }
            if (! $attrs instanceof Arg || ! $attrs->value instanceof Expr\Array_) {
                $warnings[] = sprintf('%s:%d: route group attributes could not be resolved', $file, $group->getStartLine());
            } else {
                foreach ($attrs->value->items as $item) {
                    if ($item->unpack || ! $item->key instanceof Node\Scalar\String_) {
                        $warnings[] = sprintf('%s:%d: route group attributes could not be resolved', $file, $group->getStartLine());

                        continue;
                    }
                    $key = $item->key->value;
                    $this->applyAttribute($key, [$item->value], $item, $file, $class, $eval, $prefix, $middleware, $without, $namespace, $warnings);
                }
            }
        } else {
            $pathArg = $group->args[0] ?? null;
            if (! $pathArg instanceof Arg || ! $this->loadsFiles($pathArg->value)) {
                return false;
            }
            // Flatten the chain from the root outwards.
            $calls = [];
            $node = $group->var;
            while ($node instanceof Expr\MethodCall) {
                array_unshift($calls, $node);
                $node = $node->var;
            }
            if ($node instanceof Expr\StaticCall) {
                array_unshift($calls, $node);
            }
            foreach ($calls as $call) {
                if (! $call->name instanceof Node\Identifier) {
                    continue;
                }
                $values = [];
                foreach ($call->args as $a) {
                    if ($a instanceof Arg) {
                        $values[] = $a->value;
                    }
                }
                $this->applyAttribute(strtolower($call->name->toString()), $values, $call, $file, $class, $eval, $prefix, $middleware, $without, $namespace, $warnings);
            }
        }

        $target = $pathArg->value;
        if ($target instanceof Expr\Closure || $target instanceof Expr\ArrowFunction) {
            foreach ((new NodeFinder())->findInstanceOf($target->getStmts(), Expr\Include_::class) as $include) {
                $this->addPath($include->expr, $include, $class, $prefix, $middleware, $namespace, $without, false, $parsed, $eval, $files, $warnings);
            }

            return true;
        }

        return $this->addPath($target, $group, $class, $prefix, $middleware, $namespace, $without, false, $parsed, $eval, $files, $warnings);
    }

    // A path argument, or a closure that requires route files.
    private function loadsFiles(Expr $target): bool
    {
        if ($target instanceof Expr\Closure || $target instanceof Expr\ArrowFunction) {
            return (new NodeFinder())->findFirstInstanceOf($target->getStmts(), Expr\Include_::class) !== null;
        }

        return true;
    }

    /**
     * @param  list<Expr>  $values
     * @param  list<string>  $middleware
     * @param  list<string>  $without
     * @param  list<string>  $warnings
     */
    private function applyAttribute(string $name, array $values, Node $at, string $file, ClassSymbol $class, ConstantEvaluator $eval, string &$prefix, array &$middleware, array &$without, ?string &$namespace, array &$warnings): void
    {
        $line = $at->getStartLine();
        switch (strtolower($name)) {
            case 'prefix':
                $v = isset($values[0]) ? $eval->string($values[0], $file, $class) : null;
                if ($v === null) {
                    $warnings[] = sprintf('%s:%d: route prefix could not be resolved', $file, $line);
                } else {
                    $prefix = trim($v, '/');
                }
                break;
            case 'namespace':
                $expr = $values[0] ?? null;
                if ($expr === null || $this->isNull($expr)) {
                    $namespace = null;
                    break;
                }
                // Laravel 11+ apps drop the property; the framework default is null.
                if ($this->isUnsetNamespaceProperty($expr, $class)) {
                    $namespace = null;
                    break;
                }
                $namespace = $eval->string($expr, $file, $class);
                if ($namespace === null) {
                    $warnings[] = sprintf('%s:%d: route namespace could not be resolved', $file, $line);
                }
                break;
            case 'middleware':
            case 'withoutmiddleware':
            case 'excluded_middleware':
                $exclude = strtolower($name) !== 'middleware';
                foreach ($values as $value) {
                    foreach ($value instanceof Expr\Array_ ? array_map(fn ($i) => $i->value, $value->items) : [$value] as $item) {
                        $str = $eval->string($item, $file, $class);
                        if ($str !== null && $exclude) {
                            $without[] = $str;
                        } elseif ($str !== null) {
                            $middleware[] = $str;
                        } elseif (! $this->isNull($item)) {
                            $warnings[] = sprintf('%s:%d: route middleware could not be resolved', $file, $line);
                            if ($exclude) {
                                $without[] = RouteEntry::UNRESOLVED;
                            }
                        }
                    }
                }
                break;
        }
    }

    // $this->namespace that the app never declares, or declares without a value.
    private function isUnsetNamespaceProperty(Expr $expr, ClassSymbol $class): bool
    {
        if (! $expr instanceof Expr\PropertyFetch || ! $expr->var instanceof Expr\Variable || $expr->var->name !== 'this'
            || ! $expr->name instanceof Node\Identifier || $expr->name->toString() !== 'namespace') {
            return false;
        }
        $property = $class->properties['namespace'] ?? null;

        return $property === null || $property->default === null || $this->isNull($property->default);
    }

    private function isNull(Expr $e): bool
    {
        return $e instanceof Expr\ConstFetch && strtolower($e->name->toString()) === 'null';
    }

    private function isRouteFacade(Expr\StaticCall $call): bool
    {
        if (! $call->class instanceof Node\Name) {
            return false;
        }
        $original = $call->class->getAttribute('originalName');
        $names = [$call->class->toString(), $original instanceof Node\Name ? $original->toString() : ''];

        return in_array(self::FACADE, $names, true) || in_array('Route', $names, true);
    }
}
