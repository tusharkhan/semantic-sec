<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Framework\Laravel;

use PhpParser\Node;
use PhpParser\Node\Expr;

/** Resolves a route's action argument (closure, Class::class, [Class, method], 'Class@method', action array). */
final class RouteActionResolver
{
    /** @var list<string> */
    private array $warnings = [];

    /** @var list<string> */
    private array $middleware = [];

    private ?string $name = null;

    public function __construct(private readonly ConstantEvaluator $eval, private readonly StringListReader $lists)
    {
    }

    public function resolve(?Expr $expr, RouteContext $ctx, string $file, int $line): ResolvedAction
    {
        $this->warnings = [];
        $this->middleware = [];
        $this->name = null;
        $action = $this->action($expr, $ctx, $file, $line);

        return new ResolvedAction($action, $this->middleware, $this->name, $this->warnings);
    }

    /** Prepends the group namespace the way Laravel's Router::prependGroupNamespace does. */
    public static function qualify(string $class, ?string $namespace): string
    {
        if (str_starts_with($class, '\\')) {
            return ltrim($class, '\\');
        }
        if ($namespace === null || $namespace === '' || str_starts_with($class, $namespace)) {
            return $class;
        }

        return $namespace.'\\'.$class;
    }

    private function action(?Expr $expr, RouteContext $ctx, string $file, int $line): RouteAction
    {
        if ($expr instanceof Expr\Closure || $expr instanceof Expr\ArrowFunction) {
            return new RouteAction(null, null, $expr);
        }
        if ($expr instanceof Expr\ClassConstFetch && $expr->name instanceof Node\Identifier && strtolower($expr->name->toString()) === 'class') {
            $class = $this->eval->string($expr, $file);
            if ($class !== null) {
                return new RouteAction(self::qualify($class, $ctx->namespace), '__invoke');
            }
        } elseif ($expr instanceof Expr\Array_) {
            $keyed = array_filter($expr->items, fn (Node\ArrayItem $i): bool => $i->key !== null);
            if ($keyed !== []) {
                return $this->keyedAction($expr, $ctx, $file, $line);
            }
            if (count($expr->items) === 2 && ! $expr->items[0]->unpack && ! $expr->items[1]->unpack) {
                $class = $this->eval->string($expr->items[0]->value, $file);
                $method = $this->eval->string($expr->items[1]->value, $file);
                if ($class !== null && $method !== null) {
                    return new RouteAction(ltrim($class, '\\'), $method);
                }
            }
        } elseif ($expr !== null) {
            $str = $this->eval->string($expr, $file);
            if ($str !== null) {
                return $this->stringAction($str, $ctx);
            }
        }
        $this->warn($file, $line, 'route action could not be resolved');

        return new RouteAction(null, null);
    }

    private function keyedAction(Expr\Array_ $expr, RouteContext $ctx, string $file, int $line): RouteAction
    {
        $action = null;
        foreach ($expr->items as $item) {
            $key = $item->key instanceof Node\Scalar\String_ ? strtolower($item->key->value) : null;
            if ($item->key === null && ($item->value instanceof Expr\Closure || $item->value instanceof Expr\ArrowFunction)) {
                $action = new RouteAction(null, null, $item->value);
            } elseif ($key === 'uses') {
                $uses = $this->eval->string($item->value, $file);
                $action = $uses === null ? null : $this->stringAction($uses, $ctx);
            } elseif ($key === 'middleware') {
                $this->middleware = [...$this->middleware, ...$this->lists->stringList([$item->value], $file, $line, 'middleware', $this->warnings)];
            } elseif ($key === 'as') {
                $this->name = $this->eval->string($item->value, $file);
                if ($this->name === null) {
                    $this->warn($file, $line, 'route name could not be resolved');
                }
            } else {
                $this->warn($file, $line, sprintf('route action key %s is not analysed', $key ?? '?'));
            }
        }
        if ($action === null) {
            $this->warn($file, $line, 'route action could not be resolved');
        }

        return $action ?? new RouteAction(null, null);
    }

    private function stringAction(string $action, RouteContext $ctx): RouteAction
    {
        if (str_contains($action, '@')) {
            [$class, $method] = explode('@', $action, 2);
        } elseif ($ctx->controller !== null) {
            [$class, $method] = [$ctx->controller, $action];
        } else {
            [$class, $method] = [$action, '__invoke'];
        }

        return new RouteAction(self::qualify($class, $ctx->namespace), $method);
    }

    private function warn(string $file, int $line, string $message): void
    {
        $this->warnings[] = sprintf('%s:%d: %s', $file, $line, $message);
    }
}
