<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Framework\Laravel;

use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use TusharKhan\SemanticSec\Parsing\ParseResult;

/** Interprets Route:: fluent chains in route files into RouteEntry objects, from the AST alone. */
final class RouteCollector
{
    private const FACADE = 'Illuminate\\Support\\Facades\\Route';

    private const VERBS = ['get', 'post', 'put', 'patch', 'delete', 'options'];

    private const ANY = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];

    private const RESOURCES = ['resource', 'apiresource', 'resources', 'apiresources', 'singleton', 'apisingleton', 'singletons', 'apisingletons'];

    private const UNSUPPORTED = ['view', 'redirect', 'fallback', 'permanentredirect'];

    private const GROUP_KEYS = ['prefix' => 'prefix', 'middleware' => 'middleware', 'namespace' => 'namespace', 'as' => 'name', 'controller' => 'controller', 'excluded_middleware' => 'withoutmiddleware', 'withoutmiddleware' => 'withoutmiddleware', 'domain' => 'domain', 'where' => 'where'];

    /** @var list<RouteEntry> */
    private array $routes = [];

    /** @var list<string> */
    private array $warnings = [];

    /** @var array<string, true> */
    private array $loading = [];

    private readonly StringListReader $lists;

    private readonly RouteActionResolver $actions;

    public function __construct(private readonly ParseResult $parsed, private readonly ConstantEvaluator $eval)
    {
        $this->lists = new StringListReader($eval);
        $this->actions = new RouteActionResolver($eval, $this->lists);
    }

    /** @return array{0: list<RouteEntry>, 1: list<string>} */
    public function collect(RouteFile $file): array
    {
        $this->routes = [];
        $this->warnings = [];
        $this->loading = [];
        $this->load($file->path, RouteContext::fromFile($file), null, 0);

        return [$this->routes, $this->warnings];
    }

    private function load(string $path, RouteContext $ctx, ?string $from, int $line): void
    {
        $parsed = $this->parsed->file($path);
        if ($parsed === null) {
            $message = sprintf('route file %s not found', $path);
            if ($from === null) {
                $this->warnings[] = $message;
            } else {
                $this->warn($from, $line, $message);
            }

            return;
        }
        if (isset($this->loading[$path])) {
            $this->warn((string) $from, $line, sprintf('route file %s is loaded recursively', $path));

            return;
        }
        $this->loading[$path] = true;
        $this->statements($parsed->ast, $ctx, $path);
        unset($this->loading[$path]);
    }

    /** @param array<Stmt> $stmts */
    private function statements(array $stmts, RouteContext $ctx, string $file): void
    {
        foreach ($stmts as $stmt) {
            if ($stmt instanceof Stmt\Use_ || $stmt instanceof Stmt\GroupUse || $stmt instanceof Stmt\Declare_ || $stmt instanceof Stmt\Nop) {
                continue;
            }
            if ($stmt instanceof Stmt\Namespace_) {
                $this->statements($stmt->stmts, $ctx, $file);
            } elseif ($stmt instanceof Stmt\Expression) {
                $this->expression($stmt->expr, $ctx, $file);
            } else {
                $this->warn($file, $stmt->getStartLine(), sprintf('%s in route file is not analysed', self::shortName($stmt)));
            }
        }
    }

    private function expression(Expr $expr, RouteContext $ctx, string $file): void
    {
        if ($expr instanceof Expr\Include_) {
            $path = $this->eval->path($expr->expr, $file);
            if ($path === null) {
                $this->warn($file, $expr->getStartLine(), 'route file path could not be resolved');
            } else {
                $this->load($path, $ctx, $file, $expr->getStartLine());
            }

            return;
        }
        $steps = $this->flatten($expr);
        if ($steps === null) {
            $this->warn($file, $expr->getStartLine(), sprintf('%s in route file is not analysed', self::shortName($expr)));

            return;
        }
        $this->chain($steps, $ctx, $file);
    }

    /** @return list<Expr\MethodCall|Expr\StaticCall>|null the chain from its Route:: root outwards */
    private function flatten(Expr $expr): ?array
    {
        $steps = [];
        while ($expr instanceof Expr\MethodCall) {
            array_unshift($steps, $expr);
            $expr = $expr->var;
        }
        if (! $expr instanceof Expr\StaticCall || ! $expr->class instanceof Node\Name
            || ! in_array(ltrim($expr->class->toString(), '\\'), [self::FACADE, 'Route'], true)) {
            return null;
        }
        array_unshift($steps, $expr);
        foreach ($steps as $step) {
            if (! $step->name instanceof Node\Identifier) {
                return null;
            }
        }

        return $steps;
    }

    /** @param list<Expr\MethodCall|Expr\StaticCall> $steps */
    private function chain(array $steps, RouteContext $ctx, string $file): void
    {
        $route = null;
        $done = false;
        foreach ($steps as $call) {
            $name = $call->name instanceof Node\Identifier ? $call->name->toString() : '';
            $m = strtolower($name);
            $line = $call->name->getStartLine();
            $args = $this->args($call, $file, $line);
            if ($args === null) {
                continue;
            }
            if ($done) {
                $this->warn($file, $line, sprintf('route method %s is not analysed', $name));
            } elseif ($route !== null) {
                $this->routeStep($m, $name, $args, $route, $file, $line);
            } elseif (in_array($m, self::VERBS, true) || $m === 'any' || $m === 'match') {
                $route = $this->startRoute($m, $args, $ctx, $file, $line);
                if ($route === null) {
                    return;
                }
            } elseif ($m === 'group') {
                $this->group($args, $ctx, $file, $line);
                $done = true;
            } elseif (in_array($m, self::RESOURCES, true)) {
                $this->warn($file, $line, sprintf('Route::%s is not analysed yet', $name));

                return;
            } elseif (in_array($m, self::UNSUPPORTED, true)) {
                $this->warn($file, $line, sprintf('Route::%s is not analysed', $name));

                return;
            } else {
                $ctx = $this->attribute($m, $name, $args, $ctx, $file, $line);
            }
        }
        if ($route !== null) {
            $this->routes[] = $route->toEntry();
        }
    }

    /** @return list<Expr>|null positional argument values; null (with a warning) if any are spread or named */
    private function args(Expr\MethodCall|Expr\StaticCall $call, string $file, int $line): ?array
    {
        $out = [];
        foreach ($call->args as $arg) {
            if (! $arg instanceof Arg || $arg->unpack || $arg->name !== null) {
                $this->warn($file, $line, 'route arguments could not be resolved');

                return null;
            }
            $out[] = $arg->value;
        }

        return $out;
    }

    /** @param list<Expr> $args */
    private function group(array $args, RouteContext $ctx, string $file, int $line): void
    {
        if (count($args) >= 2) {
            $ctx = $this->groupAttributes($args[0], $ctx, $file, $line);
        }
        $body = $args[count($args) >= 2 ? 1 : 0] ?? null;
        if ($body instanceof Expr\Closure) {
            $this->statements($body->stmts, $ctx, $file);
        } elseif ($body instanceof Expr\ArrowFunction) {
            $this->expression($body->expr, $ctx, $file);
        } else {
            $path = $body === null ? null : $this->eval->path($body, $file);
            if ($path === null) {
                $this->warn($file, $line, 'route file path could not be resolved');
            } else {
                $this->load($path, $ctx, $file, $line);
            }
        }
    }

    private function groupAttributes(Expr $attrs, RouteContext $ctx, string $file, int $line): RouteContext
    {
        if (! $attrs instanceof Expr\Array_) {
            $this->warn($file, $line, 'route group attributes could not be resolved');

            return $ctx;
        }
        foreach ($attrs->items as $item) {
            if ($item->unpack || ! $item->key instanceof Node\Scalar\String_) {
                $this->warn($file, $line, 'route group attributes could not be resolved');

                continue;
            }
            $key = $item->key->value;
            if (strtolower($key) === 'scope_bindings') {
                if (self::isConst($item->value, 'true')) {
                    $ctx = $ctx->merge(new RouteContext(scopeBindings: true));
                } elseif (! self::isConst($item->value, 'false')) {
                    $this->warn($file, $line, 'route group attributes could not be resolved');
                }

                continue;
            }
            $method = self::GROUP_KEYS[strtolower($key)] ?? null;
            if ($method === null) {
                $this->warn($file, $line, sprintf('route group attribute %s is not analysed', $key));

                continue;
            }
            $ctx = $this->attribute($method, $key, [$item->value], $ctx, $file, $line);
        }

        return $ctx;
    }

    /** @param list<Expr> $args */
    private function attribute(string $m, string $name, array $args, RouteContext $ctx, string $file, int $line): RouteContext
    {
        if ($m === 'domain' || str_starts_with($m, 'where')) {
            return $ctx;
        }
        switch ($m) {
            case 'middleware':
                return $ctx->merge(new RouteContext(middleware: $this->stringList($args, $file, $line)));
            case 'withoutmiddleware':
                return $ctx->merge(new RouteContext(withoutMiddleware: $this->stringList($args, $file, $line)));
            case 'can':
                $can = $this->can($args, $file, $line);

                return $can === null ? $ctx : $ctx->merge(new RouteContext(middleware: [$can]));
            case 'scopebindings':
                return $ctx->merge(new RouteContext(scopeBindings: true));
            case 'namespace':
                if (! isset($args[0]) || self::isConst($args[0], 'null')) {
                    return $ctx;
                }
                break;
        }
        $fields = ['prefix' => 'prefix', 'name' => 'name', 'as' => 'name', 'controller' => 'controller', 'namespace' => 'namespace'];
        if (! isset($fields[$m])) {
            $this->warn($file, $line, sprintf('route method %s is not analysed', $name));

            return $ctx;
        }
        $value = isset($args[0]) ? $this->eval->string($args[0], $file) : null;
        if ($value === null) {
            $this->warn($file, $line, sprintf('route %s could not be resolved', $fields[$m]));

            return $ctx;
        }

        return $ctx->merge(match ($fields[$m]) {
            'prefix' => new RouteContext(prefix: $value),
            'name' => new RouteContext(namePrefix: $value),
            'controller' => new RouteContext(controller: $value),
            default => new RouteContext(namespace: $value),
        });
    }

    /** @param list<Expr> $args */
    private function can(array $args, string $file, int $line): ?string
    {
        $ability = isset($args[0]) ? $this->eval->string($args[0], $file) : null;
        if ($ability === null) {
            $this->warn($file, $line, 'route middleware could not be resolved');

            return null;
        }
        $models = [];
        if (isset($args[1]) && ! self::isConst($args[1], 'null')) {
            $models = $this->lists->strictStringList([$args[1]], $file, $line, 'middleware', $this->warnings);
            if ($models === null) {
                return null;
            }
        }

        return 'can:'.$ability.($models === [] ? '' : ','.implode(',', $models));
    }

    /** @param list<Expr> $args */
    private function startRoute(string $m, array $args, RouteContext $ctx, string $file, int $line): ?PendingRoute
    {
        if ($m === 'match') {
            $methods = isset($args[0]) ? $this->lists->strictStringList([$args[0]], $file, $line, 'methods', $this->warnings) : [];
            if ($methods === []) {
                $this->warn($file, $line, 'route methods could not be resolved');
            }
            if ($methods === null || $methods === []) {
                return null;
            }
            $methods = array_map('strtoupper', $methods);
            array_shift($args);
        } else {
            $methods = $m === 'any' ? self::ANY : [strtoupper($m)];
        }
        $uri = isset($args[0]) ? $this->eval->string($args[0], $file) : null;
        if ($uri === null) {
            $this->warn($file, $line, 'route URI could not be resolved');

            return null;
        }
        $route = new PendingRoute($methods, $uri, $ctx, $file, $line);
        $resolved = $this->actions->resolve($args[1] ?? null, $ctx, $file, $line);
        $route->action = $resolved->action;
        $route->middleware = $resolved->middleware;
        $route->name = $resolved->name;
        array_push($this->warnings, ...$resolved->warnings);

        return $route;
    }

    /** @param list<Expr> $args */
    private function routeStep(string $m, string $name, array $args, PendingRoute $route, string $file, int $line): void
    {
        if ($m === 'domain' || str_starts_with($m, 'where')) {
            return;
        }
        switch ($m) {
            case 'middleware':
                $route->middleware = [...$route->middleware, ...$this->stringList($args, $file, $line)];
                break;
            case 'withoutmiddleware':
                $route->withoutMiddleware = [...$route->withoutMiddleware, ...$this->stringList($args, $file, $line)];
                break;
            case 'can':
                $can = $this->can($args, $file, $line);
                if ($can !== null) {
                    $route->middleware[] = $can;
                }
                break;
            case 'scopebindings':
                $route->scopeBindings = true;
                break;
            case 'withoutscopedbindings':
                $route->scopeBindings = false;
                break;
            case 'name':
                $value = isset($args[0]) ? $this->eval->string($args[0], $file) : null;
                if ($value === null) {
                    $this->warn($file, $line, 'route name could not be resolved');
                } else {
                    $route->name = ($route->name ?? '').$value;
                }
                break;
            default:
                $this->warn($file, $line, sprintf('route method %s is not analysed', $name));
        }
    }

    /**
     * @param  list<Expr>  $args
     * @return list<string>
     */
    private function stringList(array $args, string $file, int $line): array
    {
        return $this->lists->stringList($args, $file, $line, 'middleware', $this->warnings);
    }

    private function warn(string $file, int $line, string $message): void
    {
        $this->warnings[] = sprintf('%s:%d: %s', $file, $line, $message);
    }

    private static function isConst(Expr $e, string $name): bool
    {
        return $e instanceof Expr\ConstFetch && strtolower($e->name->toString()) === $name;
    }

    private static function shortName(Node $node): string
    {
        return (new \ReflectionClass($node))->getShortName();
    }
}
