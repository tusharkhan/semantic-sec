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

    public function __construct(private readonly ParseResult $parsed, private readonly ConstantEvaluator $eval)
    {
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
            $this->warnings[] = sprintf('route file %s not found', $path);

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
                $route = $this->routeStep($m, $name, $args, $route, $file, $line);
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
            $this->emit($route);
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
                return $ctx->merge(new RouteContext(middleware: $this->middleware($args, $file, $line)));
            case 'withoutmiddleware':
                return $ctx->merge(new RouteContext(withoutMiddleware: $this->middleware($args, $file, $line)));
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
            'controller' => new RouteContext(controller: ltrim($value, '\\')),
            default => new RouteContext(namespace: $value),
        });
    }

    /**
     * @param  list<Expr>  $args
     * @return list<string>
     */
    private function middleware(array $args, string $file, int $line, string $what = 'middleware'): array
    {
        $out = [];
        foreach ($args as $value) {
            foreach ($value instanceof Expr\Array_ ? $value->items : [$value] as $item) {
                if ($item instanceof Node\ArrayItem) {
                    if ($item->unpack) {
                        $this->warn($file, $line, sprintf('route %s could not be resolved', $what));

                        continue;
                    }
                    $item = $item->value;
                }
                if (self::isConst($item, 'null')) {
                    continue;
                }
                $str = $this->eval->string($item, $file);
                if ($str === null) {
                    $this->warn($file, $line, sprintf('route %s could not be resolved', $what));
                } else {
                    $out[] = $str;
                }
            }
        }

        return $out;
    }

    /** @param list<Expr> $args */
    private function can(array $args, string $file, int $line): ?string
    {
        $ability = isset($args[0]) ? $this->eval->string($args[0], $file) : null;
        $models = [];
        if ($ability !== null && isset($args[1])) {
            $models = $this->middleware([$args[1]], $file, $line);
            $expected = $args[1] instanceof Expr\Array_ ? count($args[1]->items) : 1;
            if (count($models) !== $expected) {
                return null;
            }
        }
        if ($ability === null) {
            $this->warn($file, $line, 'route middleware could not be resolved');

            return null;
        }

        return 'can:'.$ability.($models === [] ? '' : ','.implode(',', $models));
    }

    /**
     * @param  list<Expr>  $args
     * @return array{methods: list<string>, uri: string, action: RouteAction, middleware: list<string>, without: list<string>, name: ?string, scope: ?bool, ctx: RouteContext, file: string, line: int}|null
     */
    private function startRoute(string $m, array $args, RouteContext $ctx, string $file, int $line): ?array
    {
        if ($m === 'match') {
            if (! isset($args[0])) {
                $this->warn($file, $line, 'route methods could not be resolved');

                return null;
            }
            $methods = $this->middleware([$args[0]], $file, $line, 'methods');
            $expected = $args[0] instanceof Expr\Array_ ? count($args[0]->items) : 1;
            if ($methods === [] || count($methods) !== $expected) {
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
        $route = ['methods' => $methods, 'uri' => $uri, 'action' => new RouteAction(null, null), 'middleware' => [], 'without' => [], 'name' => null, 'scope' => null, 'ctx' => $ctx, 'file' => $file, 'line' => $line];
        $route['action'] = $this->action($args[1] ?? null, $route, $file, $line);

        return $route;
    }

    /**
     * @param  array{methods: list<string>, uri: string, action: RouteAction, middleware: list<string>, without: list<string>, name: ?string, scope: ?bool, ctx: RouteContext, file: string, line: int}  $route
     */
    private function action(?Expr $expr, array &$route, string $file, int $line): RouteAction
    {
        if ($expr instanceof Expr\Closure || $expr instanceof Expr\ArrowFunction) {
            return new RouteAction(null, null, $expr);
        }
        if ($expr instanceof Expr\ClassConstFetch && $expr->name instanceof Node\Identifier && strtolower($expr->name->toString()) === 'class') {
            $class = $this->eval->string($expr, $file);
            if ($class !== null) {
                return new RouteAction(self::qualify($class, $route['ctx']->namespace), '__invoke');
            }
        } elseif ($expr instanceof Expr\Array_) {
            $keyed = array_filter($expr->items, fn (Node\ArrayItem $i): bool => $i->key !== null);
            if ($keyed !== []) {
                return $this->keyedAction($expr, $route, $file, $line);
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
                return $this->stringAction($str, $route['ctx']);
            }
        }
        $this->warn($file, $line, 'route action could not be resolved');

        return new RouteAction(null, null);
    }

    /**
     * @param  array{methods: list<string>, uri: string, action: RouteAction, middleware: list<string>, without: list<string>, name: ?string, scope: ?bool, ctx: RouteContext, file: string, line: int}  $route
     */
    private function keyedAction(Expr\Array_ $expr, array &$route, string $file, int $line): RouteAction
    {
        $action = null;
        foreach ($expr->items as $item) {
            $key = $item->key instanceof Node\Scalar\String_ ? strtolower($item->key->value) : null;
            if ($item->key === null && ($item->value instanceof Expr\Closure || $item->value instanceof Expr\ArrowFunction)) {
                $action = new RouteAction(null, null, $item->value);
            } elseif ($key === 'uses') {
                $uses = $this->eval->string($item->value, $file);
                $action = $uses === null ? null : $this->stringAction($uses, $route['ctx']);
            } elseif ($key === 'middleware') {
                $route['middleware'] = [...$route['middleware'], ...$this->middleware([$item->value], $file, $line)];
            } elseif ($key === 'as') {
                $name = $this->eval->string($item->value, $file);
                if ($name === null) {
                    $this->warn($file, $line, 'route name could not be resolved');
                }
                $route['name'] = $name;
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

    /** Prepends the group namespace the way Laravel's Router::prependGroupNamespace does. */
    private static function qualify(string $class, ?string $namespace): string
    {
        if (str_starts_with($class, '\\')) {
            return ltrim($class, '\\');
        }
        if ($namespace === null || $namespace === '' || str_starts_with($class, $namespace)) {
            return $class;
        }

        return $namespace.'\\'.$class;
    }

    /**
     * @param  list<Expr>  $args
     * @param  array{methods: list<string>, uri: string, action: RouteAction, middleware: list<string>, without: list<string>, name: ?string, scope: ?bool, ctx: RouteContext, file: string, line: int}  $route
     * @return array{methods: list<string>, uri: string, action: RouteAction, middleware: list<string>, without: list<string>, name: ?string, scope: ?bool, ctx: RouteContext, file: string, line: int}
     */
    private function routeStep(string $m, string $name, array $args, array $route, string $file, int $line): array
    {
        if ($m === 'domain' || str_starts_with($m, 'where')) {
            return $route;
        }
        switch ($m) {
            case 'middleware':
                $route['middleware'] = [...$route['middleware'], ...$this->middleware($args, $file, $line)];
                break;
            case 'withoutmiddleware':
                $route['without'] = [...$route['without'], ...$this->middleware($args, $file, $line)];
                break;
            case 'can':
                $can = $this->can($args, $file, $line);
                if ($can !== null) {
                    $route['middleware'][] = $can;
                }
                break;
            case 'scopebindings':
                $route['scope'] = true;
                break;
            case 'withoutscopedbindings':
                $route['scope'] = false;
                break;
            case 'name':
                $value = isset($args[0]) ? $this->eval->string($args[0], $file) : null;
                if ($value === null) {
                    $this->warn($file, $line, 'route name could not be resolved');
                } else {
                    $route['name'] = ($route['name'] ?? '').$value;
                }
                break;
            default:
                $this->warn($file, $line, sprintf('route method %s is not analysed', $name));
        }

        return $route;
    }

    /** @param array{methods: list<string>, uri: string, action: RouteAction, middleware: list<string>, without: list<string>, name: ?string, scope: ?bool, ctx: RouteContext, file: string, line: int} $route */
    private function emit(array $route): void
    {
        $ctx = $route['ctx'];
        $uri = '/'.RouteContext::joinPath($ctx->prefix, $route['uri']);
        $name = $ctx->namePrefix.($route['name'] ?? '');

        $this->routes[] = new RouteEntry(
            $route['methods'],
            $uri,
            $name === '' ? null : $name,
            $route['action'],
            [...$ctx->middleware, ...$route['middleware']],
            [...$ctx->withoutMiddleware, ...$route['without']],
            self::parameters($uri),
            $route['scope'] ?? $ctx->scopeBindings,
            $route['file'],
            $route['line'],
        );
    }

    /** @return list<RouteParameter> */
    private static function parameters(string $uri): array
    {
        preg_match_all('/\{(\w+)(?::(\w+))?(\?)?\}/', $uri, $matches, PREG_SET_ORDER);

        return array_map(fn (array $m): RouteParameter => new RouteParameter($m[1], ($m[2] ?? '') === '' ? null : $m[2], ($m[3] ?? '') === '?'), $matches);
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
