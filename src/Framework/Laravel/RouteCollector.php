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

    private const SINGLETONS = ['singleton', 'apisingleton', 'singletons', 'apisingletons'];

    private const RESOURCE_OPTIONS = ['only' => 'only', 'except' => 'except', 'names' => 'names', 'parameters' => 'parameters', 'middleware' => 'middleware', 'excluded_middleware' => 'withoutmiddleware', 'shallow' => 'shallow'];

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
        $resource = null;
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
            } elseif ($resource !== null) {
                $this->resourceStep($m, $name, $args, $resource, $file, $line);
            } elseif (in_array($m, self::VERBS, true) || $m === 'any' || $m === 'match') {
                $route = $this->startRoute($m, $args, $ctx, $file, $line);
                if ($route === null) {
                    return;
                }
            } elseif ($m === 'group') {
                $this->group($args, $ctx, $file, $line);
                $done = true;
            } elseif ($m === 'resource' || $m === 'apiresource') {
                $resource = $this->startResource($m === 'apiresource', $args, $ctx, $file, $line);
                if ($resource === null) {
                    return;
                }
            } elseif ($m === 'resources' || $m === 'apiresources') {
                $this->resources($m === 'apiresources', $args, $ctx, $file, $line);
                $done = true;
            } elseif (in_array($m, self::SINGLETONS, true)) {
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
        if ($resource !== null) {
            $this->emitResource($resource);
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
                if (self::isConst($item->value, 'true') || self::isConst($item->value, 'false')) {
                    $ctx = $ctx->merge(new RouteContext(scopeBindings: self::isConst($item->value, 'true')));
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
                return $ctx->merge(new RouteContext(withoutMiddleware: $this->withoutList($args, $file, $line)));
            case 'can':
                $can = $this->can($args, $file, $line);

                return $can === null ? $ctx : $ctx->merge(new RouteContext(middleware: [$can]));
            case 'scopebindings':
                return $ctx->merge(new RouteContext(scopeBindings: true));
            case 'withoutscopedbindings':
                return $ctx->merge(new RouteContext(scopeBindings: false));
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
                $route->withoutMiddleware = [...$route->withoutMiddleware, ...$this->withoutList($args, $file, $line)];
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

    /** @param list<Expr> $args */
    private function startResource(bool $api, array $args, RouteContext $ctx, string $file, int $line): ?PendingResource
    {
        $name = isset($args[0]) ? $this->eval->string($args[0], $file) : null;
        if ($name === null) {
            $this->warn($file, $line, 'route resource name could not be resolved');

            return null;
        }
        $resource = new PendingResource($api, $ctx, $file, $line);
        $resource->name = $name;
        $resource->controller = $this->resourceController($args[1] ?? null, $ctx, $file, $line);
        if (isset($args[2])) {
            $this->resourceOptions($args[2], $resource, $file, $line);
        }

        return $resource;
    }

    /** @param list<Expr> $args */
    private function resources(bool $api, array $args, RouteContext $ctx, string $file, int $line): void
    {
        if (! isset($args[0]) || ! $args[0] instanceof Expr\Array_) {
            $this->warn($file, $line, 'route resources could not be resolved');

            return;
        }
        $template = new PendingResource($api, $ctx, $file, $line);
        if (isset($args[1])) {
            $this->resourceOptions($args[1], $template, $file, $line);
        }
        foreach ($args[0]->items as $item) {
            $name = $item->key === null || $item->unpack ? null : $this->eval->string($item->key, $file);
            if ($name === null) {
                $this->warn($file, $line, 'route resource name could not be resolved');

                continue;
            }
            $resource = clone $template;
            $resource->name = $name;
            $resource->controller = $this->resourceController($item->value, $ctx, $file, $line);
            $this->emitResource($resource);
        }
    }

    private function resourceController(?Expr $expr, RouteContext $ctx, string $file, int $line): ?string
    {
        $class = $expr === null ? null : $this->eval->string($expr, $file);
        if ($class === null) {
            $this->warn($file, $line, 'route action could not be resolved');

            return null;
        }

        return RouteActionResolver::qualify($class, $ctx->namespace);
    }

    private function resourceOptions(Expr $options, PendingResource $resource, string $file, int $line): void
    {
        if (! $options instanceof Expr\Array_) {
            $this->warn($file, $line, 'route resource options could not be resolved');

            return;
        }
        foreach ($options->items as $item) {
            $key = $item->key === null || $item->unpack ? null : $this->eval->string($item->key, $file);
            if ($key !== null && in_array(strtolower($key), ['middleware_for', 'excluded_middleware_for'], true)) {
                $before = count($this->warnings);
                $map = $this->perMethodMiddleware($item->value, $file, $line);
                if (strtolower($key) === 'middleware_for') {
                    $resource->middlewareFor = $map;
                } else {
                    $resource->withoutMiddlewareFor = $map;
                    if (count($this->warnings) > $before) {
                        $resource->withoutMiddleware[] = RouteEntry::UNRESOLVED;
                    }
                }

                continue;
            }
            $method = $key === null ? null : (self::RESOURCE_OPTIONS[strtolower($key)] ?? null);
            if ($method === null) {
                $this->warn($file, $line, $key === null ? 'route resource options could not be resolved' : sprintf('route resource option %s is not analysed', $key));

                continue;
            }
            $this->resourceStep($method, $key, [$item->value], $resource, $file, $line);
        }
    }

    /** @param list<Expr> $args */
    private function resourceStep(string $m, string $name, array $args, PendingResource $resource, string $file, int $line): void
    {
        if (str_starts_with($m, 'where')) {
            return;
        }
        switch ($m) {
            case 'only':
                $before = count($this->warnings);
                $only = $this->lists->stringList($args, $file, $line, 'resource methods', $this->warnings);
                if ($only !== [] || count($this->warnings) === $before) {
                    $resource->only = $only;
                }
                break;
            case 'except':
                $resource->except = $this->lists->stringList($args, $file, $line, 'resource methods', $this->warnings);
                break;
            case 'names':
                if (isset($args[0]) && $args[0] instanceof Expr\Array_) {
                    $resource->methodNames = $this->stringMap($args[0], $file, $line, 'names');
                    $resource->names = null;
                } else {
                    $names = isset($args[0]) ? $this->eval->string($args[0], $file) : null;
                    if ($names === null) {
                        $this->warn($file, $line, 'route resource names could not be resolved');
                    } else {
                        $resource->names = $names;
                        $resource->methodNames = [];
                    }
                }
                break;
            case 'name':
                $method = isset($args[0]) ? $this->eval->string($args[0], $file) : null;
                $value = isset($args[1]) ? $this->eval->string($args[1], $file) : null;
                if ($method === null || $value === null) {
                    $this->warn($file, $line, 'route resource names could not be resolved');
                } else {
                    $resource->methodNames[$method] = $value;
                }
                break;
            case 'parameters':
                if (isset($args[0]) && $args[0] instanceof Expr\Array_) {
                    $resource->parameters = $this->stringMap($args[0], $file, $line, 'parameters');
                } elseif (isset($args[0]) && $this->eval->string($args[0], $file) === 'singular') {
                    $resource->parameters = [];
                } else {
                    $this->warn($file, $line, 'route resource parameters could not be resolved');
                }
                break;
            case 'parameter':
                $segment = isset($args[0]) ? $this->eval->string($args[0], $file) : null;
                $value = isset($args[1]) ? $this->eval->string($args[1], $file) : null;
                if ($segment === null || $value === null) {
                    $this->warn($file, $line, 'route resource parameters could not be resolved');
                } else {
                    $resource->parameters[$segment] = $value;
                }
                break;
            case 'middleware':
                $resource->middleware = $this->stringList($args, $file, $line);
                foreach ($resource->middlewareFor as $method => $middleware) {
                    $resource->middlewareFor[$method] = PendingResource::unique([...$middleware, ...$resource->middleware]);
                }
                break;
            case 'middlewarefor':
            case 'withoutmiddlewarefor':
                $methods = $this->strictList($args[0] ?? null, $file, $line);
                $middleware = $this->strictList($args[1] ?? null, $file, $line);
                if ($methods === null || $middleware === null) {
                    if ($m === 'withoutmiddlewarefor') {
                        $resource->withoutMiddleware[] = RouteEntry::UNRESOLVED;
                    }
                    break;
                }
                if ($m === 'middlewarefor' && $resource->middleware !== null) {
                    $middleware = PendingResource::unique([...$resource->middleware, ...$middleware]);
                }
                foreach ($methods as $method) {
                    if ($m === 'middlewarefor') {
                        $resource->middlewareFor[$method] = $middleware;
                    } else {
                        $resource->withoutMiddlewareFor[$method] = $middleware;
                    }
                }
                break;
            case 'withoutmiddleware':
                $resource->withoutMiddleware = [...$resource->withoutMiddleware, ...$this->withoutList($args, $file, $line)];
                break;
            case 'scopebindings':
                $resource->scopeBindings = true;
                break;
            case 'scoped':
                $resource->scopeBindings = true;
                if (isset($args[0]) && $args[0] instanceof Expr\Array_) {
                    $resource->bindingFields = $this->stringMap($args[0], $file, $line, 'binding fields');
                } elseif (isset($args[0])) {
                    $this->warn($file, $line, 'route resource binding fields could not be resolved');
                }
                break;
            case 'shallow':
                if (isset($args[0]) && ! self::isConst($args[0], 'true') && ! self::isConst($args[0], 'false')) {
                    $this->warn($file, $line, 'route resource shallow could not be resolved');
                } else {
                    $resource->shallow = ! isset($args[0]) || self::isConst($args[0], 'true');
                }
                break;
            default:
                $this->warn($file, $line, sprintf('route method %s is not analysed', $name));
        }
    }

    /** @return list<string>|null a string or list argument; null (with a warning) if missing or not fully resolvable */
    private function strictList(?Expr $arg, string $file, int $line): ?array
    {
        if ($arg === null) {
            $this->warn($file, $line, 'route middleware could not be resolved');

            return null;
        }

        return $this->lists->strictStringList([$arg], $file, $line, 'middleware', $this->warnings);
    }

    /** @return array<string, list<string>> an action => middleware option map; unresolvable entries are dropped with a warning */
    private function perMethodMiddleware(Expr $value, string $file, int $line): array
    {
        if (! $value instanceof Expr\Array_) {
            $this->warn($file, $line, 'route middleware could not be resolved');

            return [];
        }
        $out = [];
        foreach ($value->items as $item) {
            $method = $item->key === null || $item->unpack ? null : $this->eval->string($item->key, $file);
            $middleware = $method === null ? null : $this->strictList($item->value, $file, $line);
            if ($method === null) {
                $this->warn($file, $line, 'route middleware could not be resolved');
            } elseif ($middleware !== null) {
                $out[$method] = $middleware;
            }
        }

        return $out;
    }

    /** @return array<string, string> string-keyed array literal; unresolvable pairs are dropped with a warning */
    private function stringMap(Expr\Array_ $array, string $file, int $line, string $what): array
    {
        $out = [];
        foreach ($array->items as $item) {
            $key = $item->key === null || $item->unpack ? null : $this->eval->string($item->key, $file);
            $value = $key === null ? null : $this->eval->string($item->value, $file);
            if ($key === null || $value === null) {
                $this->warn($file, $line, sprintf('route resource %s could not be resolved', $what));
            } else {
                $out[$key] = $value;
            }
        }

        return $out;
    }

    private function emitResource(PendingResource $resource): void
    {
        foreach ($resource->routes() as $route) {
            $this->routes[] = $route->toEntry();
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

    /**
     * Like stringList(), but records an unresolvable item as RouteEntry::UNRESOLVED.
     *
     * @param  list<Expr>  $args
     * @return list<string>
     */
    private function withoutList(array $args, string $file, int $line): array
    {
        $before = count($this->warnings);
        $list = $this->stringList($args, $file, $line);
        if (count($this->warnings) > $before) {
            $list[] = RouteEntry::UNRESOLVED;
        }

        return $list;
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
