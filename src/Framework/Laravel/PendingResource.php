<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Framework\Laravel;

use Doctrine\Inflector\Inflector;
use Doctrine\Inflector\InflectorFactory;

/** Mutable builder for Route::resource / apiResource; expands like Laravel's ResourceRegistrar. */
final class PendingResource
{
    private const DEFAULTS = ['index', 'create', 'store', 'show', 'edit', 'update', 'destroy'];

    private const API = ['index', 'store', 'show', 'update', 'destroy'];

    private const SHALLOW = ['show', 'edit', 'update', 'destroy'];

    private static ?Inflector $inflector = null;

    public string $name = '';

    public ?string $controller = null;

    /** @var list<string>|null */
    public ?array $only = null;

    /** @var list<string> */
    public array $except = [];

    public ?string $names = null;

    /** @var array<string, string> action => full route name */
    public array $methodNames = [];

    /** @var array<string, string> resource segment => wildcard */
    public array $parameters = [];

    /** @var list<string>|null null until middleware() is called, as Laravel's isset() check needs */
    public ?array $middleware = null;

    /** @var list<string> */
    public array $withoutMiddleware = [];

    /** @var array<string, list<string>> action => middleware replacing $middleware */
    public array $middlewareFor = [];

    /** @var array<string, list<string>> action => middleware added to $withoutMiddleware */
    public array $withoutMiddlewareFor = [];

    public ?bool $scopeBindings = null;

    /** @var array<string, string> */
    public array $bindingFields = [];

    public bool $shallow = false;

    public function __construct(
        public readonly bool $api,
        public readonly RouteContext $ctx,
        public readonly string $file,
        public readonly int $line,
    ) {
    }

    /** @return list<PendingRoute> */
    public function routes(): array
    {
        $slash = strrpos($this->name, '/');
        $prefix = $slash === false ? '' : substr($this->name, 0, $slash);
        $resource = $slash === false ? $this->name : substr($this->name, $slash + 1);
        $base = $this->wildcard(self::last($resource));

        $methods = array_diff(array_intersect(self::DEFAULTS, $this->only ?? ($this->api ? self::API : self::DEFAULTS)), $this->except);
        $out = [];
        foreach ($methods as $method) {
            $name = $this->shallow && in_array($method, self::SHALLOW, true) ? self::last($resource) : $resource;
            $uri = $this->uri($name);
            [$verbs, $path] = match ($method) {
                'index' => [['GET'], $uri],
                'create' => [['GET'], $uri.'/create'],
                'store' => [['POST'], $uri],
                'show' => [['GET'], $uri.'/{'.$base.'}'],
                'edit' => [['GET'], $uri.'/{'.$base.'}/edit'],
                'update' => [['PUT', 'PATCH'], $uri.'/{'.$base.'}'],
                default => [['DELETE'], $uri.'/{'.$base.'}'],
            };
            $route = new PendingRoute($verbs, RouteContext::joinPath($prefix, $path), $this->ctx, $this->file, $this->line);
            $route->action = new RouteAction($this->controller, $this->controller === null ? null : $method);
            $route->name = $this->methodNames[$method] ?? trim(($this->names ?? $name).'.'.$method, '.');
            $route->middleware = $this->middlewareFor[$method] ?? $this->middleware ?? [];
            $route->withoutMiddleware = isset($this->withoutMiddlewareFor[$method])
                ? self::unique([...$this->withoutMiddleware, ...$this->withoutMiddlewareFor[$method]])
                : $this->withoutMiddleware;
            $route->scopeBindings = $this->scopeBindings;
            $route->bindingFields = $this->bindingFields;
            $out[] = $route;
        }

        return $out;
    }

    /** Mirrors ResourceRegistrar::getResourceUri for dotted (nested) names. */
    private function uri(string $resource): string
    {
        if (! str_contains($resource, '.')) {
            return $resource;
        }
        $segments = explode('.', $resource);
        $uri = implode('/', array_map(fn (string $s): string => $s.'/{'.$this->wildcard($s).'}', $segments));

        return str_replace('/{'.$this->wildcard(self::last($resource)).'}', '', $uri);
    }

    /** Mirrors ResourceRegistrar::getResourceWildcard with singular parameters (Laravel's default). */
    private function wildcard(string $segment): string
    {
        self::$inflector ??= InflectorFactory::create()->build();

        return str_replace('-', '_', $this->parameters[$segment] ?? self::$inflector->singularize($segment));
    }

    /**
     * Mirrors Router::uniqueMiddleware.
     *
     * @param  list<string>  $middleware
     * @return list<string>
     */
    public static function unique(array $middleware): array
    {
        return array_values(array_unique($middleware));
    }

    private static function last(string $dotted): string
    {
        $parts = explode('.', $dotted);

        return end($parts);
    }
}
