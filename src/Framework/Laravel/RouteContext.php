<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Framework\Laravel;

/** Immutable route-group state inherited by every route declared inside the group. */
final readonly class RouteContext
{
    /**
     * @param  list<string>  $middleware
     * @param  list<string>  $withoutMiddleware
     */
    public function __construct(
        public string $prefix = '',
        public array $middleware = [],
        public array $withoutMiddleware = [],
        public string $namePrefix = '',
        public ?string $controller = null,
        public ?string $namespace = null,
        public ?bool $scopeBindings = null,
    ) {
    }

    public static function fromFile(RouteFile $file): self
    {
        return new self(trim($file->prefix, '/'), $file->middleware, [], '', null, $file->namespace === null ? null : trim($file->namespace, '\\'));
    }

    /** Merges an inner group's attributes the way Laravel's RouteGroup::merge does. */
    public function merge(self $inner): self
    {
        $namespace = $this->namespace;
        if ($inner->namespace !== null) {
            $namespace = $this->namespace !== null && ! str_starts_with($inner->namespace, '\\')
                ? trim($this->namespace, '\\').'\\'.trim($inner->namespace, '\\')
                : trim($inner->namespace, '\\');
        }

        return new self(
            self::joinPath($this->prefix, $inner->prefix),
            [...$this->middleware, ...$inner->middleware],
            [...$this->withoutMiddleware, ...$inner->withoutMiddleware],
            $this->namePrefix.$inner->namePrefix,
            $inner->controller ?? $this->controller,
            $namespace,
            $inner->scopeBindings ?? $this->scopeBindings,
        );
    }

    public static function joinPath(string ...$parts): string
    {
        $parts = array_filter(array_map(fn (string $p): string => trim($p, '/'), $parts), fn (string $p): bool => $p !== '');

        return implode('/', $parts);
    }
}
