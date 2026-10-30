<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Framework\Laravel;

final readonly class RouteEntry
{
    /**
     * @param  list<string>  $methods  upper-case as declared (no implicit HEAD)
     * @param  list<string>  $middleware  declared + group/inherited, raw-resolved strings
     * @param  list<string>  $withoutMiddleware
     * @param  list<RouteParameter>  $parameters
     * @param  list<AuthCheck>  $checks
     */
    public function __construct(
        public array $methods,
        public string $uri,
        public ?string $name,
        public RouteAction $action,
        public array $middleware,
        public array $withoutMiddleware,
        public array $parameters,
        public ?bool $scopeBindings, // null default, true scopeBindings(), false withoutScopedBindings()
        public string $file,
        public int $line,
        public array $checks = [],
    ) {
    }

    /** @return list<string> */
    public function keys(): array
    {
        return array_map(fn (string $m): string => $m.' '.$this->uri, $this->methods);
    }

    /** @param list<AuthCheck> $checks */
    public function withChecks(array $checks): self
    {
        return new self($this->methods, $this->uri, $this->name, $this->action, $this->middleware, $this->withoutMiddleware, $this->parameters, $this->scopeBindings, $this->file, $this->line, $checks);
    }

    /** @param list<RouteParameter> $parameters */
    public function withParameters(array $parameters): self
    {
        return new self($this->methods, $this->uri, $this->name, $this->action, $this->middleware, $this->withoutMiddleware, $parameters, $this->scopeBindings, $this->file, $this->line, $this->checks);
    }
}
