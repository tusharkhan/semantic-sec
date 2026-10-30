<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Framework\Laravel;

/** Mutable builder for one route while its fluent chain is being read. */
final class PendingRoute
{
    public RouteAction $action;

    /** @var list<string> */
    public array $middleware = [];

    /** @var list<string> */
    public array $withoutMiddleware = [];

    public ?string $name = null;

    public ?bool $scopeBindings = null;

    public ?string $domain = null;

    public bool $domainUnknown = false;

    /** @var array<string, string> parameter name => binding field */
    public array $bindingFields = [];

    /** @param list<string> $methods */
    public function __construct(
        public array $methods,
        public string $uri,
        public readonly RouteContext $ctx,
        public readonly string $file,
        public readonly int $line,
    ) {
        $this->action = new RouteAction(null, null);
    }

    public function toEntry(): RouteEntry
    {
        $uri = '/'.RouteContext::joinPath($this->ctx->prefix, $this->uri);
        $name = $this->ctx->namePrefix.($this->name ?? '');

        return new RouteEntry(
            $this->methods,
            $uri,
            $name === '' ? null : $name,
            $this->action,
            [...$this->ctx->middleware, ...$this->middleware],
            [...$this->ctx->withoutMiddleware, ...$this->withoutMiddleware],
            $this->parameters($uri),
            $this->scopeBindings ?? $this->ctx->scopeBindings,
            $this->file,
            $this->line,
        );
    }

    /** @return list<RouteParameter> */
    private function parameters(string $uri): array
    {
        preg_match_all('/\{(\w+)(?::(\w+))?(\?)?\}/', $uri, $matches, PREG_SET_ORDER);
        $domain = [];
        if (! $this->domainUnknown && ($this->domain ?? $this->ctx->domain) !== null) {
            preg_match_all('/\{(\w+)(\?)?\}/', $this->domain ?? (string) $this->ctx->domain, $found, PREG_SET_ORDER);
            $domain = array_map(static fn (array $m): RouteParameter => new RouteParameter($m[1], null, ($m[2] ?? '') === '?', null, true), $found);
        }

        return [...$domain, ...array_map(fn (array $m): RouteParameter => new RouteParameter(
            $m[1],
            ($m[2] ?? '') !== '' ? $m[2] : ($this->bindingFields[$m[1]] ?? null),
            ($m[3] ?? '') === '?',
        ), $matches)];
    }
}
