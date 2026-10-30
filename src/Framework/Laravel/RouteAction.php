<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Framework\Laravel;

use PhpParser\Node\Expr;

final readonly class RouteAction
{
    public function __construct(public ?string $class, public ?string $method, public ?Expr $closure = null)
    {
    }

    public function isClosure(): bool
    {
        return $this->closure !== null;
    }

    public function symbol(): ?string
    {
        if ($this->isClosure() || $this->class === null || $this->method === null) {
            return null;
        }

        return $this->class.'::'.$this->method;
    }
}
