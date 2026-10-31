<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Llm\Http;

use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;

final class HttpClientFactory
{
    /** @param array<int|string, callable> $middleware pushed in order; string keys become middleware names */
    public static function create(?callable $handler = null, array $middleware = []): Client
    {
        $stack = HandlerStack::create($handler);
        foreach ($middleware as $name => $fn) {
            $stack->push($fn, is_string($name) ? $name : '');
        }

        return new Client(['handler' => $stack]);
    }
}
