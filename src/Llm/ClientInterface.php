<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Llm;

use GuzzleHttp\Promise\PromiseInterface;

interface ClientInterface
{
    /** Resolves to an LlmResponse; rejects with an LlmException. */
    public function analyze(LlmRequest $request): PromiseInterface;
}
