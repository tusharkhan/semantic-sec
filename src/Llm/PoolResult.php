<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Llm;

/** Responses arrive in completion order, not request order. */
final readonly class PoolResult
{
    /**
     * @param list<LlmResponse> $responses
     * @param list<array{payloadId: string, error: string, retryable: bool}> $failures retryable is informational; the pool never retries
     */
    public function __construct(
        public array $responses,
        public array $failures,
        public int $usedTokens,
        public bool $budgetExceeded,
    ) {
    }
}
