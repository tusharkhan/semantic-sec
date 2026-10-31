<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Llm;

/** Responses arrive in completion order; usedTokens includes failed schema retries, and the budget may overshoot by up to `concurrency` slots, each spending up to two calls (the schema retry reuses its slot). */
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
        // True when a dispatch was skipped or usedTokens ended above the budget.
        public bool $budgetExceeded,
    ) {
    }
}
