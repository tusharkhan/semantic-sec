<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Llm;

final readonly class LlmResponse
{
    /** @param array<string, mixed>|null $data decoded answer, non-null only when the outcome is Ok */
    public function __construct(
        public string $payloadId,
        public LlmOutcome $outcome,
        public ?array $data,
        public int $inputTokens,
        public int $outputTokens,
        public string $model,
        public ?string $detail = null,
    ) {
        if (($outcome === LlmOutcome::Ok) !== ($data !== null)) {
            throw new \InvalidArgumentException("LlmResponse {$payloadId}: data must be set exactly when the outcome is ok");
        }
    }
}
