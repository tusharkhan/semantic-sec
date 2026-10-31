<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Llm;

final readonly class LlmResponse
{
    // Free text from the provider or the model, without C0 or C1 control characters (no terminal escapes).
    public ?string $detail;

    /** @param array<string, mixed>|null $data decoded answer, non-null only when the outcome is Ok */
    public function __construct(
        public string $payloadId,
        public LlmOutcome $outcome,
        public ?array $data,
        public int $inputTokens,
        public int $outputTokens,
        public string $model,
        ?string $detail = null,
    ) {
        $this->detail = self::clean($detail);
        if (($outcome === LlmOutcome::Ok) !== ($data !== null)) {
            throw new \InvalidArgumentException("LlmResponse {$payloadId}: data must be set exactly when the outcome is ok");
        }
    }

    // One line with C0, DEL and C1 controls replaced, so model text cannot drive a terminal.
    public static function clean(?string $text): ?string
    {
        return $text === null ? null : trim((string) preg_replace('/(?:[\x00-\x1F\x7F]|\xC2[\x80-\x9F])+/', ' ', $text));
    }
}
