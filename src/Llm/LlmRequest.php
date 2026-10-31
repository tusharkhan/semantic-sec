<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Llm;

final readonly class LlmRequest
{
    /** @param array<string, mixed> $schema JSON Schema the answer must match */
    public function __construct(
        public string $payloadId,
        public string $system,
        public string $user,
        public array $schema,
        public string $model,
        public int $maxTokens = 16000,
        public ?string $effort = null,
    ) {
    }

    public function withUserSuffix(string $s): self
    {
        return new self($this->payloadId, $this->system, $this->user . $s, $this->schema, $this->model, $this->maxTokens, $this->effort);
    }
}
