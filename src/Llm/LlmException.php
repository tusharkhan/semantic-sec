<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Llm;

final class LlmException extends \RuntimeException
{
    public function __construct(
        string $message,
        public readonly ?int $status = null,
        public readonly bool $retryable = false,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }
}
