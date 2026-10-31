<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Llm;

/** Messages must never include the request URI or a raw Guzzle exception message (either may carry a key). */
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
