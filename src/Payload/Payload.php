<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Payload;

use TusharKhan\SemanticSec\Candidates\Candidate;

/** One LLM payload (SPEC §9): the context block, a blank line, then the fenced, line-tagged code. Both parts are already escaped and redacted. */
final readonly class Payload
{
    public function __construct(
        public string $id,
        public Candidate $candidate,
        public string $context,
        public string $code,
        public int $part,
        public int $parts,
        public bool $truncated,
    ) {
    }

    public function text(): string
    {
        return $this->context."\n\n".$this->code;
    }

    public function tokens(): int
    {
        return TokenEstimator::estimate($this->text());
    }
}
