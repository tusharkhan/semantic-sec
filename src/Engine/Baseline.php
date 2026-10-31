<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Engine;

/** Fingerprints accepted as known findings (SPEC §11.4); file IO is M7. */
final readonly class Baseline
{
    /** @param array<string, true> $fingerprints */
    private function __construct(private array $fingerprints)
    {
    }

    public static function empty(): self
    {
        return new self([]);
    }

    /** @param list<string> $fingerprints */
    public static function of(array $fingerprints): self
    {
        return new self(array_fill_keys($fingerprints, true));
    }

    public function contains(string $fingerprint): bool
    {
        return isset($this->fingerprints[$fingerprint]);
    }
}
