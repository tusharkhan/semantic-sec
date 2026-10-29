<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Analysis;

enum Confidence: string
{
    case Low = 'low';
    case Medium = 'medium';
    case High = 'high';

    public function rank(): int
    {
        return match ($this) {
            self::Low => 1,
            self::Medium => 2,
            self::High => 3,
        };
    }

    public function atLeast(self $min): bool
    {
        return $this->rank() >= $min->rank();
    }
}
