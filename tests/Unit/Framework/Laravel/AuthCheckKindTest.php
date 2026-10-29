<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Framework\Laravel;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Framework\Laravel\AuthCheckKind;

final class AuthCheckKindTest extends TestCase
{
    public function testEveryValueRoundTripsThroughTryFrom(): void
    {
        self::assertCount(7, AuthCheckKind::cases());

        foreach (AuthCheckKind::cases() as $kind) {
            self::assertSame($kind, AuthCheckKind::tryFrom($kind->value));
        }
    }
}
