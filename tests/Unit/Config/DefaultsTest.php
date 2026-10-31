<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Config;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Config\Defaults;

final class DefaultsTest extends TestCase
{
    public function testModelPerProvider(): void
    {
        self::assertSame('claude-opus-5-5', Defaults::model('anthropic'));
        self::assertSame('gpt-6-astra', Defaults::model('openai'));
        self::assertNull(Defaults::model('ollama'));
        self::assertNull(Defaults::model('nope'));
    }
}
