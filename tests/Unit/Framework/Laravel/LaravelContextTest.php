<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Framework\Laravel;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Framework\Laravel\LaravelContext;

final class LaravelContextTest extends TestCase
{
    public function testFacadeMapCoversFqnAndShortAliases(): void
    {
        $map = (new LaravelContext())->facadeMap();
        $facades = ['Auth', 'Gate', 'DB', 'Cache', 'Log', 'Storage', 'Route', 'Request', 'Response', 'Session', 'Mail', 'Queue', 'Event', 'Config', 'Validator', 'Hash', 'URL', 'Redirect'];
        foreach ($facades as $facade) {
            self::assertSame('facade:'.$facade, $map['Illuminate\Support\Facades\\'.$facade] ?? null, $facade);
            self::assertSame('facade:'.$facade, $map[$facade] ?? null, $facade);
            self::assertSame('facade:'.$facade, $map['\\'.$facade] ?? null, $facade);
        }
        self::assertArrayNotHasKey('App\Services\Billing', $map);
    }

    public function testPromptContextIsShortAndFixed(): void
    {
        $text = (new LaravelContext())->promptContext();
        $lines = explode("\n", trim($text));
        self::assertGreaterThanOrEqual(5, count($lines));
        self::assertLessThanOrEqual(8, count($lines));
        self::assertSame($text, (new LaravelContext())->promptContext());
        foreach (['route model binding', 'polic', 'FormRequest', 'middleware'] as $topic) {
            self::assertStringContainsStringIgnoringCase($topic, $text);
        }
    }
}
