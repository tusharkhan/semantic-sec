<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Llm;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Llm\LlmOutcome;
use TusharKhan\SemanticSec\Llm\LlmResponse;

final class LlmResponseTest extends TestCase
{
    public function testDetailLosesC0AndC1ControlCharacters(): void
    {
        $r = new LlmResponse('p', LlmOutcome::Refused, null, 0, 0, 'm', "cy\x1b[2Jber\x07 \xc2\x9b31m\nnext\tline \u{00e9}");

        self::assertSame("cy [2Jber   31m next line \u{00e9}", $r->detail);
    }

    public function testNullDetailStaysNull(): void
    {
        self::assertNull((new LlmResponse('p', LlmOutcome::Ok, [], 0, 0, 'm'))->detail);
    }
}
