<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Llm\Provider;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Llm\Provider\JsonOutput;

final class JsonOutputTest extends TestCase
{
    /** @return iterable<string, array{string, array<string, mixed>}> */
    public static function valid(): iterable
    {
        yield 'bare object' => ['{"findings":[]}', ['findings' => []]];
        yield 'surrounding whitespace' => ["  \n{\"findings\":[]}\n ", ['findings' => []]];
        yield 'one json fence' => ["```json\n{\"findings\":[{\"a\":1}]}\n```", ['findings' => [['a' => 1]]]];
        yield 'fence with whitespace' => ["\n```json  \r\n{\"findings\":[]}\r\n```\n", ['findings' => []]];
        yield 'empty object' => ['{}', []];
    }

    /** @param array<string, mixed> $expected */
    #[DataProvider('valid')]
    public function testDecodes(string $text, array $expected): void
    {
        self::assertSame($expected, JsonOutput::decode($text));
    }

    /** @return iterable<string, array{string}> */
    public static function invalid(): iterable
    {
        yield 'empty' => [''];
        yield 'prose around object' => ['Here you go: {"findings":[]}'];
        yield 'truncated' => ['{"findings":[{"title":"x'];
        yield 'list' => ['[1,2]'];
        yield 'scalar' => ['42'];
        yield 'string' => ['"x"'];
        yield 'null' => ['null'];
        yield 'two fences' => ["```json\n{}\n```\n```json\n{}\n```"];
        yield 'fence plus prose' => ["Sure:\n```json\n{}\n```"];
        yield 'unlabelled fence' => ["```\n{}\n```"];
    }

    #[DataProvider('invalid')]
    public function testRejects(string $text): void
    {
        self::assertNull(JsonOutput::decode($text));
    }
}
