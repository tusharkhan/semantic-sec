<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Llm;

use TusharKhan\SemanticSec\Analysis\Category;
use TusharKhan\SemanticSec\Analysis\Confidence;
use TusharKhan\SemanticSec\Analysis\Severity;

final class FindingSchema
{
    public const NAME = 'semantic_sec_findings';

    // Strict-mode safe: every property required, no extra keys, no $ref, no length or range bounds.
    /** @return array<string, mixed> */
    public static function schema(): array
    {
        $step = self::object([
            'file' => ['type' => 'string'],
            'line' => ['type' => 'integer'],
            'symbol' => ['type' => 'string'],
        ]);

        $finding = self::object([
            'title' => ['type' => 'string'],
            'category' => ['type' => 'string', 'enum' => array_column(Category::cases(), 'value')],
            'severity' => ['type' => 'string', 'enum' => array_column(Severity::cases(), 'value')],
            'confidence' => ['type' => 'string', 'enum' => array_column(Confidence::cases(), 'value')],
            'file' => ['type' => 'string'],
            'line' => ['type' => 'integer'],
            'symbol' => ['type' => 'string'],
            'context' => ['type' => 'string'],
            'flaw' => ['type' => 'string'],
            'fix' => ['type' => 'string'],
            'patch' => ['type' => 'string'],
            'path' => ['type' => 'array', 'items' => $step],
        ]);

        return self::object(['findings' => ['type' => 'array', 'items' => $finding]]);
    }

    /**
     * @param  array<string, array<string, mixed>>  $properties
     * @return array<string, mixed>
     */
    private static function object(array $properties): array
    {
        return [
            'type' => 'object',
            'properties' => $properties,
            'required' => array_keys($properties),
            'additionalProperties' => false,
        ];
    }
}
