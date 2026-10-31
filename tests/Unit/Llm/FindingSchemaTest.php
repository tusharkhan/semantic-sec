<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Llm;

use Opis\JsonSchema\Validator;
use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Llm\FindingSchema;

final class FindingSchemaTest extends TestCase
{
    public function testSchemaIsValidJsonSchemaAndStrictSafe(): void
    {
        $schema = FindingSchema::schema();

        self::assertTrue(self::validate(['findings' => [self::finding()]]), 'a full finding validates');
        self::assertFalse(self::validate(['findings' => [[...self::finding(), 'extra' => 1]]]), 'extra keys are rejected');
        self::assertFalse(self::validate(['findings' => [[...self::finding(), 'category' => 'sqli']]]), 'unknown category is rejected');

        $objects = 0;
        self::walk($schema, static function (array $node, string $where) use (&$objects): void {
            foreach (['maxLength', 'minLength', 'minimum', 'maximum', '$ref', '$defs', 'definitions'] as $banned) {
                self::assertArrayNotHasKey($banned, $node, $where.' uses '.$banned);
            }
            if (($node['type'] ?? null) !== 'object') {
                return;
            }
            $objects++;
            self::assertFalse($node['additionalProperties'] ?? null, $where.' must set additionalProperties: false');
            self::assertIsArray($node['properties'] ?? null, $where.' has properties');
            self::assertSame(array_keys($node['properties']), $node['required'] ?? null, $where.' requires every property');
        });
        self::assertSame(3, $objects);

        $item = $schema['properties']['findings']['items'];
        self::assertSame(['idor', 'missing_authorization', 'mass_assignment', 'insecure_deserialization', 'workflow_bypass'], $item['properties']['category']['enum']);
        self::assertSame(['low', 'medium', 'high', 'critical'], $item['properties']['severity']['enum']);
        self::assertSame(['low', 'medium', 'high'], $item['properties']['confidence']['enum']);
        self::assertSame(['file', 'line', 'symbol'], array_keys($item['properties']['path']['items']['properties']));
        self::assertSame('semantic_sec_findings', FindingSchema::NAME);
    }

    public function testEmptyFindingsIsValid(): void
    {
        self::assertTrue(self::validate(['findings' => []]));
        self::assertFalse(self::validate([]));
    }

    /** @return array<string, mixed> */
    private static function finding(): array
    {
        return [
            'title' => 'Invoice readable by any user',
            'category' => 'idor',
            'severity' => 'high',
            'confidence' => 'high',
            'file' => 'app/Http/Controllers/InvoiceController.php',
            'line' => 19,
            'symbol' => 'App\Http\Controllers\InvoiceController::show',
            'context' => 'GET /invoices/{id} behind auth only',
            'flaw' => 'findOrFail($id) loads any invoice',
            'fix' => 'Authorize with the InvoicePolicy',
            'patch' => '',
            'path' => [['file' => 'app/Http/Controllers/InvoiceController.php', 'line' => 19, 'symbol' => 'App\Http\Controllers\InvoiceController::show']],
        ];
    }

    /** @param array<string, mixed> $data */
    private static function validate(array $data): bool
    {
        $schema = json_decode((string) json_encode(FindingSchema::schema()), false);
        $value = json_decode((string) json_encode((object) $data), false);

        return (new Validator())->validate($value, $schema)->isValid();
    }

    /**
     * @param  array<mixed>  $node
     * @param  callable(array<mixed>, string): void  $visit
     */
    private static function walk(array $node, callable $visit, string $where = '#'): void
    {
        $visit($node, $where);
        foreach ($node['properties'] ?? [] as $name => $child) {
            self::walk($child, $visit, $where.'/'.$name);
        }
        if (isset($node['items'])) {
            self::walk($node['items'], $visit, $where.'/items');
        }
    }
}
