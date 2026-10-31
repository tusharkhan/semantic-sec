<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Llm;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Llm\ResponseValidator;

final class ResponseValidatorTest extends TestCase
{
    public function testValidPasses(): void
    {
        self::assertSame([], ResponseValidator::errors(['findings' => [self::finding()]]));
        self::assertSame([], ResponseValidator::errors(['findings' => []]));
    }

    public function testTitleOver120Rejected(): void
    {
        self::assertSame([], ResponseValidator::errors(['findings' => [self::finding(['title' => str_repeat('é', 120)])]]), '120 multibyte chars fit');

        $errors = ResponseValidator::errors(['findings' => [self::finding(['title' => str_repeat('é', 121)])]]);
        self::assertSame(['/findings/0/title: must be 120 characters or fewer'], $errors);
    }

    public function testEmptyObjectFails(): void
    {
        $errors = ResponseValidator::errors([]);

        self::assertNotSame([], $errors);
        self::assertStringContainsString('findings', implode(' ', $errors));
    }

    public function testLineBelowOneRejected(): void
    {
        $finding = self::finding(['line' => 0, 'path' => [['file' => 'a.php', 'line' => 3, 'symbol' => 'A'], ['file' => 'a.php', 'line' => -2, 'symbol' => 'A']]]);

        self::assertSame(['/findings/0/line: must be 1 or more', '/findings/0/path/1/line: must be 1 or more'], ResponseValidator::errors(['findings' => [$finding]]));
    }

    public function testSchemaErrorsReported(): void
    {
        $errors = ResponseValidator::errors(['findings' => [self::finding(['category' => 'sqli'])]]);

        self::assertCount(1, $errors);
        self::assertStringStartsWith('/findings/0/category: ', $errors[0]);
    }

    public function testExtraKeysAndWrongTypesReportedWithoutCrash(): void
    {
        $errors = ResponseValidator::errors(['findings' => [self::finding(['line' => 'nineteen', 'title' => 7, 'path' => 'x']), 'not-an-object'], 'extra' => true]);

        self::assertNotSame([], $errors);
        foreach ($errors as $error) {
            self::assertLessThanOrEqual(200, mb_strlen($error));
        }
    }

    public function testHugeKeyNameIsShortened(): void
    {
        $errors = ResponseValidator::errors(['findings' => [], str_repeat('k', 5000) => 1]);

        self::assertNotSame([], $errors);
        foreach ($errors as $error) {
            self::assertLessThanOrEqual(200, mb_strlen($error));
        }
    }

    /**
     * @param  array<string, mixed>  $override
     * @return array<string, mixed>
     */
    public static function finding(array $override = []): array
    {
        return [...[
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
        ], ...$override];
    }
}
