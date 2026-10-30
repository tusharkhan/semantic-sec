<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Payload;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Payload\Redactor;

final class RedactorTest extends TestCase
{
    private const HIGH = 'Zq8xK2mR9vL4tW7yB3nC5';

    /** @return array<string, array{string}> */
    public static function secretProvider(): array
    {
        return [
            'aws' => ['AKIAIOSFODNN7EXAMPLE'],
            'sk dash' => ['sk-abcdEFGH1234ijklMNOP5678'],
            'sk_live' => ['sk_live_4eC39HqLyjWDarjtT1zdp7dc'],
            'sk_test' => ['sk_test_4eC39HqLyjWDarjtT1zdp7dc'],
            'pk_live' => ['pk_live_4eC39HqLyjWDarjtT1zdp7dc'],
            'rk_live' => ['rk_live_4eC39HqLyjWDarjtT1zdp7dc'],
            'ghp' => ['ghp_abcdefghijklmnopqrstuvwxyz0123456789'],
            'gho' => ['gho_abcdefghijklmnopqrstuvwxyz0123456789'],
            'github_pat' => ['github_pat_11ABCDEFG0abcdefghijkl_mnopqrstuvwxyz'],
            'slack bot' => ['xoxb-123456789012-1234567890123-AbCdEfGh'],
            'slack user' => ['xoxp-123456789012-1234567890123-AbCdEfGh'],
            'jwt' => ['eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uh'],
        ];
    }

    #[DataProvider('secretProvider')]
    public function testSingleQuotedTokenIsRedacted(string $secret): void
    {
        self::assertSame("\$k = '<redacted>';", (new Redactor())->redact("\$k = '{$secret}';"));
    }

    #[DataProvider('secretProvider')]
    public function testDoubleQuotedTokenIsRedacted(string $secret): void
    {
        self::assertSame('$k = "<redacted>";', (new Redactor())->redact("\$k = \"{$secret}\";"));
    }

    #[DataProvider('secretProvider')]
    public function testTokenOutsideLiteralIsRedacted(string $secret): void
    {
        $out = (new Redactor())->redact("// the key is {$secret} ok");

        self::assertSame('// the key is <redacted> ok', $out);
    }

    public function testNearMissTokensAreKept(): void
    {
        foreach (['AKIA123', 'sk-short', 'ghp_short', 'xoxz-1234567890', 'eyJabc.def', 'task-aaaaaaaaaaaaaaaaaaaaaaa', 'sk_live_short'] as $s) {
            self::assertSame("\$k = '{$s}';", (new Redactor())->redact("\$k = '{$s}';"), $s);
        }
    }

    public function testHeredocBodyIsRedactedKeepingMarkers(): void
    {
        $in = "\$k = <<<EOT\nhello world\n  AKIAIOSFODNN7EXAMPLE\n" . self::HIGH . "\nEOT;\n";
        $out = (new Redactor())->redact($in);

        self::assertSame("\$k = <<<EOT\nhello world\n  <redacted>\n<redacted>\nEOT;\n", $out);
    }

    public function testNowdocBodyIsRedacted(): void
    {
        $in = "\$k = <<<'EOT'\n" . self::HIGH . "\nEOT;\n";

        self::assertSame("\$k = <<<'EOT'\n<redacted>\nEOT;\n", (new Redactor())->redact($in));
    }

    public function testTaggedHeredocKeepsLinePrefixes(): void
    {
        $in = "L3| \$k = <<<EOT\nL4| " . self::HIGH . "\nL5| EOT;\nL6| \$x = 1;";

        self::assertSame("L3| \$k = <<<EOT\nL4| <redacted>\nL5| EOT;\nL6| \$x = 1;", (new Redactor())->redact($in));
    }

    public function testPemBlockBodyIsRedactedAndLineCountKept(): void
    {
        $in = "L1| \$k = <<<KEY\nL2| -----BEGIN RSA PRIVATE KEY-----\nL3| MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn\nL4| /ZXk9bQq2xT7vJf0hNq1pL8oKd\nL5| -----END RSA PRIVATE KEY-----\nL6| KEY;";
        $out = (new Redactor())->redact($in);

        self::assertSame(substr_count($in, "\n"), substr_count($out, "\n"));
        self::assertSame("L1| \$k = <<<KEY\nL2| -----BEGIN RSA PRIVATE KEY-----\nL3| <redacted>\nL4| <redacted>\nL5| -----END RSA PRIVATE KEY-----\nL6| KEY;", $out);
    }

    public function testPemInsideEscapedSingleLineStringIsRedacted(): void
    {
        $in = "\$k = '-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0B\\n-----END PRIVATE KEY-----';";
        $out = (new Redactor())->redact($in);

        self::assertStringNotContainsString('MIIE', $out);
        self::assertStringContainsString('-----BEGIN PRIVATE KEY-----', $out);
    }

    public function testTruncatedPemWithoutEndIsRedactedToTheEnd(): void
    {
        $out = (new Redactor())->redact("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0B\nabcdef");

        self::assertSame("-----BEGIN PRIVATE KEY-----\n<redacted>\n<redacted>", $out);
    }

    public function testEntropyThresholdJustUnderIsKept(): void
    {
        $s = 'aB3dE5gH7jK9mN1paB3d';

        self::assertSame(20, strlen($s));
        self::assertSame("\$k = '{$s}';", (new Redactor())->redact("\$k = '{$s}';"));
    }

    public function testEntropyThresholdJustOverIsRedacted(): void
    {
        $s = 'aB3dE5gH7jK9mN1pQ2sT';

        self::assertSame(20, strlen($s));
        self::assertSame("\$k = '<redacted>';", (new Redactor())->redact("\$k = '{$s}';"));
    }

    public function testExactlyFourBitsIsKept(): void
    {
        $s = 'aB3dE5gH7jK9mN1p' . 'aB3dE5gH7jK9mN1p';

        self::assertSame("\$k = '{$s}';", (new Redactor())->redact("\$k = '{$s}';"));
    }

    public function testNineteenCharsAreKeptEvenWithHighEntropy(): void
    {
        $s = 'aB3dE5gH7jK9mN1pQ2s';

        self::assertSame(19, strlen($s));
        self::assertSame("\$k = '{$s}';", (new Redactor())->redact("\$k = '{$s}';"));
    }

    public function testStringsWithSpacesAreKept(): void
    {
        $s = 'Zq8xK2mR9vL4tW7yB3nC5 and more';

        self::assertSame("\$k = '{$s}';", (new Redactor())->redact("\$k = '{$s}';"));
    }

    public function testLowercaseStringsUpToFourPointFiveAreKept(): void
    {
        $s = 'abcdefghijklmnopqrst';

        self::assertSame("\$k = '{$s}';", (new Redactor())->redact("\$k = '{$s}';"));
    }

    public function testLowercaseStringAboveFourPointFiveIsRedacted(): void
    {
        $s = 'abcdefghijklmnopqrstuvwxyz0123456789';

        self::assertSame("\$k = '<redacted>';", (new Redactor())->redact("\$k = '{$s}';"));
    }

    public function testUrlWithPasswordIsRedacted(): void
    {
        $out = (new Redactor())->redact("\$u = 'https://admin:hunter2@db.example.com/x';");

        self::assertSame("\$u = 'https://admin:<redacted>@db.example.com/x';", $out);
    }

    public function testUrlWithoutUserinfoIsKept(): void
    {
        $in = "\$u = 'https://example.com/Zq8xK2mR9vL4tW7yB3nC5/callback?a=1';";

        self::assertSame($in, (new Redactor())->redact($in));
    }

    public function testNeverRedactedShapesAreUntouched(): void
    {
        $keep = [
            "'App\\\\Http\\\\Controllers\\\\Vuln\\\\InvoiceController'",
            "'App\\Http\\Controllers\\Vuln\\InvoiceController'",
            'InvoiceController::class',
            'App\\Models\\Invoice::class',
            "'can:view,invoice'",
            "'auth:sanctum'",
            "'throttle:60,1'",
            "'permission:invoices.view,invoices.update'",
            "'/invoices/{invoice}/download/Pdf-Export'",
            "'invoices/{invoice}/attachments/{attachment}'",
            "'resources/views/Invoices/Show.blade.php'",
            "'storage/app/private/Invoices/2024'",
            "'filesystems.disks.public.visibility'",
            "'App\\Policies\\InvoicePolicy@viewAnyThing'",
        ];

        foreach ($keep as $line) {
            self::assertSame($line, (new Redactor())->redact($line), $line);
        }
    }

    public function testBase64PrefixedKeyIsNotMistakenForMiddleware(): void
    {
        $out = (new Redactor())->redact("\$k = 'base64:Zq8xK2mR9vL4tW7yB3nC5aBcDeF';");

        self::assertSame("\$k = '<redacted>';", $out);
    }

    public function testPathWithHighEntropySegmentIsRedacted(): void
    {
        $out = (new Redactor())->redact("\$k = 'keys/Zq8xK2mR9vL4tW7yB3nC5aBcDeF';");

        self::assertSame("\$k = '<redacted>';", $out);
    }

    public function testEscapedQuotesDoNotConfuseTheScanner(): void
    {
        $in = "\$a = 'don\\'t'; \$b = '" . self::HIGH . "';";

        self::assertSame("\$a = 'don\\'t'; \$b = '<redacted>';", (new Redactor())->redact($in));
    }

    public function testEscapedQuoteInsideDoubleQuotes(): void
    {
        $in = '$a = "say \\"hi\\""; $b = "' . self::HIGH . '";';

        self::assertSame('$a = "say \\"hi\\""; $b = "<redacted>";', (new Redactor())->redact($in));
    }

    public function testStringEndingInEscapedBackslash(): void
    {
        $in = "\$a = '\\\\'; \$b = '" . self::HIGH . "';";

        self::assertSame("\$a = '\\\\'; \$b = '<redacted>';", (new Redactor())->redact($in));
    }

    public function testUnterminatedQuoteDoesNotSwallowLaterLines(): void
    {
        $in = "// don't do this\n\$b = '" . self::HIGH . "';\n";

        self::assertSame("// don't do this\n\$b = '<redacted>';\n", (new Redactor())->redact($in));
    }

    public function testContextBlockIsRedactedToo(): void
    {
        $in = "Context:\nDB_PASSWORD=" . self::HIGH . "\nAPP_NAME=Laravel\nAPP_URL=http://localhost:8000\nthe key is 'ghp_abcdefghijklmnopqrstuvwxyz0123456789' here\nSTRIPE=\"" . self::HIGH . '"';
        $out = (new Redactor())->redact($in);

        self::assertSame("Context:\nDB_PASSWORD=<redacted>\nAPP_NAME=Laravel\nAPP_URL=http://localhost:8000\nthe key is '<redacted>' here\nSTRIPE=\"<redacted>\"", $out);
    }

    public function testEnvLineWithTokenValueAndTagPrefix(): void
    {
        $out = (new Redactor())->redact("L2| AWS_KEY=AKIAIOSFODNN7EXAMPLE\nL3| X=" . self::HIGH);

        self::assertSame("L2| AWS_KEY=<redacted>\nL3| X=<redacted>", $out);
    }

    public function testEmptyAndPlainTextUnchanged(): void
    {
        self::assertSame('', (new Redactor())->redact(''));
        self::assertSame("plain text\nno secrets", (new Redactor())->redact("plain text\nno secrets"));
    }

    public function testLineCountIsPreserved(): void
    {
        $in = "a\n\$k = '" . self::HIGH . "';\n\$h = <<<X\nl1\n" . self::HIGH . "\nX;\n";

        self::assertSame(substr_count($in, "\n"), substr_count((new Redactor())->redact($in), "\n"));
    }

    #[DataProvider('benchmarkFiles')]
    public function testBenchmarkFileIsUnchanged(string $path): void
    {
        $code = file_get_contents($path);
        self::assertIsString($code);
        self::assertSame($code, (new Redactor())->redact($code));

        $tagged = '';
        foreach (explode("\n", $code) as $i => $line) {
            $tagged .= 'L' . ($i + 1) . '| ' . $line . "\n";
        }
        self::assertSame($tagged, (new Redactor())->redact($tagged));
    }

    /** @return array<string, array{string}> */
    public static function benchmarkFiles(): array
    {
        $root = dirname(__DIR__, 3) . '/benchmark/laravel11-app/app/';

        return [
            'InvoiceController' => [$root . 'Http/Controllers/Vuln/InvoiceController.php'],
            'Invoice model' => [$root . 'Models/Invoice.php'],
        ];
    }
}
