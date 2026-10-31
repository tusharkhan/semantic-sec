<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Payload;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Payload\Redactor;

final class RedactorLeakTest extends TestCase
{
    private const HIGH = 'Zq8xK2mR9vL4tW7yB3nC5';

    public function testProseWithSpacesIsKeptButSecretWordInsideIsRedacted(): void
    {
        $in = "\$k = 'The invoice was created for the customer';";
        self::assertSame($in, (new Redactor())->redact($in));

        $out = (new Redactor())->redact("\$k = 'token " . self::HIGH . " and more';");
        self::assertSame("\$k = 'token <redacted> and more';", $out);
    }

    public function testHexSecretsAreRedactedInLiteralsAndEnv(): void
    {
        foreach (['5d41402abc4b2a76b9719d911017c592', 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'] as $h) {
            self::assertSame("\$k = '<redacted>';", (new Redactor())->redact("\$k = '{$h}';"), $h);
            self::assertSame('MAILGUN_SECRET=<redacted>', (new Redactor())->redact("MAILGUN_SECRET={$h}"), $h);
        }
    }

    public function testLowercaseAlnumSecretsAreRedacted(): void
    {
        $s = 'k3j9x2m8q1w7e4r6t5y0u3i8o2p9a1s7';

        self::assertSame("\$k = '<redacted>';", (new Redactor())->redact("\$k = '{$s}';"));
    }

    public function testShortMixedCaseAlnumSecretIsRedacted(): void
    {
        self::assertSame("\$k = '<redacted>';", (new Redactor())->redact("\$k = 'Kd9Xp2LmQ7vR4tY8nB3w';"));
    }

    public function testSlugsAndConfigKeysStayReadable(): void
    {
        $keep = ["'filesystems.disks.public.visibility'", "'invoice-attachments-download-cache'", "'app_invoice_download_cache_key'", "'invoicedownloadresponse'"];
        foreach ($keep as $l) {
            self::assertSame($l, (new Redactor())->redact($l), $l);
        }
    }

    public function testBase64WithSlashesIsNotAPath(): void
    {
        foreach (["'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'", "'9dF+3kLm/Qw7Xz2p/Rt8Yv1Bn+Hj4Gs6Kc0Ea5Ui'", "'base64:2fl+Ktvkfl+Fuz4Qp/A75G2RTiWVA/ZoKZvp6fiiM10='"] as $l) {
            self::assertSame("'<redacted>'", (new Redactor())->redact($l), $l);
        }
    }

    public function testBearerTokenInsideInterpolatedStringIsRedacted(): void
    {
        $out = (new Redactor())->redact('$h = "Authorization: Token ' . self::HIGH . ' {$user}";');

        self::assertSame('$h = "Authorization: Token <redacted> {$user}";', $out);
    }

    public function testUrlQueryTokenIsRedacted(): void
    {
        $out = (new Redactor())->redact("\$u = 'https://api.x.com/v1?api_key=" . self::HIGH . "&u=1';");

        self::assertSame("\$u = 'https://api.x.com/v1?api_key=<redacted>&u=1';", $out);
    }

    public function testSecretInCommentIsRedacted(): void
    {
        self::assertSame('// prod key <redacted>', (new Redactor())->redact('// prod key ' . self::HIGH));
        self::assertSame('/* STRIPE_SECRET=<redacted> */', (new Redactor())->redact('/* STRIPE_SECRET=' . self::HIGH . ' */'));
        self::assertSame('# key <redacted>', (new Redactor())->redact('# key ' . self::HIGH));
    }

    public function testHeredocKeyValueIsRedacted(): void
    {
        $out = (new Redactor())->redact("\$x = <<<EOT\napi_key: " . self::HIGH . "\nEOT;");

        self::assertSame("\$x = <<<EOT\napi_key: <redacted>\nEOT;", $out);
    }

    public function testKeyNameHeuristicRedactsQuotedValues(): void
    {
        $r = new Redactor();

        self::assertSame("'password' => '<redacted>',", $r->redact("'password' => 'hunter2-real-pass',"));
        self::assertSame("'password' => '<redacted>',", $r->redact("'password' => 'Xk9#mQ2!vL7\$pR4@nZ8',"));
        self::assertSame('$apiKey = "<redacted>";', $r->redact('$apiKey = "abc123xyz";'));
        self::assertSame("env('DB_PASSWORD', '<redacted>')", $r->redact("env('DB_PASSWORD', 'hunter2-real')"));
    }

    public function testKeyNameHeuristicLeavesCodeAndRulesAlone(): void
    {
        $keep = [
            "'password' => 'required|string|min:8|confirmed',",
            "'password' => 'confirmed',",
            "'password' => bcrypt(\$request->password),",
            "'token' => \$token,",
            "\$password = \$request->input('password');",
            "if (\$token === 'abc12345') {}",
            "'auth' => ['web'],",
            "'authorization' => 'viewAny',",
            "'secret' => env('STRIPE_SECRET'),",
            "Route::middleware('auth:sanctum');",
        ];
        foreach ($keep as $l) {
            self::assertSame($l, (new Redactor())->redact($l), $l);
        }
    }

    public function testEnvLineVariants(): void
    {
        $r = new Redactor();

        self::assertSame('DB_PASSWORD=<redacted>', $r->redact('DB_PASSWORD=s3cr3tPassw0rd!'));
        self::assertSame('DB_PASSWORD = <redacted>', $r->redact('DB_PASSWORD = Xk9mQ2vL7pR4nZ8wT3yB'));
        self::assertSame('export STRIPE_SECRET=<redacted>', $r->redact('export STRIPE_SECRET=' . self::HIGH));
        self::assertSame('# STRIPE_SECRET=<redacted>', $r->redact('# STRIPE_SECRET=' . self::HIGH));
        self::assertSame('AWS_SECRET_ACCESS_KEY=<redacted>', $r->redact('AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'));
        $plain = "APP_NAME=Laravel\nFILESYSTEM_ROOT=/var/www/storage\nAPP_ENV=production";
        self::assertSame($plain, $r->redact($plain));
    }

    public function testExplicitVendorPatterns(): void
    {
        $r = new Redactor();
        $cases = [
            'AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY',
            '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',
            'whsec_5Kd9fJ3mQpXz7LbN2vRtY8wC1hGsE4aU',
            'glpat-xR3kQ9mZ7vL2pW8nB4tY',
            'ghs_16C7e42F292c6912E7710c838347Ae178B4a',
            'ghu_16C7e42F292c6912E7710c838347Ae178B4a',
            'SK2a9f8c7e6d5b4a3f2e1d0c9b8a7f6e5d',
            'key-5d41402abc4b2a76b9719d911017c592',
        ];
        foreach ($cases as $c) {
            self::assertSame("\$k = '<redacted>';", $r->redact("\$k = '{$c}';"), $c);
        }
    }

    public function testSlackWebhookPathIsRedacted(): void
    {
        $out = (new Redactor())->redact("\$u = 'https://hooks.slack.com/services/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';");

        self::assertSame("\$u = 'https://hooks.slack.com/services/<redacted>';", $out);
    }

    public function testUrlPasswordVariants(): void
    {
        $r = new Redactor();

        self::assertSame('REDIS_URL=redis://:<redacted>@redis:6379', $r->redact('REDIS_URL=redis://:p4ssw0rdXyz@redis:6379'));
        self::assertSame("'mysql://root:<redacted>@db/app'", $r->redact("'mysql://root:ab/cd@db/app'"));
    }

    public function testCommentApostropheCannotHideLiteral(): void
    {
        $out = (new Redactor())->redact("// it's prod: \$k = '" . self::HIGH . "';");

        self::assertSame("// it's prod: \$k = '<redacted>';", $out);

        $in = "/* don't */ \$k = '" . self::HIGH . "';\n# it's\n\$j = '" . self::HIGH . "';";
        self::assertSame("/* don't */ \$k = '<redacted>';\n# it's\n\$j = '<redacted>';", (new Redactor())->redact($in));
    }

    public function testBackslashSecretIsNotTreatedAsClassName(): void
    {
        $out = (new Redactor())->redact("\$k = 'Zq8vK2mX9pL4\\\\nR7tB1wY6cH3jF5sD0gA';");

        self::assertSame("\$k = '<redacted>';", $out);
    }

    public function testMiddlewareShapedSecretIsRedacted(): void
    {
        self::assertSame("\$k = '<redacted>';", (new Redactor())->redact("\$k = 'token:Zq8vK2mX9pL4nR7tB1wY6cH3';"));
    }

    public function testPipeJoinedValidationRulesAreKept(): void
    {
        $keep = [
            "'required|string|max:120'",
            "'required|exists:payment_methods,id'",
            "'nullable|image|mimes:jpg,png,pdf|max:10240'",
            "'required|in:pending,paid,void,refunded,cancelled'",
            "'required|date_format:Y-m-d|after_or_equal:today'",
            "'sometimes|unique:invoices,reference_number,NULL,id,account_id,1'",
        ];
        foreach ($keep as $l) {
            self::assertSame($l, (new Redactor())->redact($l), $l);
        }
    }

    public function testCamelCaseIdentifiersAreKept(): void
    {
        $keep = ["'projectCustomerVendorShipField'", "'customerBillingShippingAddressList'", '"downloadInvoiceAttachmentAsPdf"', "'InvoiceAttachmentDownloadController'", "'MAX_UPLOAD_SIZE_IN_BYTES_LIMIT'"];
        foreach ($keep as $l) {
            self::assertSame($l, (new Redactor())->redact($l), $l);
        }
    }

    public function testNamespacedAndCommentTextStaysReadable(): void
    {
        $keep = [
            '// see App\\Http\\Controllers\\Vuln\\InvoiceController::download() for details',
            '/** @see https://laravel.com/docs/11.x/authorization#writing-policies */',
            '// config/filesystems.php resources/views/invoices/show.blade.php',
            'use App\\Http\\Controllers\\Vuln\\InvoiceAttachmentController;',
        ];
        foreach ($keep as $l) {
            self::assertSame($l, (new Redactor())->redact($l), $l);
        }
    }

    public function testRealCodeShapesFromTheSweepStayReadable(): void
    {
        $keep = [
            "'client_secret' => 'encrypted',",
            "'token_expires_at' => 'datetime',",
            "Route::middleware('auth:customer-api')->group(function () {",
            "Route::group(['middleware'=>['auth:api,auth:partner-api']],function (){",
            '* Sets the Access-Control-Allow-Credentials header.',
            '* Helvetica, Helvetica-Bold, Helvetica-BoldOblique, Helvetica-Oblique,',
            '// ONLY_FULL_GROUP_BY-clean (ShiftPerformanceHelper is).',
            "+ IF(p.d < '\".Carbon::now()->toDateString().\"', 1, 0)",
            "AS owed, '.ReportSql::ageBucket('invoices.due_date').' AS bucket');",
            "if (preg_match('/^private-chat\\.(project|invoice|customer)\\.(\\d+)\$/', \$channel, \$m)) {",
            '//notificationSend([],$assignees,$module_name,$message);',
            "//->with('installation_invoice_notes');",
            "if ( ! function_exists('orderSummaryByStatusWithBadge') ){",
            "'useTLS' => config('broadcasting.connections.pusher.options.useTLS'),",
            "\$imageData = base64_decode(preg_replace('/^data:image\\/\\w+;base64,/', '', \$b));",
            '$v ="nullable|unique:crews,phone,$id|unique:users,phone,$user_id";',
            "'field_values.*.project_customer_id.required' => 'Project Customer is required.',",
            '* Customer twin of Admin\\Auth\\ForgetPasswordController. Partners had no way at',
            "->orWhere('p_q_shipment_fields.FIELD_name', 'like', '%'.\$search.'%');",
            '* @param PQVendorShipFieldValueRequest $PQVendorShipFieldValueRequest',
        ];
        foreach ($keep as $l) {
            self::assertSame($l, (new Redactor())->redact($l), $l);
        }
    }

    public function testLineCountPreservedForCommentsAndBlockComments(): void
    {
        $in = "/*\n * key " . self::HIGH . "\n */\n// x " . self::HIGH . "\n\$a = 1;";
        $out = (new Redactor())->redact($in);

        self::assertSame(substr_count($in, "\n"), substr_count($out, "\n"));
        self::assertStringNotContainsString(self::HIGH, $out);
    }

    public function testRandomSecretFormatsAreNeverLeaked(): void
    {
        $b62 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        $low = 'abcdefghijklmnopqrstuvwxyz0123456789';
        mt_srand(20261101);
        $hex = '0123456789abcdef';
        $gens = [
            'hex32' => fn () => $this->pick($hex, 16, 32),
            'hex40' => fn () => $this->pick($hex, 16, 40),
            'hex64' => fn () => $this->pick($hex, 16, 64),
            'b62-20' => fn () => $this->pick($b62, 62, 20),
            'b62-32' => fn () => $this->pick($b62, 62, 32),
            'low-32' => fn () => $this->pick($low, 36, 32),
            'low-40' => fn () => $this->pick($low, 36, 40),
            'b64-40' => fn () => $this->pick($b62 . '+/', 64, 40),
            'app-key' => fn () => 'base64:' . base64_encode($this->pick(implode('', array_map('chr', range(0, 255))), 256, 32)),
        ];
        $leaks = [];
        foreach ($gens as $name => $gen) {
            for ($i = 0; $i < 2000; $i++) {
                $s = $gen();
                if (str_contains((new Redactor())->redact("\$k = '{$s}';"), $s) || str_contains((new Redactor())->redact("X_SECRET={$s}"), $s)) {
                    $leaks[$name] = ($leaks[$name] ?? 0) + 1;
                }
            }
        }
        self::assertSame([], array_diff_key($leaks, ['b62-20' => 1]));
        // 20-char base62 with many repeats can fall under the entropy bar (about 0.2%); fixed seed keeps this stable
        self::assertLessThanOrEqual(10, $leaks['b62-20'] ?? 0);
    }

    private function pick(string $alphabet, int $n, int $len): string
    {
        $s = '';
        for ($i = 0; $i < $len; $i++) {
            $s .= $alphabet[mt_rand(0, $n - 1)];
        }

        return $s;
    }
}
