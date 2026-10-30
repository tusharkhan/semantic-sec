<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Payload;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Payload\Redactor;

final class RedactorKeyTest extends TestCase
{
    /** @return array<string, array{string, string}> */
    public static function leakProvider(): array
    {
        return [
            'upper hex starting letter' => ["\$k = 'A5D41402ABC4B2A76B9719D911017C59';", 'A5D41402ABC4'],
            'upper hex env' => ['MAILGUN_SECRET=A5D41402ABC4B2A76B9719D911017C59', 'A5D41402ABC4'],
            'base32 totp' => ["\$k = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXQ';", 'JBSWY3DPEHPK'],
            'upper alnum' => ["\$k = 'X7K2M9Q4W8E1R6T5Y3U0I8O2P9A1S7D4';", 'X7K2M9Q4W8E1'],
            'upper+underscore' => ["'api_key' => 'Q7K2M9Q4W8E1R6T5Y3U0I8O2P9A_S7D4',", 'Q7K2M9Q4W8E1'],
            'dotted password' => ["'password' => 'correct.horse.battery.staple',", 'correct.horse'],
            'spaced password' => ["'password' => 'correct horse battery staple',", 'correct horse'],
            'short password' => ["'password' => 'p4ss!',", 'p4ss!'],
            'letters-only pw comment' => ['// password: Sunshinewinter', 'Sunshinewinter'],
            'letters-only pw quoted' => ["'password' => 'Sunshinewinter',", 'Sunshinewinter'],
            'pw plain word' => ["'password' => 'database',", 'database'],
            'pw colon shape' => ["'password' => 'admin:Hunter22x',", 'Hunter22x'],
            'secret pipe shape' => ["'secret' => 'prod|s3cr3tvalue9',", 's3cr3tvalue9'],
            'env pw letters-only' => ['DB_PASSWORD=Sunshinewinter', 'Sunshinewinter'],
            'env pw dotted' => ['DB_PASSWORD=correct.horse.battery', 'correct.horse'],
            'env pw short' => ['DB_PASSWORD=s3cr3t!', 's3cr3t!'],
            'env pw dq' => ['DB_PASSWORD="s3cr3tPw!"', 's3cr3tPw!'],
            'env pw sq' => ["DB_PASSWORD='s3cr3tPw!'", 's3cr3tPw!'],
            'env lowercase key' => ['db_password=s3cr3tPw!x', 's3cr3tPw!x'],
            'env export lowercase' => ['export db_password=s3cr3tPw!xy', 's3cr3tPw!xy'],
            'yaml colon' => ['password: s3cr3tPw!x', 's3cr3tPw!x'],
            'env() default secret' => ["'key' => env('STRIPE_SECRET', 's3cr3tPw!x'),", 's3cr3tPw!x'],
            'env() default pass' => ["'key' => env('MAIL_PASS', 's3cr3tPw!x'),", 's3cr3tPw!x'],
            'MAIL_PASS env' => ['MAIL_PASS=s3cr3tPw!xy', 's3cr3tPw!xy'],
            'pass key' => ["'pass' => 's3cr3tPw!xy',", 's3cr3tPw!xy'],
            'pwd key' => ["'pwd' => 's3cr3tPw!xy',", 's3cr3tPw!xy'],
            'credentials key' => ["'credentials' => 's3cr3tPw!xy',", 's3cr3tPw!xy'],
            'camelCase key' => ["\$dbPassword = 'letmeinplease';", 'letmeinplease'],
            'secret_key key' => ["'secret_key' => 'sk_test_placeholder',", 'sk_test_placeholder'],
            'token key plain' => ["'token' => 'Sunshine22winter',", 'Sunshine22winter'],
            'json context' => ['{"client_secret": "s3cr3tPw!xyZ"}', 's3cr3tPw!xyZ'],
            'json context key' => ['{"stripe": {"key": "Zq8vK2mX9pL4nR7tB1wY6cH3jF5sD0gA"}}', 'Zq8vK2mX9pL4'],
            'camel-looking secret' => ["\$k = 'HelloWorldFooBarBazQux1';", 'HelloWorld'],
            'regex-ish secret' => ["\$k = 'Zq8vK2mX9p\\\\dL4nR7tB1wY6cH3jF5sD0gA';", 'Zq8vK2mX9p'],
            'context prose' => ["Context:\nthe stripe key is Zq8vK2mX9pL4nR7tB1wY6cH3jF5sD0gA today", 'Zq8vK2mX9pL4'],
        ];
    }

    #[DataProvider('leakProvider')]
    public function testNothingLeaks(string $in, string $needle): void
    {
        $out = (new Redactor())->redact($in);

        self::assertStringNotContainsString($needle, $out);
        self::assertSame(substr_count($in, "\n"), substr_count($out, "\n"));
    }

    /** @return array<string, array{string}> */
    public static function keepProvider(): array
    {
        $lines = [
            "'password' => 'required|string|min:8|confirmed', 'token' => 'required|string|size:64',",
            "'password' => 'hashed', 'secret_answer' => 'encrypted', 'api_token' => 'encrypted:array',",
            "'token' => 'nullable|string|exists:password_reset_tokens,token',",
            "'token_name' => 'customer-portal-access-token', 'guard' => 'api_customer_passport',",
            "'password_reset_token' => 'password_reset_tokens', 'token_column' => 'remember_token',",
            "'secret' => env('PUSHER_APP_SECRET'), 'key' => env('PUSHER_APP_KEY'), 'auth_endpoint' => '/broadcasting/auth',",
            "'password' => 'App\\Rules\\StrongPassword',",
            "'driver' => 'passport', 'provider' => 'customers', 'passwords' => 'users', 'auth' => 'web',",
            "'token_type' => 'Bearer', 'access_token' => \$token->plainTextToken,",
            "'Authorization' => 'Bearer ' . \$this->apiToken, 'X-Api-Key' => \$settings->stripeSecretKey,",
            "\$token = \$user->createToken('vendor_portal_personal_access')->accessToken;",
            "\$hash = Hash::make(\$request->password); \$pw = \$request->input('password_confirmation');",
            "config('services.stripe.webhook_secret'); config('auth.passwords.users.expire');",
            "'password' => bcrypt(\$request->password), 'token' => \$token,",
            "'user_model' => 'App\\Models\\User', 'password_route' => 'password.reset', 'key_type' => 'string',",
            "'token_expires_at' => 'datetime', 'secret_field' => 'client_secret', 'key_column' => 'api_key',",
            '* @return \\Illuminate\\Database\\Eloquent\\Factories\\Factory<\\App\\Models\\Invoice>',
            '/** @use HasFactory<\\Database\\Factories\\InvoiceFactory> */',
            "'MAX_UPLOAD_SIZE_IN_BYTES_LIMIT' => 1, 'INVOICE_STATUS_PENDING_REVIEW' => 2,",
            '* @extends \\Illuminate\\Database\\Eloquent\\Factories\\Factory<\\App\\Models\\CaseOLevel>',
            "'did not return a refresh token' => 'Failed to refresh the portal session',",
            'public function testIdorL10CtorMiddlewareVulnerable(): void',
            "'localhost,localhost:3000,127.0.0.1,127.0.0.1:8000,::1',",
            "\$key = 'base64:' . base64_encode(random_bytes(32));",
            "* 'permission' is what does the work here: App\\Http\\Middleware\\",
            "'verify_csrf_token' => App\\Http\\Middleware\\VerifyCsrfToken::class,",
            "\$x = 'ONLY_FULL_GROUP_BY'; \$y = 'DEFAULT_PAYMENT_METHOD_IDENTIFIER';",
        ];
        $out = [];
        foreach ($lines as $i => $l) {
            $out['line ' . $i] = [$l];
        }

        return $out;
    }

    #[DataProvider('keepProvider')]
    public function testCodeStaysReadable(string $line): void
    {
        self::assertSame($line, (new Redactor())->redact($line));
    }

    public function testKeyClassUsesTheLastSegment(): void
    {
        $r = new Redactor();

        self::assertSame("'token_name' => 'customer-portal-access-token',", $r->redact("'token_name' => 'customer-portal-access-token',"));
        self::assertSame("'passwordName' => 'user_password_field_x',", $r->redact("'passwordName' => 'user_password_field_x',"));
        self::assertSame("'db.password' => '<redacted>',", $r->redact("'db.password' => 'abc',"));
        self::assertSame("'dbPassword' => '<redacted>',", $r->redact("'dbPassword' => 'abc',"));
        self::assertSame("'api-key' => '<redacted>',", $r->redact("'api-key' => 'abc',"));
        self::assertSame("'token' => '<redacted>',", $r->redact("'token' => 'Bearer',"));
    }

    public function testUpperSnakeConstantNeedsUnderscoreAndWordParts(): void
    {
        $r = new Redactor();

        self::assertSame("'<redacted>'", $r->redact("'X7K2M9Q4W8E1R6T5Y3U0I8O2P9A1S7D4'"));
        self::assertSame("'<redacted>'", $r->redact("'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXQ'"));
        self::assertSame("'DEFAULT_PAYMENT_METHOD_IDENTIFIER'", $r->redact("'DEFAULT_PAYMENT_METHOD_IDENTIFIER'"));
    }

    public function testRandomUpperAlphabetsAreNeverLeaked(): void
    {
        $gens = [
            'upper hex' => fn () => strtoupper(bin2hex(random_bytes(16))),
            'upper alnum 32' => fn () => $this->pick('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 32),
            'base32' => fn () => $this->pick('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', 32),
        ];
        foreach ($gens as $name => $gen) {
            $leaks = 0;
            for ($i = 0; $i < 300; $i++) {
                $s = $gen();
                if (str_contains((new Redactor())->redact("\$k = '{$s}';"), $s)) {
                    $leaks++;
                }
            }
            self::assertLessThanOrEqual(1, $leaks, $name);
        }
    }

    private function pick(string $alphabet, int $len): string
    {
        $s = '';
        for ($i = 0; $i < $len; $i++) {
            $s .= $alphabet[random_int(0, strlen($alphabet) - 1)];
        }

        return $s;
    }
}
