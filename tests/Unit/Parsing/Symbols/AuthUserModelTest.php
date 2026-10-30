<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Parsing\Symbols;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Framework\Laravel\ConstantEvaluator;
use TusharKhan\SemanticSec\Parsing\AstGenerator;
use TusharKhan\SemanticSec\Parsing\ParseFailure;
use TusharKhan\SemanticSec\Parsing\ParseResult;
use TusharKhan\SemanticSec\Parsing\SourceFile;
use TusharKhan\SemanticSec\Parsing\Symbols\AuthUserModel;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTableBuilder;

final class AuthUserModelTest extends TestCase
{
    private const MODELS_USER = '<?php namespace App\Models; class User {}';

    private const LEGACY_USER = '<?php namespace App; class User {}';

    public function testReadsProvidersUsersModelFromConfig(): void
    {
        $config = "<?php\nuse App\\Accounts\\Member;\nreturn ['defaults' => ['guard' => 'web'], 'providers' => ['users' => ['driver' => 'eloquent', 'model' => Member::class]]];";
        self::assertSame('App\Accounts\Member', self::resolve(['config/auth.php' => $config, 'app/Models/User.php' => self::MODELS_USER]));
    }

    public function testEnvDefaultClassConstIsUsed(): void
    {
        $config = "<?php\nreturn ['providers' => ['admins' => ['model' => App\\Admin::class], 'users' => ['driver' => 'eloquent', 'model' => env('AUTH_MODEL', App\\Models\\Customer::class)]]];";
        self::assertSame('App\Models\Customer', self::resolve(['config/auth.php' => $config]));
    }

    public function testStringLiteralModelIsUsed(): void
    {
        $config = "<?php\nreturn ['providers' => ['users' => ['model' => '\\\\App\\\\Models\\\\Person']]];";
        self::assertSame('App\Models\Person', self::resolve(['config/auth.php' => $config]));
    }

    public function testUnresolvableConfigGivesNullNotTheDefault(): void
    {
        $cases = [
            "<?php\nreturn ['providers' => ['users' => ['model' => env('AUTH_MODEL')]]];",
            "<?php\nreturn ['providers' => ['users' => ['model' => env('AUTH_MODEL', 'App\\\\Models\\\\User')]]];",
            "<?php\nreturn ['providers' => ['users' => ['driver' => 'database', 'table' => 'users']]];",
            "<?php\nreturn ['providers' => \$providers];",
            "<?php\nreturn config_array();",
            "<?php\n\$x = 1;",
        ];
        foreach ($cases as $i => $config) {
            self::assertNull(self::resolve(['config/auth.php' => $config, 'app/Models/User.php' => self::MODELS_USER]), (string) $i);
        }
    }

    public function testUnparseableConfigGivesNull(): void
    {
        $result = new ParseResult(
            [(new AstGenerator())->parse(new SourceFile('app/Models/User.php', '/x/app/Models/User.php', self::MODELS_USER))],
            [new ParseFailure('config/auth.php', 'Syntax error', 3)],
        );
        self::assertNull(AuthUserModel::resolve($result, (new SymbolTableBuilder())->build($result), new ConstantEvaluator()));
    }

    public function testFallsBackWithoutConfig(): void
    {
        self::assertSame('App\Models\User', self::resolve(['app/Models/User.php' => self::MODELS_USER, 'app/User.php' => self::LEGACY_USER]));
        self::assertSame('App\User', self::resolve(['app/User.php' => self::LEGACY_USER]));
        self::assertNull(self::resolve(['app/Models/Post.php' => '<?php namespace App\Models; class Post {}']));
    }

    /** @param array<string, string> $files */
    private static function resolve(array $files): ?string
    {
        $parsed = [];
        foreach ($files as $path => $code) {
            $parsed[] = (new AstGenerator())->parse(new SourceFile($path, '/nonexistent/'.$path, $code));
        }
        $result = new ParseResult($parsed, []);

        return AuthUserModel::resolve($result, (new SymbolTableBuilder())->build($result), new ConstantEvaluator());
    }
}
