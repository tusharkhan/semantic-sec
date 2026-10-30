<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Config;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Analysis\Confidence;
use TusharKhan\SemanticSec\Analysis\Severity;
use TusharKhan\SemanticSec\Config\Config;
use TusharKhan\SemanticSec\Config\ConfigException;
use TusharKhan\SemanticSec\Config\ConfigLoader;

final class ConfigLoaderTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir().'/semantic-sec-config-'.uniqid('', true);
        mkdir($this->dir, 0777, true);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir.'/*') ?: [] as $file) {
            unlink($file);
        }
        rmdir($this->dir);
    }

    private function write(string $yaml): void
    {
        file_put_contents($this->dir.'/semantic-sec.yaml', $yaml);
    }

    private function assertLoadFails(string $yaml, string ...$fragments): void
    {
        $this->write($yaml);
        try {
            (new ConfigLoader())->load($this->dir);
            self::fail('Expected ConfigException');
        } catch (ConfigException $e) {
            foreach ($fragments as $fragment) {
                self::assertStringContainsString($fragment, $e->getMessage());
            }
        }
    }

    public function testDefaultsWithoutConfigFile(): void
    {
        $config = (new ConfigLoader())->load($this->dir);

        self::assertSame($this->dir, $config->projectRoot);
        self::assertSame('anthropic', $config->provider);
        self::assertNull($config->model);
        self::assertSame(5, $config->concurrency);
        self::assertSame(8000, $config->maxPayloadTokens);
        self::assertSame(3, $config->maxDepth);
        self::assertSame(Severity::High, $config->level);
        self::assertSame(Confidence::Medium, $config->minConfidence);
        self::assertNull($config->budgetTokens);
        self::assertSame(Config::DEFAULT_SENSITIVE_FIELDS, $config->sensitiveFields);
    }

    public function testEmptyFileMeansDefaults(): void
    {
        $this->write('');

        self::assertSame('anthropic', (new ConfigLoader())->load($this->dir)->provider);
    }

    public function testReadsValuesFromYaml(): void
    {
        $this->write(<<<'YAML'
provider: openai
concurrency: 2
level: medium
auth_helpers: [ownsOrFail]
laravel:
  sensitive_fields: [plan]
rulesets:
  - name: tenancy
    prompt: "Scope by team_id."
YAML);

        $config = (new ConfigLoader())->load($this->dir);

        self::assertSame('openai', $config->provider);
        self::assertSame(2, $config->concurrency);
        self::assertSame(Severity::Medium, $config->level);
        self::assertSame(['ownsOrFail'], $config->authHelpers);
        self::assertContains('plan', $config->sensitiveFields);
        self::assertContains('is_admin', $config->sensitiveFields);
        self::assertCount(1, $config->rulesets);
        self::assertSame('tenancy', $config->rulesets[0]->name);
        self::assertSame('Scope by team_id.', $config->rulesets[0]->prompt);
    }

    public function testSensitiveFieldsAreDeduplicated(): void
    {
        $this->write("laravel:\n  sensitive_fields: [role, plan]\n");

        $fields = (new ConfigLoader())->load($this->dir)->sensitiveFields;

        self::assertSame(array_values(array_unique($fields)), $fields);
        self::assertContains('plan', $fields);
    }

    public function testExplicitConfigPath(): void
    {
        file_put_contents($this->dir.'/custom.yaml', "concurrency: 9\n");

        $config = (new ConfigLoader())->load($this->dir, $this->dir.'/custom.yaml');
        unlink($this->dir.'/custom.yaml');

        self::assertSame(9, $config->concurrency);
    }

    public function testUnknownKeyThrowsWithKeyName(): void
    {
        $this->assertLoadFails("concurency: 10\n", 'Unknown config key "concurency"');
    }

    public function testUnknownNestedKeyThrows(): void
    {
        $this->assertLoadFails("laravel:\n  routes: []\n", '"laravel.routes"');
    }

    public function testInvalidEnumValueThrows(): void
    {
        $this->assertLoadFails("level: severe\n", 'level', 'low, medium, high, critical');
    }

    public function testMaxDepthOutOfRangeThrows(): void
    {
        $this->assertLoadFails("max_depth: 9\n", 'between 1 and 5');
    }

    public function testNonPositiveIntegersThrow(): void
    {
        $this->assertLoadFails("concurrency: 0\n", 'concurrency');
        $this->assertLoadFails("budget_tokens: -1\n", 'budget_tokens');
        $this->assertLoadFails("max_payload_tokens: 0\n", 'max_payload_tokens');
    }

    public function testUnknownProviderThrows(): void
    {
        $this->assertLoadFails("provider: gemini\n", 'provider', 'openai, anthropic, ollama');
    }

    public function testListKeysMustBeListsOfStrings(): void
    {
        $this->assertLoadFails("paths: app\n", 'paths');
        $this->assertLoadFails("exclude: [1]\n", 'exclude');
    }

    public function testRulesetEntryErrorsNameTheIndex(): void
    {
        $this->assertLoadFails("rulesets:\n  - name: a\n    prompt: b\n  - name: c\n", 'rulesets[1]');
        $this->assertLoadFails("rulesets:\n  - name: a\n    prompt: b\n    extra: x\n", 'rulesets[0]');
    }

    public function testYamlParseErrorBecomesConfigException(): void
    {
        $this->assertLoadFails("provider: [unclosed\n", 'YAML');
    }

    public function testNonMapDocumentThrows(): void
    {
        $this->assertLoadFails("- a\n- b\n", 'mapping');
    }

    public function testExplicitMissingConfigPathThrows(): void
    {
        $this->expectException(ConfigException::class);

        (new ConfigLoader())->load($this->dir, $this->dir.'/missing.yaml');
    }

    public function testAuthMiddlewareDefaultsAndParses(): void
    {
        self::assertSame([], (new ConfigLoader())->load($this->dir)->authMiddleware);

        $this->write("auth_middleware: [login, App\\Http\\Middleware\\LoginMiddleware]\n");

        self::assertSame(['login', 'App\\Http\\Middleware\\LoginMiddleware'], (new ConfigLoader())->load($this->dir)->authMiddleware);
    }

    public function testAuthMiddlewareValidation(): void
    {
        $this->assertLoadFails("auth_middlewares: [login]\n", 'Unknown config key "auth_middlewares"');
        $this->assertLoadFails("auth_middleware: login\n", 'auth_middleware');
        $this->assertLoadFails("auth_middleware: ['']\n", 'auth_middleware');
        $this->assertLoadFails("auth_middleware: [1]\n", 'auth_middleware');
    }
}
