<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Config;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Analysis\Confidence;
use TusharKhan\SemanticSec\Analysis\Severity;
use TusharKhan\SemanticSec\Config\Config;
use TusharKhan\SemanticSec\Config\ConfigException;
use TusharKhan\SemanticSec\Config\ConfigLoader;
use TusharKhan\SemanticSec\Config\CustomRuleset;

final class ConfigWithTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir().'/semsec-with-'.bin2hex(random_bytes(4));
        mkdir($this->dir);
        file_put_contents($this->dir.'/semantic-sec.yaml', <<<'YAML'
            effort: low
            api_key_env: MY_KEY
            exclude: [vendor-x]
            auth_helpers: [ownsOrFail]
            authorization_middleware: [permission]
            rulesets:
              - {name: tenancy, prompt: scope by team}
            YAML);
    }

    protected function tearDown(): void
    {
        exec('rm -rf '.escapeshellarg($this->dir));
    }

    public function testNoOverridesKeepsEverything(): void
    {
        $c = (new ConfigLoader())->load($this->dir);

        self::assertEquals($c, $c->with([]));
    }

    public function testOverridesReplaceOnlyTheirFields(): void
    {
        $c = (new ConfigLoader())->load($this->dir);
        $w = $c->with(['level' => 'critical', 'min_confidence' => 'low', 'provider' => 'openai', 'model' => 'm-1', 'concurrency' => '3', 'budget_tokens' => '0', 'paths' => ['app']]);

        self::assertSame([Severity::Critical, Confidence::Low, 'openai', 'm-1', 3, 0, ['app']], [$w->level, $w->minConfidence, $w->provider, $w->model, $w->concurrency, $w->budgetTokens, $w->paths]);
        self::assertSame(['low', 'MY_KEY', ['vendor-x'], ['ownsOrFail'], ['permission']], [$w->effort, $w->apiKeyEnv, $w->exclude, $w->authHelpers, $w->authorizationMiddleware]);
        self::assertEquals([new CustomRuleset('tenancy', 'scope by team')], $w->rulesets);
        self::assertSame(Severity::High, $c->level, 'the original is untouched');
        self::assertSame(7, $c->with(['concurrency' => 7, 'budget_tokens' => null])->concurrency);
        self::assertNull($c->with(['budget_tokens' => null])->budgetTokens);
    }

    /** @return iterable<string, array{array<string, mixed>, string}> */
    public static function invalid(): iterable
    {
        yield 'level' => [['level' => 'severe'], '"level" must be one of: low, medium, high, critical'];
        yield 'min_confidence' => [['min_confidence' => 'sure'], '"min_confidence" must be one of: low, medium, high'];
        yield 'provider' => [['provider' => 'gemini'], '"provider" must be one of: openai, anthropic, ollama'];
        yield 'model blank' => [['model' => ' '], '"model" must be a non-empty string'];
        yield 'concurrency zero' => [['concurrency' => '0'], '"concurrency" must be a positive integer'];
        yield 'concurrency text' => [['concurrency' => 'two'], '"concurrency" must be a positive integer'];
        yield 'budget negative' => [['budget_tokens' => '-1'], '"budget_tokens" must be an integer of 0 or more'];
        yield 'budget float' => [['budget_tokens' => '1e6'], '"budget_tokens" must be an integer of 0 or more'];
        yield 'ollama without model' => [['provider' => 'ollama'], 'ollama needs a model'];
    }

    /** @param array<string, mixed> $overrides */
    #[DataProvider('invalid')]
    public function testInvalidOverrideIsAConfigError(array $overrides, string $message): void
    {
        $c = (new ConfigLoader())->load($this->dir);

        $this->expectException(ConfigException::class);
        $this->expectExceptionMessage($message);
        $c->with($overrides);
    }

    public function testUnknownKeyIsAProgrammingError(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        (new ConfigLoader())->load($this->dir)->with(['effortt' => 'low']);
    }

    public function testConfigIsStillConstructible(): void
    {
        self::assertInstanceOf(Config::class, (new ConfigLoader())->load($this->dir)->with(['paths' => []]));
    }
}
