<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Engine;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Candidates\Candidate;
use TusharKhan\SemanticSec\Config\CustomRuleset;
use TusharKhan\SemanticSec\Engine\ResultCache;
use TusharKhan\SemanticSec\Framework\Laravel\RouteAction;
use TusharKhan\SemanticSec\Framework\Laravel\RouteEntry;
use TusharKhan\SemanticSec\Llm\LlmOutcome;
use TusharKhan\SemanticSec\Llm\LlmResponse;
use TusharKhan\SemanticSec\Parsing\CallGraph\ExecutionPath;
use TusharKhan\SemanticSec\Parsing\CallGraph\PathNode;
use TusharKhan\SemanticSec\Payload\Payload;
use TusharKhan\SemanticSec\Tests\Unit\Llm\ResponseValidatorTest;

final class ResultCacheTest extends TestCase
{
    private string $base;

    private string $dir;

    protected function setUp(): void
    {
        $this->base = sys_get_temp_dir().'/semsec-cache-'.bin2hex(random_bytes(4));
        $this->dir = $this->base.'/.semantic-sec/cache';
        mkdir($this->dir, 0777, true);
    }

    protected function tearDown(): void
    {
        exec('chmod -R u+rwx '.escapeshellarg($this->base).' 2>/dev/null; rm -rf '.escapeshellarg($this->base));
    }

    public function testKeyChangesWithEachComponent(): void
    {
        $rules = [new CustomRuleset('tenant', 'Check tenant scoping')];
        $make = fn (array $o = []): ResultCache => new ResultCache(
            $this->dir,
            $o['provider'] ?? 'openai',
            $o['model'] ?? 'gpt-x',
            $o['rulesets'] ?? $rules,
            true,
            $o['tool'] ?? '1.0.0',
            $o['prompt'] ?? '2',
        );
        $payload = self::payload();
        $key = $make()->key($payload);

        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $key);
        self::assertSame($key, $make()->key(self::payload()), 'deterministic');
        $variants = [
            'tool' => $make(['tool' => '1.0.1'])->key($payload),
            'provider' => $make(['provider' => 'anthropic'])->key($payload),
            'model' => $make(['model' => 'gpt-y'])->key($payload),
            'prompt' => $make(['prompt' => '3'])->key($payload),
            'ruleset prompt' => $make(['rulesets' => [new CustomRuleset('tenant', 'Check tenant scoping!')]])->key($payload),
            'ruleset name' => $make(['rulesets' => [new CustomRuleset('tenant2', 'Check tenant scoping')]])->key($payload),
            'ruleset added' => $make(['rulesets' => [...$rules, new CustomRuleset('x', 'y')]])->key($payload),
            'no rulesets' => $make(['rulesets' => []])->key($payload),
            'middleware' => $make()->key(self::payload(context: "Route:\n  GET /posts/{id}\nMiddleware: web")),
            'code' => $make()->key(self::payload(code: '```php\n1| return Post::find($id)->load("x");\n```')),
        ];
        foreach ($variants as $what => $variant) {
            self::assertNotSame($key, $variant, $what.' must change the key');
        }
        self::assertCount(count($variants), array_unique($variants));
        // Separator ambiguity: moving text between provider and model must not collide.
        self::assertNotSame($make(['provider' => 'a|b', 'model' => 'c'])->key($payload), $make(['provider' => 'a', 'model' => 'b|c'])->key($payload));
    }

    public function testDefaultsUseTheToolAndPromptVersion(): void
    {
        $default = new ResultCache($this->dir, 'openai', 'gpt-x', [], true);
        $explicit = new ResultCache($this->dir, 'openai', 'gpt-x', [], true, \TusharKhan\SemanticSec\Console\Application::VERSION, \TusharKhan\SemanticSec\Llm\SecurityPrompt::VERSION);

        self::assertSame($explicit->key(self::payload()), $default->key(self::payload()));
    }

    public function testRoundTripReturnsOkWithStoredModelAndZeroTokens(): void
    {
        $cache = self::cache($this->dir);
        $payload = self::payload();
        self::assertNull($cache->get($payload));

        $cache->put($payload, self::ok('gpt-x-2026-01'));
        $hit = $cache->get($payload);

        self::assertNotNull($hit);
        self::assertSame(LlmOutcome::Ok, $hit->outcome);
        self::assertSame(self::data(), $hit->data);
        self::assertSame('gpt-x-2026-01', $hit->model);
        self::assertSame($payload->id, $hit->payloadId);
        self::assertSame(0, $hit->inputTokens);
        self::assertSame(0, $hit->outputTokens);
        self::assertSame(1, $cache->hits());
        self::assertSame([], $cache->warnings());

        $fresh = self::cache($this->dir);
        self::assertNotNull($fresh->get($payload), 'persists across instances');
    }

    public function testOnlyOkCached(): void
    {
        $cache = self::cache($this->dir);
        $payload = self::payload();
        foreach ([LlmOutcome::Refused, LlmOutcome::Truncated, LlmOutcome::Invalid] as $outcome) {
            $cache->put($payload, new LlmResponse($payload->id, $outcome, null, 10, 5, 'gpt-x', 'nope'));
        }

        self::assertSame([], self::files($this->dir));
        self::assertNull($cache->get($payload));
        self::assertSame(0, $cache->hits());
    }

    public function testOkWithInvalidDataIsNotCached(): void
    {
        $cache = self::cache($this->dir);
        $payload = self::payload();
        $cache->put($payload, new LlmResponse($payload->id, LlmOutcome::Ok, ['findings' => 'x'], 1, 1, 'gpt-x'));

        self::assertSame([], self::files($this->dir));
    }

    public function testReadDisabledStillWrites(): void
    {
        $payload = self::payload();
        $cache = new ResultCache($this->dir, 'openai', 'gpt-x', [], false);
        $cache->put($payload, self::ok());

        self::assertSame([$cache->key($payload).'.json'], self::files($this->dir));
        self::assertNull($cache->get($payload));
        self::assertSame(0, $cache->hits());
        self::assertNotNull((new ResultCache($this->dir, 'openai', 'gpt-x', [], true))->get($payload));
    }

    public function testFileHoldsOnlyVersionModelAndData(): void
    {
        $cache = self::cache($this->dir);
        $payload = self::payload();
        $cache->put($payload, new LlmResponse($payload->id, LlmOutcome::Ok, self::data(), 1234, 567, 'gpt-x', 'sk-secret-detail'));

        $raw = (string) file_get_contents($this->dir.'/'.$cache->key($payload).'.json');
        $stored = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        self::assertSame(['v', 'model', 'data'], array_keys($stored));
        self::assertSame(1, $stored['v']);
        self::assertSame('gpt-x', $stored['model']);
        self::assertSame(self::data(), $stored['data']);
        self::assertStringNotContainsString('sk-secret', $raw);
        self::assertStringNotContainsString('1234', $raw);
        self::assertStringNotContainsString($payload->code, $raw);
    }

    public function testCorruptFileIsMissWithWarning(): void
    {
        $payload = self::payload();
        $key = self::cache($this->dir)->key($payload);
        $good = json_encode(['v' => 1, 'model' => 'gpt-x', 'data' => self::data()], JSON_THROW_ON_ERROR);
        $corrupt = [
            'truncated' => substr($good, 0, (int) (strlen($good) / 2)),
            'not json' => 'hello',
            'empty' => '',
            'wrong v' => json_encode(['v' => 2, 'model' => 'gpt-x', 'data' => self::data()]),
            'string v' => json_encode(['v' => '1', 'model' => 'gpt-x', 'data' => self::data()]),
            'no model' => json_encode(['v' => 1, 'data' => self::data()]),
            'model not string' => json_encode(['v' => 1, 'model' => ['x'], 'data' => self::data()]),
            'data not array' => json_encode(['v' => 1, 'model' => 'gpt-x', 'data' => 'findings']),
            'data null' => json_encode(['v' => 1, 'model' => 'gpt-x', 'data' => null]),
            'top-level list' => '[1,2,3]',
            'top-level scalar' => '42',
            'deep nesting' => str_repeat('[', 5000).str_repeat(']', 5000),
        ];
        foreach ($corrupt as $what => $content) {
            file_put_contents($this->dir.'/'.$key.'.json', (string) $content);
            $cache = self::cache($this->dir);

            self::assertNull($cache->get($payload), $what);
            self::assertNull($cache->get($payload), $what.' (again)');
            self::assertSame(['cache entry '.$key.' ignored'], $cache->warnings(), $what);
            self::assertSame(0, $cache->hits(), $what);
        }
    }

    public function testUnreadableFileIsMissWithWarning(): void
    {
        $payload = self::payload();
        $key = self::cache($this->dir)->key($payload);
        mkdir($this->dir.'/'.$key.'.json');

        $cache = self::cache($this->dir);
        self::assertNull($cache->get($payload));
        self::assertSame(['cache entry '.$key.' ignored'], $cache->warnings());
    }

    public function testSymlinkedEntryIsMissWithWarning(): void
    {
        $payload = self::payload();
        $key = self::cache($this->dir)->key($payload);
        $elsewhere = $this->base.'/elsewhere.json';
        file_put_contents($elsewhere, (string) json_encode(['v' => 1, 'model' => 'gpt-x', 'data' => self::data()]));
        symlink($elsewhere, $this->dir.'/'.$key.'.json');

        $cache = self::cache($this->dir);
        self::assertNull($cache->get($payload));
        self::assertSame(['cache entry '.$key.' ignored'], $cache->warnings());
    }

    public function testMissingFileIsQuietMiss(): void
    {
        $cache = self::cache($this->dir);

        self::assertNull($cache->get(self::payload()));
        self::assertSame([], $cache->warnings());
    }

    public function testInvalidDataIsMiss(): void
    {
        $payload = self::payload();
        $key = self::cache($this->dir)->key($payload);
        $invalid = [
            'no findings' => [],
            'findings not list' => ['findings' => 'none'],
            'extra property' => ['findings' => [], 'extra' => 1],
            'bad category' => ['findings' => [ResponseValidatorTest::finding(['category' => 'xss'])]],
            'line zero' => ['findings' => [ResponseValidatorTest::finding(['line' => 0])]],
            'title too long' => ['findings' => [ResponseValidatorTest::finding(['title' => str_repeat('a', 121)])]],
        ];
        foreach ($invalid as $what => $data) {
            file_put_contents($this->dir.'/'.$key.'.json', (string) json_encode(['v' => 1, 'model' => 'gpt-x', 'data' => $data]));
            $cache = self::cache($this->dir);

            self::assertNull($cache->get($payload), $what);
            self::assertSame(['cache entry '.$key.' ignored'], $cache->warnings(), $what);
        }
    }

    public function testAtomicWrite(): void
    {
        $cache = self::cache($this->dir);
        $payload = self::payload();
        $target = $this->dir.'/'.$cache->key($payload).'.json';
        // A planted symlink at the target is replaced, never written through.
        $outside = $this->base.'/outside.txt';
        file_put_contents($outside, 'keep');
        symlink($outside, $target);

        $cache->put($payload, self::ok('first'));
        self::assertFalse(is_link($target));
        self::assertSame('keep', file_get_contents($outside));

        $cache->put($payload, self::ok('second'));
        self::assertSame([basename($target)], self::files($this->dir), 'no temp file left behind');
        self::assertSame('second', self::cache($this->dir)->get($payload)?->model);
    }

    public function testWriteFailureIsWarningNotCrash(): void
    {
        if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
            self::markTestSkipped('root ignores directory permissions');
        }
        $cache = self::cache($this->dir);
        $payload = self::payload();
        chmod($this->dir, 0555);

        $cache->put($payload, self::ok());

        chmod($this->dir, 0777);
        self::assertSame([], self::files($this->dir));
        self::assertSame(['cache entry '.$cache->key($payload).' not written'], $cache->warnings());
    }

    public function testInProjectPreparesGuardedDir(): void
    {
        $root = $this->base.'/project';
        mkdir($root);
        $cache = ResultCache::inProject($root, 'openai', 'gpt-x', [], true);
        $cache->put(self::payload(), self::ok());

        self::assertCount(1, self::files($root.'/'.ResultCache::DIR));

        $linked = $this->base.'/linked';
        mkdir($linked.'/.semantic-sec', 0777, true);
        symlink($this->base.'/elsewhere', $linked.'/.semantic-sec/cache');
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('is a symlink');
        ResultCache::inProject($linked, 'openai', 'gpt-x', [], true);
    }

    private static function cache(string $dir): ResultCache
    {
        return new ResultCache($dir, 'openai', 'gpt-x', [], true, '1.0.0', '2');
    }

    /** @return array<string, mixed> */
    private static function data(): array
    {
        return ['findings' => [ResponseValidatorTest::finding(['line' => 19.0])]];
    }

    private static function ok(string $model = 'gpt-x'): LlmResponse
    {
        return new LlmResponse('001-get-posts-id-1', LlmOutcome::Ok, self::data(), 100, 50, $model);
    }

    private static function payload(string $context = "Route:\n  GET /posts/{id}", string $code = '```php\n1| return Post::find($id);\n```'): Payload
    {
        $route = new RouteEntry(['GET'], '/posts/{id}', null, new RouteAction('App\Http\Controllers\PostController', 'show'), [], [], [], null, 'routes/web.php', 1);
        $node = new PathNode('App\Http\Controllers\PostController::show', null, null, 'app/Http/Controllers/PostController.php', 9, 13, 0, null, null);

        return new Payload('001-get-posts-id-1', new Candidate($route, new ExecutionPath([$node], []), [], []), $context, $code, 1, 1, false);
    }

    /** @return list<string> */
    private static function files(string $dir): array
    {
        return array_values(array_diff(scandir($dir) ?: [], ['.', '..']));
    }
}
