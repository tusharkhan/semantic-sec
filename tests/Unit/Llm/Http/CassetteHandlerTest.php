<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Llm\Http;

use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Llm\Http\Cassette;
use TusharKhan\SemanticSec\Llm\Http\CassetteHandler;
use TusharKhan\SemanticSec\Llm\Http\HttpClientFactory;

final class CassetteHandlerTest extends TestCase
{
    private const KEY = 'sk-live/ab+c=9Z';

    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/semantic-sec-cassette-' . bin2hex(random_bytes(4));
        mkdir($this->dir);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/*') ?: [] as $file) {
            unlink($file);
        }
        rmdir($this->dir);
    }

    public function testReplaysInOrder(): void
    {
        $path = $this->writeCassette([
            $this->interaction('POST', 'https://api.example.test/v1/one', 200, '{"n":1}'),
            $this->interaction('GET', 'https://api.example.test/v1/two', 429, '{"n":2}'),
        ]);
        $client = HttpClientFactory::create(new CassetteHandler(Cassette::load($path), 'replay'));

        $first = $client->post('https://api.example.test/v1/one', ['body' => '{}']);
        $second = $client->get('https://api.example.test/v1/two', ['http_errors' => false]);

        self::assertSame(200, $first->getStatusCode());
        self::assertSame('{"n":1}', (string) $first->getBody());
        self::assertSame('application/json', $first->getHeaderLine('content-type'));
        self::assertSame(429, $second->getStatusCode());
        self::assertSame('{"n":2}', (string) $second->getBody());
    }

    public function testReplayMismatchNamesExpectedAndActual(): void
    {
        $path = $this->writeCassette([$this->interaction('POST', 'https://api.example.test/v1/one', 200, '{}')]);
        $client = HttpClientFactory::create(new CassetteHandler(Cassette::load($path), 'replay'));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage("cassette {$path}: expected POST https://api.example.test/v1/one, got GET https://api.example.test/v1/other");

        $client->get('https://api.example.test/v1/other');
    }

    public function testReplayPastTheEndFails(): void
    {
        $path = $this->writeCassette([]);
        $client = HttpClientFactory::create(new CassetteHandler(Cassette::load($path), 'replay'));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage("cassette {$path}: expected no more requests, got GET https://api.example.test/v1/one");

        $client->get('https://api.example.test/v1/one');
    }

    public function testRecordScrubsAuthHeaders(): void
    {
        $path = $this->dir . '/recorded.json';
        $inner = new MockHandler([new Response(200, ['content-type' => 'application/json'], '{"ok":true}')]);
        $handler = new CassetteHandler(Cassette::load($path), 'record', $inner);
        $client = HttpClientFactory::create($handler);

        $response = $client->post('https://api.example.test/v1/messages', [
            'headers' => ['x-api-key' => 'sk-test-123', 'Authorization' => 'Bearer sk-test-123', 'api-key' => 'sk-test-123', 'anthropic-version' => '2026-10-21'],
            'body' => '{"q":1}',
        ]);

        self::assertSame('{"ok":true}', (string) $response->getBody());
        $json = (string) file_get_contents($path);
        self::assertStringNotContainsString('sk-test-123', $json);
        $saved = json_decode($json, true, flags: JSON_THROW_ON_ERROR);
        self::assertIsArray($saved);
        $request = $saved['interactions'][0]['request'];
        self::assertSame('<scrubbed>', $request['headers']['x-api-key']);
        self::assertSame('<scrubbed>', $request['headers']['Authorization']);
        self::assertSame('<scrubbed>', $request['headers']['api-key']);
        self::assertSame('2026-10-21', $request['headers']['anthropic-version']);
        self::assertSame('POST', $request['method']);
        self::assertSame('{"q":1}', $request['body']);
        self::assertSame(200, $saved['interactions'][0]['response']['status']);
        self::assertSame('{"ok":true}', $saved['interactions'][0]['response']['body']);

        $replayed = HttpClientFactory::create(new CassetteHandler(Cassette::load($path), 'replay'))
            ->post('https://api.example.test/v1/messages', ['body' => '{"q":1}']);
        self::assertSame('{"ok":true}', (string) $replayed->getBody());
    }

    public function testRejectsUnknownMode(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new CassetteHandler(Cassette::load($this->dir . '/x.json'), 'live');
    }

    public function testFactoryPushesMiddleware(): void
    {
        $seen = [];
        $spy = static function (callable $next) use (&$seen): callable {
            return static function (\Psr\Http\Message\RequestInterface $request, array $options) use ($next, &$seen) {
                $seen[] = $request->getMethod() . ' ' . $request->getUri();

                return $next($request, $options);
            };
        };
        $client = HttpClientFactory::create(new MockHandler([new Response(204)]), ['spy' => $spy]);

        $client->send(new Request('DELETE', 'https://api.example.test/v1/x'));

        self::assertSame(['DELETE https://api.example.test/v1/x'], $seen);
    }

    public function testRecordScrubsSensitiveQueryValuesAndReplayMatchesScrubbedForm(): void
    {
        $path = $this->dir . '/query.json';
        $inner = new MockHandler([new Response(200, [], '{}')]);
        $uri = 'https://api.example.test/v1/x?key=sk-live-999&model=m&access_token=abc&Signature=s1&page=2&password=p&auth=a&client_secret=c';
        HttpClientFactory::create(new CassetteHandler(Cassette::load($path), 'record', $inner))->get($uri);

        $saved = $this->saved($path);
        self::assertSame(
            'https://api.example.test/v1/x?key=<scrubbed>&model=m&access_token=<scrubbed>&Signature=<scrubbed>&page=2&password=<scrubbed>&auth=<scrubbed>&client_secret=<scrubbed>',
            $saved['interactions'][0]['request']['uri'],
        );

        $replay = HttpClientFactory::create(new CassetteHandler(Cassette::load($path), 'replay'));
        self::assertSame(200, $replay->get($uri)->getStatusCode());
    }

    public function testReplayStillRejectsADifferentNonSecretQuery(): void
    {
        $path = $this->writeCassette([$this->interaction('GET', 'https://api.example.test/v1/x?key=<scrubbed>&page=2', 200, '{}')]);
        $client = HttpClientFactory::create(new CassetteHandler(Cassette::load($path), 'replay'));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('expected GET https://api.example.test/v1/x?key=<scrubbed>&page=2, got GET https://api.example.test/v1/x?key=<scrubbed>&page=3');

        $client->get('https://api.example.test/v1/x?key=other&page=3');
    }

    public function testRecordScrubsHeadersByNamePattern(): void
    {
        $path = $this->dir . '/headers.json';
        $inner = new MockHandler([new Response(200, ['Set-Cookie' => 's=1', 'X-Session-Id' => 'abc', 'X-Request-Id' => 'req-1'], '{}')]);
        HttpClientFactory::create(new CassetteHandler(Cassette::load($path), 'record', $inner))->get('https://api.example.test/v1/x', [
            'headers' => ['X-Goog-Api-Key' => 'g', 'Cookie' => 'a=1', 'Proxy-Authorization' => 'Basic x', 'X-Auth-Token' => 't', 'Accept' => 'application/json'],
        ]);

        $saved = $this->saved($path)['interactions'][0];
        foreach (['X-Goog-Api-Key', 'Cookie', 'Proxy-Authorization', 'X-Auth-Token'] as $name) {
            self::assertSame('<scrubbed>', $saved['request']['headers'][$name], $name);
        }
        self::assertSame('application/json', $saved['request']['headers']['Accept']);
        self::assertSame('<scrubbed>', $saved['response']['headers']['Set-Cookie']);
        self::assertSame('<scrubbed>', $saved['response']['headers']['X-Session-Id']);
        self::assertSame('req-1', $saved['response']['headers']['X-Request-Id']);
    }

    public function testRecordScrubsOrganizationHeaders(): void
    {
        $path = $this->dir . '/org.json';
        $inner = new MockHandler([new Response(200, ['anthropic-organization-id' => 'org-123', 'OpenAI-Organization' => 'org-x', 'X-Request-Id' => 'req-1'], '{}')]);
        HttpClientFactory::create(new CassetteHandler(Cassette::load($path), 'record', $inner))->get('https://api.example.test/v1/x', ['headers' => ['OpenAI-Organization' => 'org-y']]);

        $saved = $this->saved($path)['interactions'][0];
        self::assertSame('<scrubbed>', $saved['request']['headers']['OpenAI-Organization']);
        self::assertSame('<scrubbed>', $saved['response']['headers']['anthropic-organization-id']);
        self::assertSame('<scrubbed>', $saved['response']['headers']['OpenAI-Organization']);
        self::assertSame('req-1', $saved['response']['headers']['X-Request-Id']);
    }

    public function testCommittedCassettesCarryNoOrganizationIds(): void
    {
        foreach (glob(__DIR__ . '/../../../Fixtures/cassettes/*/*.json') ?: [] as $file) {
            $json = json_decode((string) file_get_contents($file), true, 512, JSON_THROW_ON_ERROR);
            foreach ($json['interactions'] as $i) {
                foreach (['request', 'response'] as $side) {
                    foreach ($i[$side]['headers'] as $name => $value) {
                        if (stripos((string) $name, 'organization') !== false) {
                            self::assertSame('<scrubbed>', $value, basename($file) . ' ' . $name);
                        }
                    }
                }
            }
        }
    }

    public function testRecordReplacesConfiguredSecretsEverywhere(): void
    {
        $path = $this->dir . '/secrets.json';
        $inner = new MockHandler([new Response(400, ['X-Echo' => 'got sk-live-999'], '{"error":"bad key sk-live-999"}')]);
        $handler = new CassetteHandler(Cassette::load($path), 'record', $inner, ['', 'sk-live-999']);
        HttpClientFactory::create($handler)->post('https://api.example.test/v1/sk-live-999/x', [
            'headers' => ['X-Trace' => 'sk-live-999'],
            'body' => '{"prompt":"use sk-live-999 please"}',
            'http_errors' => false,
        ]);

        $json = (string) file_get_contents($path);
        self::assertStringNotContainsString('sk-live-999', $json);
        $saved = $this->saved($path)['interactions'][0];
        self::assertSame('https://api.example.test/v1/<scrubbed>/x', $saved['request']['uri']);
        self::assertSame('<scrubbed>', $saved['request']['headers']['X-Trace']);
        self::assertSame('got <scrubbed>', $saved['response']['headers']['X-Echo']);
        self::assertSame('{"prompt":"use <scrubbed> please"}', $saved['request']['body']);
        self::assertSame('{"error":"bad key <scrubbed>"}', $saved['response']['body']);
    }

    public function testReplayMatchesARealRequestWithTheKeyInPathAndQuery(): void
    {
        $path = $this->dir . '/replay-secret.json';
        $uri = 'https://api.example.test/v1/' . self::KEY . '/x?q=' . urlencode(self::KEY) . '&mode=1';
        $inner = new MockHandler([new Response(200, [], '{"ok":true}')]);
        HttpClientFactory::create(new CassetteHandler(Cassette::load($path), 'record', $inner, [self::KEY]))->get($uri);

        self::assertSame('https://api.example.test/v1/<scrubbed>/x?q=<scrubbed>&mode=1', $this->saved($path)['interactions'][0]['request']['uri']);
        $handler = new CassetteHandler(Cassette::load($path), 'replay', secrets: [self::KEY]);
        self::assertSame('{"ok":true}', (string) HttpClientFactory::create($handler)->get($uri)->getBody());
        $handler->assertExhausted();
    }

    public function testDebugOutputOmitsSecrets(): void
    {
        $path = $this->writeCassette([$this->interaction('GET', 'https://api.example.test/x', 200, '{}')]);
        $handler = new CassetteHandler(Cassette::load($path), 'replay', secrets: [self::KEY]);

        $dump = print_r($handler, true);

        self::assertStringNotContainsString(self::KEY, $dump);
        self::assertStringNotContainsString(urlencode(self::KEY), $dump);
        self::assertStringNotContainsString(base64_encode(self::KEY), $dump);
    }

    public function testReplayMismatchNeverEchoesTheKey(): void
    {
        $path = $this->writeCassette([$this->interaction('GET', 'https://api.example.test/v1/<scrubbed>/x', 200, '{}')]);
        $client = HttpClientFactory::create(new CassetteHandler(Cassette::load($path), 'replay', secrets: [self::KEY]));

        try {
            $client->get('https://api.example.test/v2/' . self::KEY . '/x');
            self::fail('expected a mismatch');
        } catch (\LogicException $e) {
            self::assertStringNotContainsString(self::KEY, $e->getMessage());
            self::assertStringContainsString('got GET https://api.example.test/v2/<scrubbed>/x', $e->getMessage());
        }
    }

    /** @return iterable<string, array{string}> */
    public static function encodedKeys(): iterable
    {
        yield 'raw' => [self::KEY];
        yield 'urlencode' => [urlencode(self::KEY)];
        yield 'rawurlencode' => [rawurlencode(self::KEY)];
        yield 'json escaped' => [substr((string) json_encode(self::KEY), 1, -1)];
        yield 'base64' => [base64_encode(self::KEY)];
    }

    #[DataProvider('encodedKeys')]
    public function testRecordScrubsEveryEncodingInEveryLocation(string $variant): void
    {
        $path = $this->dir . '/variants.json';
        $leaf = '{"leaf":"x ' . $variant . ' y"}';
        $key = '{"' . $variant . '":{"deep":["t ' . $variant . '"]}}';
        $inner = new MockHandler([
            new Response(200, ['X-Echo' => 'a' . $variant], $leaf),
            new Response(200, [], $key),
            new Response(200, [], 'plain ' . $variant . ' text'),
        ]);
        $handler = new CassetteHandler(Cassette::load($path), 'record', $inner, ['', self::KEY]);
        $client = HttpClientFactory::create($handler);
        $first = 'https://api.example.test/v1/' . $variant . '/x?q=' . $variant . '&mode=1';
        $client->post($first, ['headers' => ['X-Custom' => 'a' . $variant], 'body' => $leaf]);
        $client->post('https://api.example.test/v1/keys', ['body' => $key]);
        $client->post('https://api.example.test/v1/plain', ['body' => 'plain ' . $variant . ' text']);

        $json = (string) file_get_contents($path);
        foreach (self::encodedKeys() as $name => [$needle]) {
            self::assertStringNotContainsString($needle, $json, "{$name} survived");
        }
        $saved = $this->saved($path)['interactions'];
        self::assertSame('https://api.example.test/v1/<scrubbed>/x?q=<scrubbed>&mode=1', $saved[0]['request']['uri']);
        self::assertSame('a<scrubbed>', $saved[0]['request']['headers']['X-Custom']);
        self::assertSame('a<scrubbed>', $saved[0]['response']['headers']['X-Echo']);
        foreach (['request', 'response'] as $side) {
            self::assertSame(['leaf' => 'x <scrubbed> y'], json_decode($saved[0][$side]['body'], true, flags: JSON_THROW_ON_ERROR));
            self::assertSame(['<scrubbed>' => ['deep' => ['t <scrubbed>']]], json_decode($saved[1][$side]['body'], true, flags: JSON_THROW_ON_ERROR));
            self::assertSame('plain <scrubbed> text', $saved[2][$side]['body']);
        }

        $replay = new CassetteHandler(Cassette::load($path), 'replay', secrets: [self::KEY]);
        $replayClient = HttpClientFactory::create($replay);
        $replayClient->post($first);
        $replayClient->post('https://api.example.test/v1/keys');
        $replayClient->post('https://api.example.test/v1/plain');
        $replay->assertExhausted();
    }

    public function testRecordRedactsSecretLookingBodyValuesAndKeepsJsonValid(): void
    {
        $path = $this->dir . '/redact.json';
        $github = 'ghp_' . str_repeat('aB3dE5', 6);
        $aws = 'AKIA' . 'ABCDEFGHIJKLMNOP';
        $inner = new MockHandler([new Response(200, [], "plain text with {$aws} inside")]);
        $body = '{"note":"token ' . $github . ' \"quoted\"","empty":{},"n":1.0,"list":[]}';
        HttpClientFactory::create(new CassetteHandler(Cassette::load($path), 'record', $inner))->post('https://api.example.test/v1/x', ['body' => $body]);

        $json = (string) file_get_contents($path);
        self::assertStringNotContainsString($github, $json);
        $saved = $this->saved($path)['interactions'][0];
        $request = json_decode($saved['request']['body'], false, flags: JSON_THROW_ON_ERROR);
        self::assertInstanceOf(\stdClass::class, $request);
        self::assertSame('token <redacted> "quoted"', $request->note);
        self::assertInstanceOf(\stdClass::class, $request->empty);
        self::assertSame(1.0, $request->n);
        self::assertSame("plain text with {$aws} inside", $saved['response']['body'], 'response bodies are recorded as received');
    }

    public function testRecordKeepsResponseBodiesVerbatimButScrubsSecrets(): void
    {
        $path = $this->dir . '/response.json';
        $file = 'app/Http/Controllers/Vuln/AccountController.php';
        $patch = "--- a/app/X.php\n+++ b/app/X.php\n@@ -1 +1 @@\n-old\n+new\n--- a/{$file}\n+++ b/{$file}\n@@ -13,2 +13,2 @@";
        $text = json_encode(['patch' => $patch], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        $response = json_encode(['content' => [['text' => $text]], 'leak' => 'k=' . self::KEY], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        $inner = new MockHandler([new Response(200, [], $response)]);
        $client = HttpClientFactory::create(new CassetteHandler(Cassette::load($path), 'record', $inner, [self::KEY]));
        $client->post('https://api.example.test/v1/x', ['body' => '{"q":"password = \\"hunter2hunter2\\""}']);

        $json = (string) file_get_contents($path);
        self::assertStringNotContainsString(self::KEY, $json);
        $saved = $this->saved($path)['interactions'][0];
        $body = json_decode($saved['response']['body'], true, flags: JSON_THROW_ON_ERROR);
        $data = json_decode($body['content'][0]['text'], true, flags: JSON_THROW_ON_ERROR);
        self::assertSame($patch, $data['patch'], 'the response body is not run through the Redactor');
        self::assertSame('k=<scrubbed>', $body['leak'], 'configured secrets are still scrubbed');
        self::assertStringNotContainsString('hunter2hunter2', $saved['request']['body'], 'request bodies are still redacted');
    }

    public function testRecordRedactsRequestSecretsNestedInArrays(): void
    {
        $path = $this->dir . '/nested.json';
        $github = 'ghp_' . str_repeat('aB3dE5', 6);
        $inner = new MockHandler([new Response(200, [], '{}')]);
        $body = json_encode(['messages' => [['role' => 'user', 'content' => [['text' => "token {$github}"]]]]], JSON_THROW_ON_ERROR);
        HttpClientFactory::create(new CassetteHandler(Cassette::load($path), 'record', $inner))->post('https://api.example.test/v1/x', ['body' => $body]);

        self::assertStringNotContainsString($github, (string) file_get_contents($path));
        $request = json_decode($this->saved($path)['interactions'][0]['request']['body'], true, flags: JSON_THROW_ON_ERROR);
        self::assertSame('token <redacted>', $request['messages'][0]['content'][0]['text']);
    }

    public function testRecordLeavesCleanJsonBodiesVerbatim(): void
    {
        $path = $this->dir . '/verbatim.json';
        $inner = new MockHandler([new Response(200, [], '{ "ok" : true }')]);
        HttpClientFactory::create(new CassetteHandler(Cassette::load($path), 'record', $inner))->post('https://api.example.test/v1/x', ['body' => "{\n  \"model\": \"claude-opus-5-5\"\n}"]);

        $saved = $this->saved($path)['interactions'][0];
        self::assertSame("{\n  \"model\": \"claude-opus-5-5\"\n}", $saved['request']['body']);
        self::assertSame('{ "ok" : true }', $saved['response']['body']);
    }

    public function testRecordDropsTransportHeaders(): void
    {
        $path = $this->dir . '/transport.json';
        $inner = new MockHandler([new Response(200, ['Content-Encoding' => 'gzip', 'Content-Length' => '11', 'Transfer-Encoding' => 'chunked', 'Content-Type' => 'application/json'], '{"ok":true}')]);
        HttpClientFactory::create(new CassetteHandler(Cassette::load($path), 'record', $inner))->get('https://api.example.test/v1/x');

        self::assertSame(['Content-Type' => 'application/json'], $this->saved($path)['interactions'][0]['response']['headers']);
    }

    public function testRecordOverwritesAnExistingCassette(): void
    {
        $path = $this->writeCassette([
            $this->interaction('GET', 'https://api.example.test/v1/old1', 200, '{}'),
            $this->interaction('GET', 'https://api.example.test/v1/old2', 200, '{}'),
        ]);
        $inner = new MockHandler([new Response(200, [], '{"new":true}')]);
        HttpClientFactory::create(new CassetteHandler(Cassette::load($path), 'record', $inner))->get('https://api.example.test/v1/new');

        $interactions = $this->saved($path)['interactions'];
        self::assertCount(1, $interactions);
        self::assertSame('https://api.example.test/v1/new', $interactions[0]['request']['uri']);
    }

    public function testAssertExhaustedReportsUnusedInteractions(): void
    {
        $path = $this->writeCassette([
            $this->interaction('GET', 'https://api.example.test/v1/one', 200, '{}'),
            $this->interaction('GET', 'https://api.example.test/v1/two', 200, '{}'),
        ]);
        $handler = new CassetteHandler(Cassette::load($path), 'replay');
        $client = HttpClientFactory::create($handler);
        $client->get('https://api.example.test/v1/one');

        try {
            $handler->assertExhausted();
            self::fail('expected unused interactions to be reported');
        } catch (\LogicException $e) {
            self::assertSame("cassette {$path}: 1 unused interactions", $e->getMessage());
        }

        $client->get('https://api.example.test/v1/two');
        $handler->assertExhausted();
    }

    public function testBodyReplayMatchesWhatWasRecordedDespiteRedaction(): void
    {
        $path = $this->dir . '/round-trip.json';
        $entropy = 'Zx9qLm2vT8rB4nKw7YpC3sHd6FgJ1aUe';
        $bodies = [
            json_encode(['system' => [['type' => 'text', 'text' => 'review']], 'messages' => [['role' => 'user', 'content' => "L3| \$k = '{$entropy}'; // sk-proj-" . str_repeat('A1b2', 8) . "\nL4| key " . self::KEY]]], JSON_THROW_ON_ERROR),
            '{"messages":[{"role":"user","content":"clean body, n=1.0"}],"n":1.0}',
        ];
        $inner = new MockHandler([new Response(200, [], '{"r":1}'), new Response(200, [], '{"r":2}')]);
        $recorder = HttpClientFactory::create(new CassetteHandler(Cassette::load($path), 'record', $inner, [self::KEY], 'body'));
        foreach ($bodies as $body) {
            $recorder->post('https://api.example.test/v1/messages', ['body' => $body]);
        }
        self::assertStringNotContainsString($entropy, (string) file_get_contents($path));

        $handler = new CassetteHandler(Cassette::load($path), 'replay', secrets: [self::KEY], match: 'body');
        $replay = HttpClientFactory::create($handler);
        self::assertSame('{"r":2}', (string) $replay->post('https://api.example.test/v1/messages', ['body' => $bodies[1]])->getBody());
        self::assertSame('{"r":1}', (string) $replay->post('https://api.example.test/v1/messages', ['body' => $bodies[0]])->getBody());
        $handler->assertExhausted();
    }

    public function testReplayOfMissingFileFails(): void
    {
        $path = $this->dir . '/missing.json';

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage("cassette not found: {$path}");

        new CassetteHandler(Cassette::load($path), 'replay');
    }

    /** @return array{interactions: list<array{request: array{method: string, uri: string, headers: array<string, string>, body: string}, response: array{status: int, headers: array<string, string>, body: string}}>} */
    private function saved(string $path): array
    {
        /** @var array{interactions: list<array{request: array{method: string, uri: string, headers: array<string, string>, body: string}, response: array{status: int, headers: array<string, string>, body: string}}>} */
        return json_decode((string) file_get_contents($path), true, flags: JSON_THROW_ON_ERROR);
    }

    public function testBodyModeIgnoresOrder(): void
    {
        $path = $this->writeCassette([
            $this->bodied('POST', 'https://api.example.test/v1/m', '{"q":"one","k":"<scrubbed>"}', '{"n":1}'),
            $this->bodied('POST', 'https://api.example.test/v1/m', '{"q":"two","k":"<scrubbed>"}', '{"n":2}'),
            $this->bodied('POST', 'https://api.example.test/v1/m', '{"q":"two","k":"<scrubbed>"}', '{"n":3}'),
        ]);
        $handler = new CassetteHandler(Cassette::load($path), 'replay', secrets: [self::KEY], match: 'body');
        $client = HttpClientFactory::create($handler);
        $send = static fn (string $q): string => (string) $client->post('https://api.example.test/v1/m', ['body' => json_encode(['q' => $q, 'k' => self::KEY], JSON_UNESCAPED_SLASHES)])->getBody();

        self::assertSame('{"n":2}', $send('two'));
        self::assertSame('{"n":1}', $send('one'));
        try {
            $handler->assertExhausted();
            self::fail('one interaction is still unused');
        } catch (\LogicException $e) {
            self::assertStringContainsString('1 unused interactions', $e->getMessage());
        }
        self::assertSame('{"n":3}', $send('two'), 'a used interaction is never replayed twice');
        $handler->assertExhausted();

        $this->expectException(\LogicException::class);
        $send('two');
    }

    public function testBodyModeMismatchNamesNothingSecret(): void
    {
        $path = $this->writeCassette([$this->bodied('POST', 'https://api.example.test/v1/m', '{"q":"recorded"}', '{}')]);
        $client = HttpClientFactory::create(new CassetteHandler(Cassette::load($path), 'replay', secrets: [self::KEY], match: 'body'));
        $body = json_encode(['q' => 'private source code', 'k' => self::KEY, 'aws' => 'AKIAIOSFODNN7EXAMPLE'], JSON_UNESCAPED_SLASHES);
        $scrubbed = json_encode(['q' => 'private source code', 'k' => '<scrubbed>', 'aws' => '<redacted>'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        try {
            $client->post('https://api.example.test/v1/m', ['body' => $body]);
            self::fail('a mismatch must throw');
        } catch (\LogicException $e) {
            $message = $e->getMessage();
        }

        self::assertSame("cassette {$path}: no unused interaction for POST https://api.example.test/v1/m with body sha256 " . hash('sha256', (string) $scrubbed), $message);
        foreach (['private source code', self::KEY, 'AKIAIOSFODNN7EXAMPLE', 'recorded'] as $leak) {
            self::assertStringNotContainsString($leak, $message);
        }
    }

    public function testBodyModeRejectsUnknownMatch(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new CassetteHandler(Cassette::load($this->writeCassette([])), 'replay', match: 'random');
    }

    /** @return array<string, mixed> */
    private function bodied(string $method, string $uri, string $requestBody, string $responseBody): array
    {
        return [
            'request' => ['method' => $method, 'uri' => $uri, 'headers' => [], 'body' => $requestBody],
            'response' => ['status' => 200, 'headers' => ['content-type' => 'application/json'], 'body' => $responseBody],
        ];
    }

    /** @param list<array<string, mixed>> $interactions */
    private function writeCassette(array $interactions): string
    {
        $path = $this->dir . '/cassette.json';
        file_put_contents($path, json_encode(['interactions' => $interactions], JSON_THROW_ON_ERROR));

        return $path;
    }

    /** @return array<string, mixed> */
    private function interaction(string $method, string $uri, int $status, string $body): array
    {
        return [
            'request' => ['method' => $method, 'uri' => $uri, 'headers' => [], 'body' => ''],
            'response' => ['status' => $status, 'headers' => ['content-type' => 'application/json'], 'body' => $body],
        ];
    }
}
