<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Llm;

use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Llm\ClientInterface;
use TusharKhan\SemanticSec\Llm\FindingSchema;
use TusharKhan\SemanticSec\Llm\Http\HttpClientFactory;
use TusharKhan\SemanticSec\Llm\LlmException;
use TusharKhan\SemanticSec\Llm\LlmOutcome;
use TusharKhan\SemanticSec\Llm\LlmRequest;
use TusharKhan\SemanticSec\Llm\LlmResponse;
use TusharKhan\SemanticSec\Llm\Provider\OllamaClient;
use TusharKhan\SemanticSec\Llm\ValidatingClient;
use TusharKhan\SemanticSec\Tests\Support\NetworkTrap;
use TusharKhan\SemanticSec\Tests\Support\ScriptedClient;

final class ValidatingClientTest extends TestCase
{
    private const SUFFIX_END = '. Answer again with valid JSON matching the schema.';

    public function testValidOkNotRetried(): void
    {
        $inner = self::scripted([self::ok(['findings' => []])]);

        $response = self::send($inner);

        self::assertSame(LlmOutcome::Ok, $response->outcome);
        self::assertCount(1, $inner->requests);
    }

    public function testRetryOnceThenSucceeds(): void
    {
        $bad = ['findings' => [ResponseValidatorTest::finding(['title' => str_repeat('x', 121)])]];
        $good = ['findings' => [ResponseValidatorTest::finding()]];
        $inner = self::scripted([self::ok($bad), self::ok($good)]);

        $response = self::send($inner);

        self::assertSame(LlmOutcome::Ok, $response->outcome);
        self::assertSame($good, $response->data);
        self::assertCount(2, $inner->requests);
        $suffix = "\n\nYour previous answer was invalid: /findings/0/title: must be 120 characters or fewer".self::SUFFIX_END;
        self::assertSame('payload'.$suffix, $inner->requests[1]->user);
        self::assertStringEndsWith($suffix, $inner->requests[1]->user);
        self::assertSame('payload', $inner->requests[0]->user);
    }

    public function testRetryOnceThenInvalid(): void
    {
        $bad = ['findings' => [ResponseValidatorTest::finding(['line' => 0])]];
        $inner = self::scripted([self::ok($bad), self::ok($bad)]);

        $response = self::send($inner);

        self::assertSame(LlmOutcome::Invalid, $response->outcome);
        self::assertNull($response->data);
        self::assertSame('/findings/0/line: must be 1 or more', $response->detail);
        self::assertCount(2, $inner->requests);
    }

    public function testEmptyObjectFailsThenRetries(): void
    {
        $inner = self::scripted([self::ok([]), self::ok(['findings' => []])]);

        $response = self::send($inner);

        self::assertSame(LlmOutcome::Ok, $response->outcome);
        self::assertCount(2, $inner->requests);
        self::assertStringContainsString('findings', $inner->requests[1]->user);
    }

    public function testInnerInvalidRetried(): void
    {
        $inner = self::scripted([self::invalid('generated JSON does not match the schema (HTTP 400)'), self::ok(['findings' => []])]);

        $response = self::send($inner);

        self::assertSame(LlmOutcome::Ok, $response->outcome);
        self::assertStringEndsWith("\n\nYour previous answer was invalid: generated JSON does not match the schema (HTTP 400)".self::SUFFIX_END, $inner->requests[1]->user);
    }

    public function testInvalidTwiceKeepsLastDetail(): void
    {
        $inner = self::scripted([self::invalid('first'), self::invalid('second')]);

        $response = self::send($inner);

        self::assertSame(LlmOutcome::Invalid, $response->outcome);
        self::assertSame('second', $response->detail);
    }

    public function testRefusedNotRetried(): void
    {
        $inner = self::scripted([new LlmResponse('p1', LlmOutcome::Refused, null, 10, 2, 'm1', 'cyber')]);

        $response = self::send($inner);

        self::assertSame(LlmOutcome::Refused, $response->outcome);
        self::assertSame('cyber', $response->detail);
        self::assertCount(1, $inner->requests);
    }

    public function testTruncatedNotRetried(): void
    {
        $inner = self::scripted([new LlmResponse('p1', LlmOutcome::Truncated, null, 10, 16000, 'm1')]);

        self::assertSame(LlmOutcome::Truncated, self::send($inner)->outcome);
        self::assertCount(1, $inner->requests);
    }

    public function testTokensSummed(): void
    {
        $inner = self::scripted([
            new LlmResponse('p1', LlmOutcome::Ok, [], 100, 20, 'model-a'),
            new LlmResponse('p1', LlmOutcome::Ok, ['findings' => []], 130, 7, 'model-b'),
        ]);

        $response = self::send($inner);

        self::assertSame(230, $response->inputTokens);
        self::assertSame(27, $response->outputTokens);
        self::assertSame('model-b', $response->model);
        self::assertSame('p1', $response->payloadId);
    }

    public function testTokensSummedWhenRetryIsRefused(): void
    {
        $inner = self::scripted([self::invalid('bad'), new LlmResponse('p1', LlmOutcome::Refused, null, 5, 1, 'model-b', 'cyber')]);

        $response = self::send($inner);

        self::assertSame(LlmOutcome::Refused, $response->outcome);
        self::assertSame(15, $response->inputTokens);
        self::assertSame(3, $response->outputTokens);
        self::assertSame('cyber', $response->detail);
    }

    public function testErrorSuffixCapped(): void
    {
        $many = array_fill(0, 300, ResponseValidatorTest::finding(['line' => 0]));
        $huge = ['findings' => [], str_repeat('k', 50_000) => 1];
        $inner = self::scripted([self::ok(['findings' => $many]), self::ok($huge)]);

        $response = self::send($inner);

        $suffix = substr($inner->requests[1]->user, strlen('payload'));
        self::assertLessThanOrEqual(1200, mb_strlen($suffix));
        self::assertStringEndsWith(self::SUFFIX_END, $suffix);
        self::assertSame(LlmOutcome::Invalid, $response->outcome);
        self::assertLessThanOrEqual(1000, mb_strlen((string) $response->detail));
        self::assertStringNotContainsString(str_repeat('k', 300), (string) $response->detail);
    }

    public function testRejectionPassesThroughUntouched(): void
    {
        $e = new LlmException('anthropic rejected the API key (HTTP 401)', 401, false);
        $inner = self::scripted([$e]);

        try {
            (new ValidatingClient($inner))->analyze(self::request())->wait();
            self::fail('expected the rejection');
        } catch (LlmException $caught) {
            self::assertSame($e, $caught);
        }
        self::assertCount(1, $inner->requests);
    }

    public function testInnerThrowingSynchronouslyBecomesRejection(): void
    {
        $inner = self::scripted([]);

        $promise = (new ValidatingClient($inner))->analyze(self::request());

        self::assertInstanceOf(PromiseInterface::class, $promise);
        $promise->wait(false);
        self::assertSame(PromiseInterface::REJECTED, $promise->getState());
    }

    public function testOllamaProseIsRetriedThenOk(): void
    {
        NetworkTrap::install();
        $body = static fn (string $content): string => (string) json_encode(['model' => 'llama4', 'message' => ['role' => 'assistant', 'content' => $content], 'done' => true, 'done_reason' => 'stop', 'prompt_eval_count' => 1200, 'eval_count' => 85]);
        $mock = new MockHandler([
            new Response(200, [], $body("Here are the findings:\n{\"findings\":[]}\nHope this helps.")),
            new Response(200, [], $body("```json\n{\"findings\":[]}\n```")),
        ]);
        $client = new ValidatingClient(new OllamaClient(HttpClientFactory::create($mock)));

        $response = $client->analyze(self::request('llama4'))->wait();

        self::assertSame([], NetworkTrap::uninstall(), 'no network');
        self::assertInstanceOf(LlmResponse::class, $response);
        self::assertSame(LlmOutcome::Ok, $response->outcome);
        self::assertSame(['findings' => []], $response->data);
        self::assertSame(2400, $response->inputTokens);
        self::assertSame(0, $mock->count());
    }

    private static function send(ClientInterface $client): LlmResponse
    {
        $response = (new ValidatingClient($client))->analyze(self::request())->wait();
        self::assertInstanceOf(LlmResponse::class, $response);

        return $response;
    }

    private static function request(string $model = 'm'): LlmRequest
    {
        return new LlmRequest('p1', 'system', 'payload', FindingSchema::schema(), $model);
    }

    /** @param array<string, mixed> $data */
    private static function ok(array $data): LlmResponse
    {
        return new LlmResponse('p1', LlmOutcome::Ok, $data, 10, 2, 'm1');
    }

    private static function invalid(string $detail): LlmResponse
    {
        return new LlmResponse('p1', LlmOutcome::Invalid, null, 10, 2, 'm1', $detail);
    }

    /** @param list<LlmResponse|LlmException> $script */
    private static function scripted(array $script): ScriptedClient
    {
        return new ScriptedClient($script);
    }
}
