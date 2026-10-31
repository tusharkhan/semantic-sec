<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Llm;

use GuzzleHttp\Promise\Promise;
use GuzzleHttp\Promise\PromiseInterface;
use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Llm\ClientInterface;
use TusharKhan\SemanticSec\Llm\FakeClient;
use TusharKhan\SemanticSec\Llm\LlmException;
use TusharKhan\SemanticSec\Llm\LlmOutcome;
use TusharKhan\SemanticSec\Llm\LlmRequest;
use TusharKhan\SemanticSec\Llm\LlmResponse;
use TusharKhan\SemanticSec\Llm\RequestPool;

final class RequestPoolTest extends TestCase
{
    public function testConcurrencyNeverExceedsLimit(): void
    {
        $client = new DeferredClient(tokens: 1);

        $result = (new RequestPool($client, 3, null))->run(self::requests(10));

        self::assertSame(3, $client->maxInFlight);
        self::assertCount(10, $result->responses);
        self::assertSame(10, $result->usedTokens);
        self::assertFalse($result->budgetExceeded);
    }

    public function testConcurrencyOfOneIsSequential(): void
    {
        $client = new DeferredClient(tokens: 1);

        (new RequestPool($client, 1, null))->run(self::requests(4));

        self::assertSame(1, $client->maxInFlight);
        self::assertCount(4, $client->requests);
    }

    public function testBudgetStopsDispatchKeepsInFlight(): void
    {
        // Each request estimates 10 tokens and each answer costs 15.
        $client = new DeferredClient(tokens: 15);

        $result = (new RequestPool($client, 2, 20))->run(self::requests(5));

        self::assertTrue($result->budgetExceeded);
        self::assertCount(2, $client->requests);
        self::assertCount(2, $result->responses);
        self::assertSame(30, $result->usedTokens);
    }

    public function testBudgetExactlyAtLimitDispatches(): void
    {
        $client = new DeferredClient(tokens: 10);

        $result = (new RequestPool($client, 1, 20))->run(self::requests(3));

        self::assertCount(2, $result->responses);
        self::assertSame(20, $result->usedTokens);
        self::assertTrue($result->budgetExceeded);

        $single = (new RequestPool(new DeferredClient(tokens: 10), 1, 10))->run(self::requests(1));
        self::assertCount(1, $single->responses);
        self::assertFalse($single->budgetExceeded);
    }

    public function testBudgetCountsSystemAndUser(): void
    {
        $request = new LlmRequest('p1', str_repeat('s', 35), str_repeat('u', 35), [], 'm');

        $result = (new RequestPool(new DeferredClient(tokens: 1), 1, 19))->run([$request]);

        self::assertTrue($result->budgetExceeded);
        self::assertSame([], $result->responses);
    }

    public function testZeroRequests(): void
    {
        $client = new DeferredClient(tokens: 1);

        $result = (new RequestPool($client, 5, 100))->run([]);

        self::assertSame([], $result->responses);
        self::assertSame([], $result->failures);
        self::assertSame(0, $result->usedTokens);
        self::assertFalse($result->budgetExceeded);
        self::assertSame([], $client->requests);
    }

    public function testFailureRecordedNotThrown(): void
    {
        $ok = new LlmResponse('p2', LlmOutcome::Ok, ['findings' => []], 7, 3, 'm');
        $client = new FakeClient([
            'p1' => new LlmException('anthropic is unavailable (HTTP 429)', 429, true),
            'p2' => $ok,
            'p3' => new LlmException('anthropic rejected the API key (HTTP 401)', 401, false),
        ]);

        $result = (new RequestPool($client, 2, null))->run(self::requests(3));

        self::assertSame([$ok], $result->responses);
        self::assertSame(10, $result->usedTokens);
        $failures = $result->failures;
        usort($failures, static fn (array $a, array $b): int => $a['payloadId'] <=> $b['payloadId']);
        self::assertSame([
            ['payloadId' => 'p1', 'error' => 'anthropic is unavailable (HTTP 429)', 'retryable' => true],
            ['payloadId' => 'p3', 'error' => 'anthropic rejected the API key (HTTP 401)', 'retryable' => false],
        ], $failures);
    }

    public function testNoRetryInThePool(): void
    {
        $client = new FakeClient(['p1' => new LlmException('anthropic is unavailable (HTTP 503)', 503, true)]);

        (new RequestPool($client, 1, null))->run(self::requests(1));

        self::assertCount(1, $client->requests);
    }

    public function testSynchronousThrowIsRecorded(): void
    {
        $client = new FakeClient([]);

        $result = (new RequestPool($client, 1, null))->run(self::requests(1));

        self::assertSame([['payloadId' => 'p1', 'error' => 'unexpected LogicException', 'retryable' => false]], $result->failures);
    }

    public function testConcurrencyMustBePositive(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new RequestPool(new FakeClient([]), 0, null);
    }

    /** @return \Generator<int, LlmRequest> */
    private static function requests(int $n): \Generator
    {
        for ($i = 1; $i <= $n; $i++) {
            // 35 bytes estimate to exactly 10 tokens.
            yield new LlmRequest("p{$i}", '', str_repeat('x', 35), [], 'm');
        }
    }
}

/** Answers with pending promises that settle only when waited on, tracking how many are open. */
final class DeferredClient implements ClientInterface
{
    /** @var list<LlmRequest> */
    public array $requests = [];

    public int $maxInFlight = 0;

    private int $inFlight = 0;

    public function __construct(private readonly int $tokens)
    {
    }

    public function analyze(LlmRequest $request): PromiseInterface
    {
        $this->requests[] = $request;
        $this->inFlight++;
        $this->maxInFlight = max($this->maxInFlight, $this->inFlight);
        $promise = null;
        $promise = new Promise(function () use (&$promise, $request): void {
            assert($promise instanceof Promise);
            $this->inFlight--;
            $promise->resolve(new LlmResponse($request->payloadId, LlmOutcome::Ok, ['findings' => []], $this->tokens, 0, 'm'));
        });

        return $promise;
    }
}
