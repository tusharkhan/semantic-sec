<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Llm;

use GuzzleHttp\Promise\Create;
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
use TusharKhan\SemanticSec\Llm\ValidatingClient;
use TusharKhan\SemanticSec\Payload\TokenEstimator;

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
        // Each request reserves 2 × (10 + 5) + T tokens and each answer costs 15.
        $client = new DeferredClient(tokens: 15);

        $result = (new RequestPool($client, 2, 60 + 2 * self::retryText()))->run(self::requests(5));

        self::assertTrue($result->budgetExceeded);
        self::assertCount(2, $client->requests);
        self::assertCount(2, $result->responses);
        self::assertSame(30, $result->usedTokens);
    }

    public function testBudgetExactlyAtLimitDispatches(): void
    {
        $client = new DeferredClient(tokens: 10);

        // The second dispatch lands exactly on 10 used + (30 + T) reserved.
        $result = (new RequestPool($client, 1, 40 + self::retryText()))->run(self::requests(3));

        self::assertCount(2, $result->responses);
        self::assertSame(20, $result->usedTokens);
        self::assertTrue($result->budgetExceeded);

        $single = (new RequestPool(new DeferredClient(tokens: 10), 1, 30 + self::retryText()))->run(self::requests(1));
        self::assertCount(1, $single->responses);
        self::assertFalse($single->budgetExceeded);
    }

    public function testActualAboveReservationStillMarksBudgetExceeded(): void
    {
        // A client that bills more than it reserved is the only way past the cap.
        $client = new DeferredClient(tokens: 45 + self::retryText());

        $result = (new RequestPool($client, 2, 60 + 2 * self::retryText()))->run(self::requests(2));

        self::assertCount(2, $result->responses);
        self::assertSame(90 + 2 * self::retryText(), $result->usedTokens);
        self::assertTrue($result->budgetExceeded);
    }

    public function testBudgetCountsSystemAndUserAndMaxTokens(): void
    {
        // 70 bytes with the `[]` schema estimate to 20, so the reservation is 2 × (20 + 5) + T.
        $request = new LlmRequest('p1', str_repeat('s', 35), str_repeat('u', 33), [], 'm', maxTokens: 5);

        $result = (new RequestPool(new DeferredClient(tokens: 1), 1, 49 + self::retryText()))->run([$request]);
        self::assertTrue($result->budgetExceeded);
        self::assertSame([], $result->responses);

        $result = (new RequestPool(new DeferredClient(tokens: 1), 1, 50 + self::retryText()))->run([$request]);
        self::assertFalse($result->budgetExceeded);
        self::assertCount(1, $result->responses);
    }

    public function testDefaultMaxTokensIsReserved(): void
    {
        $request = new LlmRequest('p1', '', str_repeat('x', 33), [], 'm');

        $result = (new RequestPool(new DeferredClient(tokens: 1), 1, 32019 + self::retryText()))->run([$request]);

        self::assertTrue($result->budgetExceeded);
        self::assertSame([], $result->responses);
    }

    public function testLargeSchemaAndRetryTextStayWithinBudget(): void
    {
        $schema = ['description' => str_repeat('s', 7000)];
        $base = TokenEstimator::estimate(str_repeat('x', 35).json_encode($schema));
        // Exactly one full reservation: two calls at full input and output, plus the longest retry text.
        $budget = 2 * ($base + 5) + TokenEstimator::forBytes(ValidatingClient::MAX_RETRY_SUFFIX_BYTES);
        $inner = new SchemaBillingClient();
        $requests = array_map(static fn (int $i): LlmRequest => new LlmRequest("p{$i}", '', str_repeat('x', 35), $schema, 'm', 5), [1, 2, 3]);

        $result = (new RequestPool(new ValidatingClient($inner), 2, $budget))->run($requests);

        self::assertCount(2, $inner->requests);
        self::assertGreaterThan(2 * ($base + 5), $result->usedTokens);
        self::assertLessThanOrEqual($budget, $result->usedTokens);
        self::assertTrue($result->budgetExceeded);
    }

    public function testBudgetBelowOneReservationDispatchesNothing(): void
    {
        $client = new DeferredClient(tokens: 1);

        $result = (new RequestPool($client, 5, 29 + self::retryText()))->run(self::requests(3));

        self::assertSame([], $client->requests);
        self::assertSame([], $result->responses);
        self::assertSame([], $result->failures);
        self::assertSame(0, $result->usedTokens);
        self::assertTrue($result->budgetExceeded);
    }

    public function testReservationReleasedOnFailure(): void
    {
        $client = new ScriptedClient([
            'p1' => new LlmException('anthropic request failed (HTTP 500)', 500, true, spentTokens: 5),
            'p2' => new \RuntimeException('sync'),
            'p3' => 'not a response',
            'p4' => new LlmResponse('p4', LlmOutcome::Ok, ['findings' => []], 10, 0, 'm'),
            'p5' => new LlmResponse('p5', LlmOutcome::Ok, ['findings' => []], 10, 0, 'm'),
            'p6' => new LlmResponse('p6', LlmOutcome::Ok, ['findings' => []], 10, 0, 'm'),
            'p7' => new LlmResponse('p7', LlmOutcome::Ok, ['findings' => []], 10, 0, 'm'),
        ]);

        // Failures free their 30 + T; p6 lands on 25 + 30 + T, and p7 would need 35 + 30 + T.
        $result = (new RequestPool($client, 1, 60 + self::retryText()))->run(self::requests(7));

        self::assertSame(['p1', 'p2', 'p3', 'p4', 'p5', 'p6'], array_map(static fn (LlmRequest $r): string => $r->payloadId, $client->requests));
        self::assertCount(3, $result->failures);
        self::assertSame(35, $result->usedTokens);
        self::assertTrue($result->budgetExceeded);
    }

    public function testNullBudgetUnchanged(): void
    {
        $client = new DeferredClient(tokens: 1_000_000);

        $result = (new RequestPool($client, 2, null))->run(self::requests(5, maxTokens: 16000));

        self::assertCount(5, $client->requests);
        self::assertCount(5, $result->responses);
        self::assertSame(5_000_000, $result->usedTokens);
        self::assertFalse($result->budgetExceeded);
    }

    public function testNeverExceedsBudgetWithConcurrencyAndRetries(): void
    {
        $budget = 5 * (30 + self::retryText()) + 400;
        $inner = new BillingClient(budget: $budget);

        $result = (new RequestPool(new ValidatingClient($inner), 5, $budget))->run(self::requests(50));

        self::assertGreaterThan(5, count($inner->dispatched));
        self::assertLessThan(50, count($inner->dispatched));
        self::assertGreaterThan(0, $inner->retries);
        self::assertGreaterThan(0, $inner->maxInFlight - 1);
        self::assertSame($inner->billed, $result->usedTokens);
        self::assertLessThanOrEqual($budget, $inner->peak);
        self::assertLessThanOrEqual($budget, $result->usedTokens);
        self::assertTrue($result->budgetExceeded);
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

    public function testFailureSpentTokensAreCounted(): void
    {
        $client = new FakeClient([
            'p1' => new LlmException('anthropic request failed (HTTP 500)', 500, true, spentTokens: 1100),
            'p2' => new LlmResponse('p2', LlmOutcome::Ok, ['findings' => []], 7, 3, 'm'),
        ]);

        $result = (new RequestPool($client, 2, null))->run(self::requests(2));

        self::assertSame(1110, $result->usedTokens);
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

    public function testAnonymousClassIsNamedWithoutPath(): void
    {
        $client = new class () implements ClientInterface {
            public function analyze(LlmRequest $request): PromiseInterface
            {
                throw new class ('boom') extends \RuntimeException {
                };
            }
        };

        $result = (new RequestPool($client, 1, null))->run(self::requests(1));

        self::assertSame('unexpected anonymous class', $result->failures[0]['error']);
    }

    public function testConcurrencyMustBePositive(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new RequestPool(new FakeClient([]), 0, null);
    }

    /** @return \Generator<int, LlmRequest> */
    private static function requests(int $n, int $maxTokens = 5): \Generator
    {
        for ($i = 1; $i <= $n; $i++) {
            // 33 bytes plus the `[]` schema estimate to exactly 10 tokens, so the default reservation is 30 + T.
            yield new LlmRequest("p{$i}", '', str_repeat('x', 33), [], 'm', $maxTokens);
        }
    }

    // T: the tokens reserved for the longest schema-retry text.
    private static function retryText(): int
    {
        return TokenEstimator::forBytes(ValidatingClient::MAX_RETRY_SUFFIX_BYTES);
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

/** Answers from a script: a response or LlmException settles, any other Throwable is thrown synchronously, anything else resolves as is. */
final class ScriptedClient implements ClientInterface
{
    /** @var list<LlmRequest> */
    public array $requests = [];

    /** @param array<string, mixed> $script */
    public function __construct(private readonly array $script)
    {
    }

    public function analyze(LlmRequest $request): PromiseInterface
    {
        $this->requests[] = $request;
        $answer = $this->script[$request->payloadId] ?? null;
        if ($answer instanceof LlmException) {
            return Create::rejectionFor($answer);
        }
        if ($answer instanceof \Throwable) {
            throw $answer;
        }

        return Create::promiseFor($answer);
    }
}

/** Bills each call up to what it sends plus maxTokens, mixing instant and deferred answers, invalid first attempts and failed retries. */
final class BillingClient implements ClientInterface
{
    /** @var array<string, int> first attempt's ceiling keyed by payload id */
    public array $dispatched = [];

    public int $retries = 0;

    public int $billed = 0;

    public int $peak = 0;

    public int $maxInFlight = 0;

    private int $inFlight = 0;

    private int $calls = 0;

    public function __construct(public readonly int $budget)
    {
    }

    public function analyze(LlmRequest $request): PromiseInterface
    {
        $retry = isset($this->dispatched[$request->payloadId]);
        $ceiling = TokenEstimator::estimate($request->system.$request->user.json_encode($request->schema)) + $request->maxTokens;
        $this->dispatched[$request->payloadId] ??= $ceiling;
        $n = ++$this->calls;
        $this->retries += $retry ? 1 : 0;
        $id = (int) substr($request->payloadId, 1);
        // Every third payload is invalid first time; every ninth fails its retry.
        $answer = match (true) {
            !$retry && $id % 3 === 0 => 'invalid',
            $retry && $id % 9 === 0 => 'fail',
            default => 'ok',
        };
        // Mostly the full ceiling, so the cap is tested at its edge.
        $tokens = $n % 4 === 0 ? intdiv($ceiling, 2) : $ceiling;
        $this->inFlight++;
        $this->maxInFlight = max($this->maxInFlight, $this->inFlight);
        $settle = function () use ($request, $answer, $tokens): LlmResponse {
            $this->inFlight--;
            $this->billed += $tokens;
            $this->peak = max($this->peak, $this->billed);
            if ($answer === 'fail') {
                throw new LlmException('openai request failed (HTTP 500)', 500, true, spentTokens: $tokens);
            }
            $outcome = $answer === 'invalid' ? LlmOutcome::Invalid : LlmOutcome::Ok;

            return new LlmResponse($request->payloadId, $outcome, $outcome === LlmOutcome::Ok ? ['findings' => []] : null, $tokens, 0, 'm', $outcome === LlmOutcome::Ok ? null : 'bad json');
        };
        if ($n % 2 === 0) {
            try {
                return Create::promiseFor($settle());
            } catch (LlmException $e) {
                return Create::rejectionFor($e);
            }
        }
        $promise = null;
        $promise = new Promise(function () use (&$promise, $settle): void {
            assert($promise instanceof Promise);
            try {
                $promise->resolve($settle());
            } catch (LlmException $e) {
                $promise->reject($e);
            }
        });

        return $promise;
    }
}

/** Bills what is really sent: system, user (retry text included) and schema, at full maxTokens; the first answer carries the longest error text. */
final class SchemaBillingClient implements ClientInterface
{
    /** @var list<LlmRequest> */
    public array $requests = [];

    public function analyze(LlmRequest $request): PromiseInterface
    {
        $this->requests[] = $request;
        $input = TokenEstimator::estimate($request->system.$request->user.json_encode($request->schema));
        $first = count($this->requests) === 1;
        $outcome = $first ? LlmOutcome::Invalid : LlmOutcome::Ok;

        return Create::promiseFor(new LlmResponse($request->payloadId, $outcome, $first ? null : ['findings' => []], $input, $request->maxTokens, 'm', $first ? str_repeat("\u{1D11E}", 5000) : null));
    }
}
