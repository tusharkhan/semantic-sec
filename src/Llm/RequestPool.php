<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Llm;

use GuzzleHttp\Promise\Each;
use GuzzleHttp\Promise\PromiseInterface;
use TusharKhan\SemanticSec\Payload\TokenEstimator;

/** Runs requests with bounded concurrency under a hard token budget; never retries and never throws from run(). */
final class RequestPool
{
    /** @var list<LlmResponse> */
    private array $responses = [];

    /** @var list<array{payloadId: string, error: string, retryable: bool}> */
    private array $failures = [];

    private int $usedTokens = 0;

    private int $reservedTokens = 0;

    private bool $budgetExceeded = false;

    public function __construct(
        private readonly ClientInterface $client,
        private readonly int $concurrency,
        private readonly ?int $budgetTokens,
    ) {
        if ($concurrency < 1) {
            throw new \InvalidArgumentException("concurrency must be at least 1, got {$concurrency}");
        }
    }

    /** @param iterable<LlmRequest> $requests responses come back in completion order */
    public function run(iterable $requests): PoolResult
    {
        $this->responses = [];
        $this->failures = [];
        $this->usedTokens = 0;
        $this->reservedTokens = 0;
        $this->budgetExceeded = false;

        Each::ofLimit($this->dispatch($requests), $this->concurrency)->wait();

        if ($this->budgetTokens !== null && $this->usedTokens > $this->budgetTokens) {
            $this->budgetExceeded = true;
        }

        return new PoolResult($this->responses, $this->failures, $this->usedTokens, $this->budgetExceeded);
    }

    // Lazy, so each budget check sees the tokens and reservations of every request so far.
    /**
     * @param iterable<LlmRequest> $requests
     * @return \Generator<int, PromiseInterface>
     */
    private function dispatch(iterable $requests): \Generator
    {
        foreach ($requests as $request) {
            $reservation = $this->budgetTokens === null ? 0 : self::reservation($request);
            if ($this->budgetTokens !== null && $this->usedTokens + $this->reservedTokens + $reservation > $this->budgetTokens) {
                $this->budgetExceeded = true;

                return;
            }
            $this->reservedTokens += $reservation;
            try {
                $promise = $this->client->analyze($request);
            } catch (\Throwable $e) {
                $this->reservedTokens -= $reservation;
                $this->fail($request->payloadId, $e);

                continue;
            }
            yield $promise->then(
                function (mixed $response) use ($request, $reservation): void {
                    $this->reservedTokens -= $reservation;
                    if (!$response instanceof LlmResponse) {
                        $this->failures[] = ['payloadId' => $request->payloadId, 'error' => 'client resolved without an LlmResponse', 'retryable' => false];

                        return;
                    }
                    $this->responses[] = $response;
                    $this->usedTokens += $response->inputTokens + $response->outputTokens;
                },
                function (mixed $reason) use ($request, $reservation): void {
                    $this->reservedTokens -= $reservation;
                    $this->usedTokens += $reason instanceof LlmException ? $reason->spentTokens : 0;
                    $this->fail($request->payloadId, $reason);
                },
            );
        }
    }

    // Worst case for one slot: two calls (the schema retry), each at full input and maxTokens output.
    private static function reservation(LlmRequest $request): int
    {
        return 2 * (TokenEstimator::estimate($request->system.$request->user) + $request->maxTokens);
    }

    // Only LlmException messages are known secret-safe, so anything else is named by class alone.
    private function fail(string $payloadId, mixed $reason): void
    {
        $this->failures[] = match (true) {
            $reason instanceof LlmException => ['payloadId' => $payloadId, 'error' => $reason->getMessage(), 'retryable' => $reason->retryable],
            $reason instanceof \Throwable => ['payloadId' => $payloadId, 'error' => 'unexpected '.(str_contains($reason::class, '@anonymous') ? 'anonymous class' : $reason::class), 'retryable' => false],
            default => ['payloadId' => $payloadId, 'error' => 'unknown failure', 'retryable' => false],
        };
    }
}
