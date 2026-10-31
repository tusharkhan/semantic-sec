<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Llm;

use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;

/** Test double that answers from a fixed map keyed by payload id. */
final class FakeClient implements ClientInterface
{
    /** @var list<LlmRequest> */
    public array $requests = [];

    /** @param array<string, LlmResponse|LlmException> $byPayloadId */
    public function __construct(private readonly array $byPayloadId)
    {
    }

    public function analyze(LlmRequest $request): PromiseInterface
    {
        $this->requests[] = $request;
        $answer = $this->byPayloadId[$request->payloadId]
            ?? throw new \LogicException("FakeClient has no response for {$request->payloadId}");

        return $answer instanceof LlmException ? Create::rejectionFor($answer) : Create::promiseFor($answer);
    }
}
