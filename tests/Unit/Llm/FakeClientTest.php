<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Llm;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Llm\FakeClient;
use TusharKhan\SemanticSec\Llm\LlmException;
use TusharKhan\SemanticSec\Llm\LlmOutcome;
use TusharKhan\SemanticSec\Llm\LlmRequest;
use TusharKhan\SemanticSec\Llm\LlmResponse;

final class FakeClientTest extends TestCase
{
    public function testResolvesConfiguredResponseAndRecordsRequest(): void
    {
        $response = new LlmResponse('001-get-x-1', LlmOutcome::Ok, ['findings' => []], 120, 30, 'fake-model');
        $fake = new FakeClient(['001-get-x-1' => $response]);

        $result = $fake->analyze($this->request('001-get-x-1'))->wait();

        self::assertSame($response, $result);
        self::assertSame(LlmOutcome::Ok, $result->outcome);
        self::assertCount(1, $fake->requests);
        self::assertSame('001-get-x-1', $fake->requests[0]->payloadId);
    }

    public function testRejectsWithConfiguredException(): void
    {
        $fake = new FakeClient(['002-post-y-1' => new LlmException('anthropic rejected the API key (HTTP 401)', 401, false)]);

        try {
            $fake->analyze($this->request('002-post-y-1'))->wait();
            self::fail('expected the promise to reject');
        } catch (LlmException $e) {
            self::assertSame(401, $e->status);
            self::assertFalse($e->retryable);
        }
        self::assertCount(1, $fake->requests);
    }

    public function testUnknownPayloadIdIsALogicError(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('no response for 003-x');

        (new FakeClient([]))->analyze($this->request('003-x'));
    }

    public function testWithUserSuffixReturnsCopy(): void
    {
        $request = $this->request('001-get-x-1');
        $retry = $request->withUserSuffix("\n\nagain");

        self::assertSame('user prompt', $request->user);
        self::assertSame("user prompt\n\nagain", $retry->user);
        self::assertSame($request->schema, $retry->schema);
        self::assertSame(16000, $retry->maxTokens);
        self::assertNull($retry->effort);
    }

    private function request(string $payloadId): LlmRequest
    {
        return new LlmRequest($payloadId, 'system prompt', 'user prompt', ['type' => 'object'], 'fake-model');
    }
}
