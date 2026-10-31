<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support;

use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use TusharKhan\SemanticSec\Llm\ClientInterface;
use TusharKhan\SemanticSec\Llm\LlmException;
use TusharKhan\SemanticSec\Llm\LlmRequest;
use TusharKhan\SemanticSec\Llm\LlmResponse;

/** Test double: answers each call with the next scripted item and throws synchronously when the script runs out. */
final class ScriptedClient implements ClientInterface
{
    /** @var list<LlmRequest> */
    public array $requests = [];

    /** @param list<LlmResponse|LlmException> $script */
    public function __construct(private array $script)
    {
    }

    public function analyze(LlmRequest $request): PromiseInterface
    {
        $this->requests[] = $request;
        $answer = array_shift($this->script) ?? throw new \LogicException('script exhausted');

        return $answer instanceof LlmException ? Create::rejectionFor($answer) : Create::promiseFor($answer);
    }
}
