<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Llm\Provider;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Request;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use TusharKhan\SemanticSec\Llm\ClientInterface;
use TusharKhan\SemanticSec\Llm\LlmException;
use TusharKhan\SemanticSec\Llm\LlmOutcome;
use TusharKhan\SemanticSec\Llm\LlmRequest;
use TusharKhan\SemanticSec\Llm\LlmResponse;

/** Ollama /api/chat over raw HTTP with a JSON-schema `format`; local, so no API key. */
final class OllamaClient implements ClientInterface
{
    public const DEFAULT_BASE_URL = 'http://localhost:11434';

    private const PROVIDER = 'ollama';

    public function __construct(
        private readonly Client $http,
        private readonly string $baseUrl = self::DEFAULT_BASE_URL,
        private readonly ?float $temperature = 0.0,
    ) {
    }

    public function analyze(LlmRequest $request): PromiseInterface
    {
        try {
            $http = $this->build($request);
        } catch (\Throwable) {
            // URI and JSON errors echo the base URL (userinfo included) or payload, so none of it is kept.
            return Create::rejectionFor(new LlmException(self::PROVIDER.' request could not be built', null, false));
        }

        return $this->http
            ->sendAsync($http, ['http_errors' => false])
            ->then(
                fn (ResponseInterface $response): LlmResponse => $this->toResponse($request, $response),
                static function (mixed $reason): never {
                    if ($reason instanceof LlmException) {
                        throw $reason;
                    }
                    // Guzzle messages carry the URI, so neither the message nor the exception is kept.
                    if ($reason instanceof ConnectException) {
                        throw new LlmException(self::PROVIDER.' is not reachable', null, true);
                    }

                    throw new LlmException(self::PROVIDER.' request failed: transport error', null, true);
                },
            );
    }

    private function build(LlmRequest $request): RequestInterface
    {
        $body = [
            'model' => $request->model,
            'messages' => [['role' => 'system', 'content' => $request->system], ['role' => 'user', 'content' => $request->user]],
            'stream' => false,
            'format' => $request->schema,
        ];
        if ($this->temperature !== null) {
            $body['options'] = ['temperature' => $this->temperature];
        }
        $json = json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR);

        return new Request('POST', rtrim($this->baseUrl, '/').'/api/chat', ['Content-Type' => 'application/json'], $json);
    }

    private function toResponse(LlmRequest $request, ResponseInterface $response): LlmResponse
    {
        $status = $response->getStatusCode();
        $json = json_decode((string) $response->getBody(), true);
        $json = is_array($json) ? $json : [];

        if ($status !== 200) {
            $error = is_string($json['error'] ?? null) ? $json['error'] : null;
            if ($status === 404 && $error !== null && stripos($error, 'not found') !== false) {
                // Only the configured model name is echoed, never the server's text.
                throw new LlmException(self::PROVIDER." model {$request->model} not found; pull it first", 404, false);
            }

            throw HttpError::from(self::PROVIDER, $status, $error, '');
        }

        $model = is_string($json['model'] ?? null) ? $json['model'] : $request->model;
        $make = static fn (LlmOutcome $outcome, ?array $data = null, ?string $detail = null): LlmResponse => new LlmResponse($request->payloadId, $outcome, $data, self::int($json, 'prompt_eval_count'), self::int($json, 'eval_count'), $model, $detail);

        if (($json['done_reason'] ?? null) === 'length') {
            return $make(LlmOutcome::Truncated, null, 'length');
        }
        $message = is_array($json['message'] ?? null) ? $json['message'] : [];
        $content = $message['content'] ?? null;
        if (!is_string($content)) {
            return $make(LlmOutcome::Invalid, null, 'no message content');
        }
        $data = JsonOutput::decode($content);

        return $data === null ? $make(LlmOutcome::Invalid, null, 'the answer is not a single JSON object') : $make(LlmOutcome::Ok, $data);
    }

    /** @param array<mixed> $json */
    private static function int(array $json, string $key): int
    {
        return is_int($json[$key] ?? null) ? $json[$key] : 0;
    }
}
