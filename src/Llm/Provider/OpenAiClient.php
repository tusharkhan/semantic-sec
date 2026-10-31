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
use TusharKhan\SemanticSec\Llm\FindingSchema;
use TusharKhan\SemanticSec\Llm\LlmException;
use TusharKhan\SemanticSec\Llm\LlmOutcome;
use TusharKhan\SemanticSec\Llm\LlmRequest;
use TusharKhan\SemanticSec\Llm\LlmResponse;

/** OpenAI Chat Completions over raw HTTP with strict json_schema output; Groq uses it through base_url. */
final class OpenAiClient implements ClientInterface
{
    public const DEFAULT_BASE_URL = 'https://api.openai.com/v1';

    private const PROVIDER = 'openai';

    private const GROQ_SCHEMA_MISMATCH = 'Generated JSON does not match the expected schema';

    public function __construct(
        private readonly Client $http,
        #[\SensitiveParameter] private readonly string $apiKey,
        private readonly string $baseUrl = self::DEFAULT_BASE_URL,
        private readonly ?float $temperature = null,
        private readonly ?int $seed = null,
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
                    $kind = $reason instanceof ConnectException ? 'connection error' : 'transport error';

                    throw new LlmException(self::PROVIDER." request failed: {$kind}", null, true);
                },
            );
    }

    private function build(LlmRequest $request): RequestInterface
    {
        $headers = ['Authorization' => 'Bearer '.$this->apiKey, 'Content-Type' => 'application/json'];
        $body = json_encode($this->body($request), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR);

        return new Request('POST', rtrim($this->baseUrl, '/').'/chat/completions', $headers, $body);
    }

    /** @return array<string, mixed> */
    private function body(LlmRequest $request): array
    {
        $body = [
            'model' => $request->model,
            'messages' => [['role' => 'system', 'content' => $request->system], ['role' => 'user', 'content' => $request->user]],
            'response_format' => ['type' => 'json_schema', 'json_schema' => ['name' => FindingSchema::NAME, 'strict' => true, 'schema' => $request->schema]],
            'max_completion_tokens' => $request->maxTokens,
        ];
        if ($this->temperature !== null) {
            $body['temperature'] = $this->temperature;
        }
        if ($this->seed !== null) {
            $body['seed'] = $this->seed;
        }

        return $body;
    }

    private function toResponse(LlmRequest $request, ResponseInterface $response): LlmResponse
    {
        $status = $response->getStatusCode();
        $raw = (string) $response->getBody();
        $json = json_decode($raw, true);
        $json = is_array($json) ? $json : [];
        $usage = is_array($json['usage'] ?? null) ? $json['usage'] : [];
        $model = is_string($json['model'] ?? null) ? $json['model'] : $request->model;
        $make = static fn (LlmOutcome $outcome, ?array $data = null, ?string $detail = null): LlmResponse => new LlmResponse($request->payloadId, $outcome, $data, self::int($usage, 'prompt_tokens'), self::int($usage, 'completion_tokens'), $model, $detail);

        $error = is_array($json['error'] ?? null) ? $json['error'] : [];
        if ($status === 400 && (($error['code'] ?? null) === 'json_validate_failed' || str_contains($raw, self::GROQ_SCHEMA_MISMATCH))) {
            // Groq's best-effort decoding failed; Invalid lets the schema retry run.
            return $make(LlmOutcome::Invalid, null, 'generated JSON does not match the schema (HTTP 400)');
        }
        if ($status !== 200) {
            throw HttpError::from(self::PROVIDER, $status, is_string($error['message'] ?? null) ? $error['message'] : null, $this->apiKey);
        }
        $choice = is_array($json['choices'][0] ?? null) ? $json['choices'][0] : null;
        if ($choice === null) {
            throw new LlmException(self::PROVIDER.' returned an unreadable response (HTTP 200)', 200, false);
        }
        $message = is_array($choice['message'] ?? null) ? $choice['message'] : [];
        $finish = $choice['finish_reason'] ?? null;

        $refusal = $message['refusal'] ?? null;
        if (is_string($refusal) && trim($refusal) !== '') {
            return $make(LlmOutcome::Refused, null, HttpError::scrub($refusal, $this->apiKey));
        }
        if ($finish === 'content_filter') {
            return $make(LlmOutcome::Refused, null, 'content_filter');
        }
        if ($finish === 'length') {
            return $make(LlmOutcome::Truncated, null, 'length');
        }

        $content = $message['content'] ?? null;
        if (!is_string($content)) {
            return $make(LlmOutcome::Invalid, null, 'no message content (finish_reason '.(is_string($finish) ? $finish : '-').')');
        }
        $data = JsonOutput::decode($content);

        return $data === null ? $make(LlmOutcome::Invalid, null, 'the answer is not a single JSON object') : $make(LlmOutcome::Ok, $data);
    }

    /** @param array<mixed> $usage */
    private static function int(array $usage, string $key): int
    {
        return is_int($usage[$key] ?? null) ? $usage[$key] : 0;
    }
}
