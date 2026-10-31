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
use TusharKhan\SemanticSec\Payload\Redactor;

/** Anthropic Messages API over raw HTTP, with structured outputs instead of a forced tool. */
final class AnthropicClient implements ClientInterface
{
    public const DEFAULT_BASE_URL = 'https://api.anthropic.com';

    private const VERSION = '2026-10-21';

    private const FALLBACK_BETA = 'server-side-fallback-2026-07-01';

    private const PROVIDER = 'anthropic';

    public function __construct(
        private readonly Client $http,
        #[\SensitiveParameter] private readonly string $apiKey,
        private readonly string $baseUrl = self::DEFAULT_BASE_URL,
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
        $base = rtrim($this->baseUrl, '/');
        $official = strcasecmp($base, self::DEFAULT_BASE_URL) === 0;
        $headers = ['x-api-key' => $this->apiKey, 'anthropic-version' => self::VERSION, 'content-type' => 'application/json'];
        if ($official) {
            $headers['anthropic-beta'] = self::FALLBACK_BETA;
        }
        $body = json_encode(self::body($request, $official), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR);

        return new Request('POST', $base.'/v1/messages', $headers, $body);
    }

    /** @return array<string, mixed> */
    private static function body(LlmRequest $request, bool $official): array
    {
        $output = ['format' => ['type' => 'json_schema', 'schema' => $request->schema]];
        if ($request->effort !== null) {
            $output['effort'] = $request->effort;
        }
        $body = [
            'model' => $request->model,
            'max_tokens' => $request->maxTokens,
            'system' => [['type' => 'text', 'text' => $request->system, 'cache_control' => ['type' => 'ephemeral']]],
            'messages' => [['role' => 'user', 'content' => $request->user]],
            'output_config' => $output,
        ];
        if ($official) {
            $body['fallbacks'] = 'default';
        }

        return $body;
    }

    private function toResponse(LlmRequest $request, ResponseInterface $response): LlmResponse
    {
        $status = $response->getStatusCode();
        $json = json_decode((string) $response->getBody(), true);
        $json = is_array($json) ? $json : [];
        if ($status !== 200) {
            throw $this->error($status, $json);
        }
        if (!isset($json['content']) || !is_array($json['content'])) {
            throw new LlmException(self::PROVIDER.' returned an unreadable response (HTTP 200)', 200, false);
        }

        $usage = is_array($json['usage'] ?? null) ? $json['usage'] : [];
        // Budget counts everything processed, so cache writes and reads are input tokens too.
        $input = self::int($usage, 'input_tokens') + self::int($usage, 'cache_creation_input_tokens') + self::int($usage, 'cache_read_input_tokens');
        $output = self::int($usage, 'output_tokens');
        $model = is_string($json['model'] ?? null) ? $json['model'] : $request->model;
        $make = static fn (LlmOutcome $outcome, ?array $data = null, ?string $detail = null): LlmResponse => new LlmResponse($request->payloadId, $outcome, $data, $input, $output, $model, $detail);

        $stop = $json['stop_reason'] ?? null;
        if ($stop === 'refusal') {
            $details = is_array($json['stop_details'] ?? null) ? $json['stop_details'] : [];

            return $make(LlmOutcome::Refused, null, is_string($details['category'] ?? null) ? $details['category'] : 'refusal');
        }
        if ($stop === 'max_tokens' || $stop === 'model_context_window_exceeded') {
            return $make(LlmOutcome::Truncated, null, $stop);
        }

        $text = self::firstText($json['content']);
        if ($text === null) {
            return $make(LlmOutcome::Invalid, null, 'no text block in the response');
        }
        $data = JsonOutput::decode($text);

        return $data === null ? $make(LlmOutcome::Invalid, null, 'the answer is not a single JSON object') : $make(LlmOutcome::Ok, $data);
    }

    /** @param array<mixed> $content */
    private static function firstText(array $content): ?string
    {
        foreach ($content as $block) {
            if (is_array($block) && ($block['type'] ?? null) === 'text' && is_string($block['text'] ?? null)) {
                return $block['text'];
            }
        }

        return null;
    }

    /** @param array<mixed> $json */
    private function error(int $status, array $json): LlmException
    {
        if ($status >= 300 && $status < 400) {
            return new LlmException(self::PROVIDER." answered with a redirect (HTTP {$status}); redirects are not followed", $status, false);
        }
        if ($status === 401 || $status === 403) {
            return new LlmException(self::PROVIDER." rejected the API key (HTTP {$status})", $status, false);
        }
        $error = is_array($json['error'] ?? null) ? $json['error'] : [];
        if ($status === 429 || $status >= 500 || ($error['type'] ?? null) === 'overloaded_error') {
            return new LlmException(self::PROVIDER." is unavailable (HTTP {$status})", $status, true);
        }
        $detail = is_string($error['message'] ?? null) ? $this->scrub($error['message']) : '';

        return new LlmException(self::PROVIDER." request failed (HTTP {$status})".($detail === '' ? '' : ": {$detail}"), $status, false);
    }

    // Drops the key, URLs and secret-looking tokens, and keeps one short line.
    private function scrub(string $message): string
    {
        $message = $this->apiKey === '' ? $message : str_replace($this->apiKey, '<scrubbed>', $message);
        $message = (string) preg_replace('~\b[a-z][a-z0-9+.-]*://\S+~i', '<url>', $message);
        $message = (string) preg_replace('/\s+/', ' ', (new Redactor())->redact($message));

        return mb_strimwidth(trim($message), 0, 300, '…');
    }

    /** @param array<mixed> $usage */
    private static function int(array $usage, string $key): int
    {
        return is_int($usage[$key] ?? null) ? $usage[$key] : 0;
    }
}
