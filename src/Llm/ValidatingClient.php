<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Llm;

use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;

/** Adds SPEC §10's one schema retry to any client: an invalid answer is re-asked once with the errors appended. */
final class ValidatingClient implements ClientInterface
{
    public const MAX_ERRORS = 1000;

    public function __construct(private readonly ClientInterface $inner)
    {
    }

    public function analyze(LlmRequest $request): PromiseInterface
    {
        return $this->send($request)->then(function (mixed $first) use ($request): mixed {
            $errors = $first instanceof LlmResponse ? self::problems($first) : null;
            if ($errors === null) {
                return $first;
            }
            $retry = $request->withUserSuffix("\n\nYour previous answer was invalid: {$errors}. Answer again with valid JSON matching the schema.");

            return $this->send($retry)->then(
                static fn (mixed $second): mixed => $second instanceof LlmResponse ? self::settle($first, $second) : $second,
                static fn (mixed $reason): never => throw self::spent($reason, $first),
            );
        });
    }

    // Wraps a synchronous throw from the inner client into a rejection.
    private function send(LlmRequest $request): PromiseInterface
    {
        try {
            return $this->inner->analyze($request);
        } catch (\Throwable $e) {
            return Create::rejectionFor($e);
        }
    }

    // The retry's rejection, carrying the first attempt's tokens too, so the pool still counts them.
    private static function spent(mixed $reason, LlmResponse $first): \Throwable
    {
        if (!$reason instanceof LlmException) {
            return $reason instanceof \Throwable ? $reason : new LlmException('schema retry failed', null, false);
        }

        return new LlmException($reason->getMessage(), $reason->status, $reason->retryable, $reason, $reason->spentTokens + $first->inputTokens + $first->outputTokens);
    }

    // Null when the response stands as is: a valid Ok, a refusal or a truncation.
    private static function problems(LlmResponse $r): ?string
    {
        if ($r->outcome === LlmOutcome::Invalid) {
            return self::cap([$r->detail ?? 'the answer is not valid JSON']);
        }
        if ($r->outcome !== LlmOutcome::Ok || $r->data === null) {
            return null;
        }
        $errors = ResponseValidator::errors($r->data);

        return $errors === [] ? null : self::cap($errors);
    }

    private static function settle(LlmResponse $first, LlmResponse $second): LlmResponse
    {
        $errors = self::problems($second);
        [$outcome, $data, $detail] = $errors === null ? [$second->outcome, $second->data, $second->detail] : [LlmOutcome::Invalid, null, $errors];

        return new LlmResponse($second->payloadId, $outcome, $data, $first->inputTokens + $second->inputTokens, $first->outputTokens + $second->outputTokens, $second->model, $detail);
    }

    /** @param list<string> $errors */
    private static function cap(array $errors): string
    {
        // No angle brackets, so the model's own key names cannot close the <untrusted_code> fence.
        $text = str_replace(['<', '>'], '', (string) preg_replace('/[\x00-\x1F\x7F]+/', ' ', implode('; ', $errors)));

        return mb_strlen($text) > self::MAX_ERRORS ? mb_substr($text, 0, self::MAX_ERRORS - 1).'…' : $text;
    }
}
