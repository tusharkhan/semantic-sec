<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Llm\Http;

use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Middleware;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/** The only retry layer: 429, any 5xx and connection errors, at most 4 attempts with exponential backoff. */
final class RetryMiddleware
{
    public const MAX_ATTEMPTS = 4;

    public const MAX_DELAY_MS = 60_000;

    private const HTTP_DATE_FORMATS = ['D, d M Y H:i:s \G\M\T', 'l, d-M-y H:i:s \G\M\T', 'D M j H:i:s Y'];

    /**
     * @param (callable(int): void)|null $sleep waits the given ms itself; null hands the delay to the Guzzle handler (non-blocking under curl multi)
     * @param (callable(): int)|null $now current Unix time, for HTTP-date Retry-After
     */
    public static function create(?callable $sleep = null, ?callable $now = null): callable
    {
        $now ??= time(...);

        return Middleware::retry(
            static fn (int $retries, RequestInterface $request, ?ResponseInterface $response = null, mixed $exception = null): bool => $retries < self::MAX_ATTEMPTS - 1 && self::retryable($response, $exception),
            static function (int $retries, ?ResponseInterface $response = null) use ($sleep, $now): int {
                $ms = self::delay($retries, $response, $now());
                if ($sleep === null) {
                    return $ms;
                }
                $sleep($ms);

                return 0;
            },
        );
    }

    // Backoff for retry n (1-based), raised to Retry-After when that is longer, capped at 60 s.
    public static function delay(int $retry, ?ResponseInterface $response, int $now): int
    {
        $backoff = 1000 * 2 ** max(0, $retry - 1);
        $after = $response === null ? null : self::retryAfter($response->getHeaderLine('Retry-After'), $now);

        return min(self::MAX_DELAY_MS, max($backoff, $after ?? 0));
    }

    private static function retryable(?ResponseInterface $response, mixed $exception): bool
    {
        if ($exception instanceof ConnectException) {
            return true;
        }
        if ($response === null && $exception instanceof RequestException) {
            $response = $exception->getResponse();
        }
        if ($response === null) {
            return false;
        }
        $status = $response->getStatusCode();

        return $status === 429 || $status >= 500;
    }

    // Retry-After as delta-seconds or an HTTP-date; null when absent, unreadable or already past.
    private static function retryAfter(string $value, int $now): ?int
    {
        $value = trim($value);
        if ($value === '') {
            return null;
        }
        if (ctype_digit($value)) {
            return strlen($value) > 6 ? self::MAX_DELAY_MS : (int) $value * 1000;
        }
        foreach (self::HTTP_DATE_FORMATS as $format) {
            $date = \DateTimeImmutable::createFromFormat('!'.$format, $value, new \DateTimeZone('UTC'));
            if ($date !== false) {
                $ms = ($date->getTimestamp() - $now) * 1000;

                return $ms > 0 ? $ms : null;
            }
        }

        return null;
    }
}
