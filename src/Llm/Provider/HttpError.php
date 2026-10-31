<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Llm\Provider;

use TusharKhan\SemanticSec\Llm\LlmException;
use TusharKhan\SemanticSec\Payload\Redactor;

/** Maps a non-200 provider answer to a secret-safe LlmException. */
final class HttpError
{
    public static function from(string $provider, int $status, ?string $apiMessage, #[\SensitiveParameter] string $apiKey, bool $overloaded = false): LlmException
    {
        if ($status >= 300 && $status < 400) {
            return new LlmException("{$provider} answered with a redirect (HTTP {$status}); redirects are not followed", $status, false);
        }
        if ($status === 401 || $status === 403) {
            return new LlmException("{$provider} rejected the API key (HTTP {$status})", $status, false);
        }
        if ($status === 429 || $status >= 500 || $overloaded) {
            return new LlmException("{$provider} is unavailable (HTTP {$status})", $status, true);
        }
        $detail = $apiMessage === null ? '' : self::scrub($apiMessage, $apiKey);

        return new LlmException("{$provider} request failed (HTTP {$status})".($detail === '' ? '' : ": {$detail}"), $status, false);
    }

    // Drops the key, URLs and secret-looking tokens, and keeps one short line.
    public static function scrub(string $message, #[\SensitiveParameter] string $apiKey): string
    {
        $message = $apiKey === '' ? $message : str_replace($apiKey, '<scrubbed>', $message);
        $message = (string) preg_replace('~\b[a-z][a-z0-9+.-]*://\S+~i', '<url>', $message);
        $message = (string) preg_replace('/\s+/', ' ', (new Redactor())->redact($message));

        return mb_strimwidth(trim($message), 0, 300, '…');
    }
}
