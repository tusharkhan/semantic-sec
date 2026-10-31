<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Llm\Provider;

final class JsonOutput
{
    // Exactly one ```json fence around the whole answer; anything else stays as-is and must parse alone.
    private const FENCE = '/\A```json[ \t]*\R(.*?)\R?```\z/s';

    /** @return array<string, mixed>|null the decoded object, or null when the text is not exactly one JSON object */
    public static function decode(string $text): ?array
    {
        $text = trim($text);
        if (preg_match(self::FENCE, $text, $m) === 1) {
            $text = trim($m[1]);
        }

        try {
            $object = json_decode($text, false, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }
        if (!$object instanceof \stdClass) {
            return null;
        }

        /** @var array<string, mixed> */
        return json_decode($text, true, 512, JSON_THROW_ON_ERROR);
    }
}
