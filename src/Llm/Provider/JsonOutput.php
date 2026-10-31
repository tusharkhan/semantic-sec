<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Llm\Provider;

final class JsonOutput
{
    // Exactly one fence, unlabelled or labelled json in any case, around the whole answer.
    private const FENCE = '/\A```(?i:json)?[ \t]*\R(.*?)\R?```\z/s';

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
