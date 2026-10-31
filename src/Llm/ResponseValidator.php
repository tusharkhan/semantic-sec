<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Llm;

use Opis\JsonSchema\Errors\ErrorFormatter;
use Opis\JsonSchema\Errors\ValidationError;
use Opis\JsonSchema\Validator;

/** Checks a decoded answer against FindingSchema plus the bounds the strict schema cannot carry (SPEC §10). */
final class ResponseValidator
{
    public const MAX_TITLE = 120;

    // One error line, so a huge key or value from the model is never echoed whole.
    public const MAX_ERROR = 200;

    private const MAX_SCHEMA_ERRORS = 10;

    /**
     * @param  array<mixed>  $data  the decoded answer
     * @return list<string> one "<json pointer>: <message>" per problem; empty when valid
     */
    public static function errors(array $data): array
    {
        $errors = self::schemaErrors($data);
        foreach (is_array($data['findings'] ?? null) ? $data['findings'] : [] as $i => $finding) {
            if (!is_array($finding)) {
                continue;
            }
            if (is_string($finding['title'] ?? null) && mb_strlen($finding['title']) > self::MAX_TITLE) {
                $errors[] = "/findings/{$i}/title: must be ".self::MAX_TITLE.' characters or fewer';
            }
            if (is_int($finding['line'] ?? null) && $finding['line'] < 1) {
                $errors[] = "/findings/{$i}/line: must be 1 or more";
            }
            foreach (is_array($finding['path'] ?? null) ? $finding['path'] : [] as $j => $step) {
                if (is_array($step) && is_int($step['line'] ?? null) && $step['line'] < 1) {
                    $errors[] = "/findings/{$i}/path/{$j}/line: must be 1 or more";
                }
            }
        }

        return array_values(array_unique(array_map(self::shorten(...), $errors)));
    }

    // Opis needs objects, so the top level is cast; an empty nested object decodes to [] and is checked as an array.
    /**
     * @param  array<mixed>  $data
     * @return list<string>
     */
    private static function schemaErrors(array $data): array
    {
        $json = json_encode((object) $data, JSON_PRESERVE_ZERO_FRACTION | JSON_INVALID_UTF8_SUBSTITUTE);
        $schema = json_encode(FindingSchema::schema());
        if ($json === false || $schema === false) {
            return ['/: the answer could not be re-encoded as JSON'];
        }
        $validator = (new Validator())->setStopAtFirstError(false)->setMaxErrors(self::MAX_SCHEMA_ERRORS);
        $error = $validator->validate(json_decode($json, false), json_decode($schema, false))->error();
        if ($error === null) {
            return [];
        }

        $errors = [];
        foreach ((new ErrorFormatter())->format($error, true, self::message(...)) as $pointer => $messages) {
            foreach ((array) $messages as $message) {
                if (is_string($message)) {
                    $errors[] = ($pointer === '' ? '/' : $pointer).': '.$message;
                }
            }
        }

        return $errors;
    }

    // Opis also lists declared properties as "additional" once one of them fails; keep only the undeclared ones.
    private static function message(ValidationError $error, ?string $message = null): ?string
    {
        if ($error->keyword() !== 'additionalProperties') {
            return (new ErrorFormatter())->formatErrorMessage($error, $message);
        }
        $node = $error->schema()->info()->data();
        $declared = is_object($node) && isset($node->properties) ? array_keys((array) $node->properties) : [];
        $listed = $error->args()['properties'] ?? [];
        $extra = array_values(array_diff(is_array($listed) ? array_map('strval', $listed) : [], $declared));

        return $extra === [] ? null : 'Additional object properties are not allowed: '.implode(', ', $extra);
    }

    private static function shorten(string $error): string
    {
        $error = (string) preg_replace('/[\x00-\x1F\x7F]+/', ' ', $error);

        return mb_strlen($error) > self::MAX_ERROR ? mb_substr($error, 0, self::MAX_ERROR - 1).'…' : $error;
    }
}
