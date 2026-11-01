<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support\Benchmark;

use TusharKhan\SemanticSec\Llm\Http\Cassette;

/** @phpstan-import-type Usage from Report */
final class CassetteUsage
{
    /**
     * Token usage, model ids and request count from a recorded Anthropic cassette.
     *
     * @return array{usage: Usage, models: list<string>, requests: int}
     */
    public static function read(string $path): array
    {
        $usage = ['input' => 0, 'output' => 0, 'cacheRead' => 0, 'cacheWrite' => 0];
        $models = [];
        $interactions = Cassette::load($path)->interactions();
        foreach ($interactions as $interaction) {
            $body = json_decode($interaction['response']['body'], true);
            if (! is_array($body)) {
                continue;
            }
            $u = is_array($body['usage'] ?? null) ? $body['usage'] : [];
            foreach (['input' => 'input_tokens', 'output' => 'output_tokens', 'cacheRead' => 'cache_read_input_tokens', 'cacheWrite' => 'cache_creation_input_tokens'] as $key => $field) {
                $usage[$key] += is_int($u[$field] ?? null) ? $u[$field] : 0;
            }
            if (is_string($body['model'] ?? null)) {
                $models[$body['model']] = true;
            }
        }
        $models = array_keys($models);
        sort($models);

        return ['usage' => $usage, 'models' => $models, 'requests' => count($interactions)];
    }
}
