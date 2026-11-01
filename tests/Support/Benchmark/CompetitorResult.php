<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support\Benchmark;

/** The competitor's score from the same Scorer, its converted run, and its run metadata (sha, model, pr, limits, usage, cost, turns, capped). */
final class CompetitorResult
{
    /** @param array<string, mixed> $meta */
    public function __construct(public readonly Score $score, public readonly CompetitorRun $run, public readonly array $meta)
    {
    }

    /**
     * run-meta.json and the claude-call-*.json outputs that tools/competitor/run.sh leaves beside eval_results.json.
     *
     * @return array<string, mixed>
     */
    public static function readMeta(string $dir): array
    {
        $meta = self::json($dir.'/run-meta.json') ?? [];
        $calls = glob($dir.'/claude-call-*.json') ?: [];
        sort($calls);
        if ($calls === []) {
            return $meta;
        }
        $usage = ['input' => 0, 'output' => 0, 'cacheRead' => 0, 'cacheWrite' => 0];
        $cost = 0.0;
        $turns = 0;
        $capped = false;
        foreach ($calls as $path) {
            $call = self::json($path);
            if ($call === null) {
                $capped = true;
                continue;
            }
            $u = is_array($call['usage'] ?? null) ? $call['usage'] : [];
            foreach (['input' => 'input_tokens', 'output' => 'output_tokens', 'cacheRead' => 'cache_read_input_tokens', 'cacheWrite' => 'cache_creation_input_tokens'] as $ours => $theirs) {
                $usage[$ours] += is_int($u[$theirs] ?? null) ? $u[$theirs] : 0;
            }
            $cost += is_numeric($call['total_cost_usd'] ?? null) ? (float) $call['total_cost_usd'] : 0.0;
            $turns += is_int($call['num_turns'] ?? null) ? $call['num_turns'] : 0;
            $capped = $capped || ($call['subtype'] ?? 'success') !== 'success' || ($call['is_error'] ?? false) === true;
        }

        return [...$meta, 'usage' => $usage, 'cost' => $cost, 'turns' => $turns, 'calls' => count($calls), 'capped' => $capped];
    }

    /** @return array<mixed>|null */
    private static function json(string $path): ?array
    {
        $text = is_file($path) ? file_get_contents($path) : false;
        $data = $text === false ? null : json_decode($text, true);

        return is_array($data) ? $data : null;
    }
}
