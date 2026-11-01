<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support\Benchmark;

/**
 * A competitor eval_results.json after conversion: analyze-shaped findings per app, plus how each finding was mapped.
 * @phpstan-type Trace array{app: string|null, file: string, line: int, rawCategory: string, category: string, rule: string, confidence: string, disguisedSymbol: string, symbol: string, location: string}
 */
final class CompetitorRun
{
    /**
     * @param array<string, array{findings: list<array<string, mixed>>}> $analyze per app, in the shape Scorer reads
     * @param list<Trace> $traces one per competitor finding, in their order
     * @param array{success: bool, runtime: float, findings_count: int} $meta
     */
    public function __construct(public readonly array $analyze, public readonly array $traces, public readonly array $meta)
    {
    }

    // Findings outside every benchmark app; they cannot land on a case and are listed only.
    public function unmapped(): int
    {
        return count(array_filter($this->traces, static fn (array $t): bool => $t['app'] === null));
    }

    /** @return array<string, int> rule => findings in a benchmark app it decided, in CategoryInference::rules() order, zeros left out */
    public function rules(): array
    {
        $counts = array_fill_keys(CategoryInference::rules(), 0);
        foreach (array_filter($this->traces, static fn (array $t): bool => $t['app'] !== null) as $trace) {
            $counts[$trace['rule']] = ($counts[$trace['rule']] ?? 0) + 1;
        }

        return array_filter($counts);
    }
}
