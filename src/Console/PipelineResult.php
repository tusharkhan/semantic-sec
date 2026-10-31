<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Console;

use TusharKhan\SemanticSec\Candidates\Candidate;
use TusharKhan\SemanticSec\Payload\Payload;

/** What AnalysisPipeline produced, with the one parse of the project that the engine reuses. */
final readonly class PipelineResult
{
    /**
     * @param  MappedProject  $project  its config carries the run's overrides and report paths
     * @param  list<array{candidate: Candidate, payloads: list<Payload>}>  $results
     * @param  list<string>  $warnings
     */
    public function __construct(
        public MappedProject $project,
        public array $results,
        public array $warnings,
        public string $system,
    ) {
    }

    /** @return list<Payload> every payload, in candidate order */
    public function payloads(): array
    {
        $out = [];
        foreach ($this->results as $r) {
            array_push($out, ...$r['payloads']);
        }

        return $out;
    }
}
