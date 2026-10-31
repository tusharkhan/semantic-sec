<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Console;

use TusharKhan\SemanticSec\Framework\Laravel\LaravelContext;
use TusharKhan\SemanticSec\Llm\SecurityPrompt;

/** Map, then candidates (SPEC §7), then payloads (SPEC §9) and the system prompt they go with; no LLM. */
final class AnalysisPipeline
{
    private readonly MapBuilder $mapper;

    public function __construct(?MapBuilder $mapper = null)
    {
        $this->mapper = $mapper ?? new MapBuilder();
    }

    /**
     * @param  list<string>|null  $paths  project-relative report scope; null keeps the config's `paths`
     * @param  array{level?: mixed, min_confidence?: mixed, provider?: mixed, model?: mixed, concurrency?: mixed, budget_tokens?: mixed}  $overrides  CLI options, see Config::with()
     *
     * @throws \TusharKhan\SemanticSec\Config\ConfigException
     * @throws \TusharKhan\SemanticSec\Framework\FrameworkNotDetected
     */
    public function run(string $root, ?string $configPath, ?string $framework, bool $deep, ?array $paths, array $overrides = []): PipelineResult
    {
        $mapped = $this->mapper->project($root, $configPath, $framework);
        $config = $mapped->config->with($paths === null ? $overrides : [...$overrides, 'paths' => $paths]);
        $project = new MappedProject($config, $mapped->framework, $mapped->parsed, $mapped->symbols, $mapped->map, $mapped->warnings);
        $context = new LaravelContext();
        $warnings = $project->warnings;

        [$candidates, $w] = $context->candidateSelector($project->parsed, $project->symbols, $config, $project->framework)->select($project->map, $deep);
        array_push($warnings, ...$w);

        $builder = $context->payloadBuilder($project->parsed, $project->symbols, $config, $project->framework);
        $results = [];
        foreach ($candidates as $i => $candidate) {
            [$payloads, $w] = $builder->build($candidate, $i + 1);
            array_push($warnings, ...$w);
            $results[] = ['candidate' => $candidate, 'payloads' => $payloads];
        }

        return new PipelineResult($project, $results, $warnings, SecurityPrompt::system($context->promptContext(), $config->rulesets));
    }
}
