<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Console;

use TusharKhan\SemanticSec\Candidates\Candidate;
use TusharKhan\SemanticSec\Config\Config;
use TusharKhan\SemanticSec\Framework\Laravel\LaravelContext;
use TusharKhan\SemanticSec\Llm\SecurityPrompt;
use TusharKhan\SemanticSec\Payload\Payload;

/** Map, then candidates (SPEC §7), then payloads (SPEC §9) and the system prompt they go with; no LLM. */
final class AnalysisPipeline
{
    /**
     * @param  list<string>|null  $paths  project-relative report scope; null keeps the config's `paths`
     * @return array{0: list<array{candidate: Candidate, payloads: list<Payload>}>, 1: list<string>, 2: string} results, warnings, system prompt
     */
    public function run(string $root, ?string $configPath, ?string $framework, bool $deep, ?array $paths): array
    {
        $project = (new MapBuilder())->project($root, $configPath, $framework);
        $config = $paths === null ? $project->config : self::withPaths($project->config, $paths);
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

        return [$results, $warnings, SecurityPrompt::system($context->promptContext(), $config->rulesets)];
    }

    /** @param list<string> $paths */
    private static function withPaths(Config $c, array $paths): Config
    {
        return new Config(
            $c->projectRoot,
            $c->provider,
            $c->model,
            $c->apiKeyEnv,
            $c->baseUrl,
            $c->concurrency,
            $c->budgetTokens,
            $c->maxPayloadTokens,
            $c->maxDepth,
            $c->level,
            $c->minConfidence,
            $paths,
            $c->exclude,
            $c->laravelRouteFiles,
            $c->sensitiveFields,
            $c->authHelpers,
            $c->rulesets,
            $c->authMiddleware,
            $c->effort,
            $c->authorizationMiddleware,
        );
    }
}
