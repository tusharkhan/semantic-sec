<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support;

use TusharKhan\SemanticSec\Console\AnalysisPipeline;
use TusharKhan\SemanticSec\Engine\AnalysisResult;
use TusharKhan\SemanticSec\Engine\Baseline;
use TusharKhan\SemanticSec\Engine\Engine;
use TusharKhan\SemanticSec\Engine\Fingerprinter;
use TusharKhan\SemanticSec\Engine\ResultCache;
use TusharKhan\SemanticSec\Llm\GroundingChecker;
use TusharKhan\SemanticSec\Llm\Http\Cassette;
use TusharKhan\SemanticSec\Llm\Http\CassetteHandler;
use TusharKhan\SemanticSec\Llm\Http\HttpClientFactory;
use TusharKhan\SemanticSec\Llm\Http\RetryMiddleware;
use TusharKhan\SemanticSec\Llm\Provider\AnthropicClient;
use TusharKhan\SemanticSec\Llm\ValidatingClient;

/** Replays the pinned live laravel11 benchmark cassette against a temp copy of the app; no network. */
final class BenchmarkReplay
{
    // The live run used --level low --min-confidence low; neither changes a request body.
    public static function run(string $root): AnalysisResult
    {
        $cassette = LiveBenchmark::recordedCassette() ?? throw new \LogicException('the live benchmark cassette is not committed');
        $run = (new AnalysisPipeline())->run($root, null, null, false, null, ['level' => 'low', 'min_confidence' => 'low']);
        $handler = new CassetteHandler(Cassette::load($cassette), 'replay', match: 'body');
        $client = new ValidatingClient(new AnthropicClient(HttpClientFactory::create($handler, [RetryMiddleware::create()]), 'replay-key'));
        $project = $run->project;
        $engine = new Engine(
            $client,
            ResultCache::inProject($root, $project->config, $run->system, true),
            new Fingerprinter($project->parsed, $project->symbols),
            new GroundingChecker($project->symbols),
            $project->parsed,
            $project->config,
            Baseline::empty(),
        );

        NetworkTrap::install();
        try {
            $result = $engine->run($run->payloads(), count($run->results));
        } finally {
            $calls = NetworkTrap::uninstall();
        }
        if ($calls !== []) {
            throw new \LogicException('the replay touched the network');
        }
        $handler->assertExhausted();

        return $result;
    }
}
