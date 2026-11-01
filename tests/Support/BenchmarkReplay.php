<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support;

use PHPUnit\Framework\Assert;
use TusharKhan\SemanticSec\Console\AnalysisPipeline;
use TusharKhan\SemanticSec\Engine\AnalysisResult;
use TusharKhan\SemanticSec\Engine\Baseline;
use TusharKhan\SemanticSec\Engine\Engine;
use TusharKhan\SemanticSec\Engine\Fingerprinter;
use TusharKhan\SemanticSec\Engine\ResultCache;
use TusharKhan\SemanticSec\Framework\Laravel\LaravelContext;
use TusharKhan\SemanticSec\Llm\GroundingChecker;
use TusharKhan\SemanticSec\Llm\Http\Cassette;
use TusharKhan\SemanticSec\Llm\Http\CassetteHandler;
use TusharKhan\SemanticSec\Llm\Http\HttpClientFactory;
use TusharKhan\SemanticSec\Llm\Http\RetryMiddleware;
use TusharKhan\SemanticSec\Llm\Provider\AnthropicClient;
use TusharKhan\SemanticSec\Llm\SecurityPrompt;
use TusharKhan\SemanticSec\Llm\ValidatingClient;

/** Replays bin/benchmark's laravel11-app recording against a temp copy of the app; no network. */
final class BenchmarkReplay
{
    public const CASSETTE = __DIR__.'/../Fixtures/cassettes/anthropic/benchmark-laravel11-app.json';

    // bin/benchmark recorded with --level low --min-confidence low --no-cache --no-baseline; none of them changes a request body.
    public static function run(string $root): AnalysisResult
    {
        self::skipIfStale();
        $cassette = is_file(self::CASSETTE) ? self::CASSETTE : throw new \LogicException('the laravel11-app benchmark cassette is not committed');
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

    // Requests match by body, so a cassette recorded under another system prompt can only miss: skip until it is re-recorded.
    public static function skipIfStale(): void
    {
        $body = json_decode((string) (Cassette::load(self::CASSETTE)->interactions()[0]['request']['body'] ?? ''), true);
        $system = is_array($body) ? ($body['system'] ?? null) : null;
        $recorded = is_array($system) ? implode('', array_map(static fn (mixed $b): string => is_array($b) && is_string($b['text'] ?? null) ? $b['text'] : '', $system)) : $system;
        if ($recorded !== SecurityPrompt::system((new LaravelContext())->promptContext(), [])) {
            Assert::markTestSkipped(sprintf('benchmark-laravel11-app.json was recorded under an older system prompt; prompt v%s needs bin/benchmark --live to re-record it', SecurityPrompt::VERSION));
        }
    }
}
