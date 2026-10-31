<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support;

use TusharKhan\SemanticSec\Analysis\Confidence;
use TusharKhan\SemanticSec\Analysis\Severity;
use TusharKhan\SemanticSec\Candidates\Candidate;
use TusharKhan\SemanticSec\Config\Config;
use TusharKhan\SemanticSec\Framework\DetectedFramework;
use TusharKhan\SemanticSec\Framework\Laravel\LaravelContext;
use TusharKhan\SemanticSec\Parsing\AstGenerator;
use TusharKhan\SemanticSec\Parsing\ParseResult;
use TusharKhan\SemanticSec\Parsing\SourceFile;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTableBuilder;
use TusharKhan\SemanticSec\Payload\PayloadBuilder;

/** An in-memory Laravel project with its deep-mode candidates and a payload builder. */
final class PayloadProject
{
    /**
     * @param  array<string, string>  $files  path => code
     * @return array{PayloadBuilder, array<string, Candidate>} candidates by route key
     */
    public static function build(array $files, int $limit): array
    {
        $parsedFiles = [];
        foreach ($files as $path => $code) {
            $parsedFiles[] = (new AstGenerator())->parse(new SourceFile($path, '/nonexistent/'.$path, $code));
        }
        $parsed = new ParseResult($parsedFiles, []);
        $symbols = (new SymbolTableBuilder())->build($parsed);
        $config = new Config('/nonexistent', 'anthropic', null, null, null, 5, null, $limit, 3, Severity::High, Confidence::Medium, [], [], [], Config::DEFAULT_SENSITIVE_FIELDS, [], []);
        $framework = new DetectedFramework('laravel', 11);
        $context = new LaravelContext();
        $map = $context->buildAuthorizationMap($parsed, $symbols, $config, $framework);
        [$candidates] = $context->candidateSelector($parsed, $symbols, $config, $framework)->select($map, true);
        $byKey = [];
        foreach ($candidates as $candidate) {
            foreach ($candidate->route->keys() as $key) {
                $byKey[$key] = $candidate;
            }
        }

        return [$context->payloadBuilder($parsed, $symbols, $config, $framework), $byKey];
    }
}
