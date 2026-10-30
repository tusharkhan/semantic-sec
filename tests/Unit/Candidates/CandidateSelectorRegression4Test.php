<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Candidates;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Analysis\Category;
use TusharKhan\SemanticSec\Analysis\Confidence;
use TusharKhan\SemanticSec\Analysis\Severity;
use TusharKhan\SemanticSec\Candidates\Candidate;
use TusharKhan\SemanticSec\Candidates\Exclusion;
use TusharKhan\SemanticSec\Config\Config;
use TusharKhan\SemanticSec\Framework\DetectedFramework;
use TusharKhan\SemanticSec\Framework\Laravel\LaravelContext;
use TusharKhan\SemanticSec\Parsing\AstGenerator;
use TusharKhan\SemanticSec\Parsing\ParseResult;
use TusharKhan\SemanticSec\Parsing\SourceFile;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTableBuilder;

/** Review round 4: lookup-named app calls, identifier strings as callables, unknown methods on a relation hop in a variable. */
final class CandidateSelectorRegression4Test extends TestCase
{
    /** @var array{0: array<string, Candidate>, 1: list<Exclusion>}|null */
    private static ?array $probes = null;

    /** @return array<string, array{string, string}> */
    public static function wronglyExcluded(): array
    {
        return [
            'id through a lookup-named private method' => ['GET /i1/{id}', 'idor'],
            'id through a lookup-named service method' => ['GET /i2/{id}', 'idor'],
            'id through a lookup-named service method, named argument' => ['GET /i7/{id}', 'idor'],
            'id through a callee local copy' => ['GET /i8/{id}', 'idor'],
            'request id through a lookup-named private method' => ['POST /i9', 'idor'],
            'unknown method on a request-user relation hop variable' => ['POST /s1', 'missing_authorization'],
            'unknown method on an auth-user relation hop variable' => ['POST /s11', 'missing_authorization'],
            'app function name string passed to ob_start' => ['POST /c1', 'missing_authorization'],
            'namespaced function name string passed to set_error_handler' => ['POST /c5', 'missing_authorization'],
        ];
    }

    #[DataProvider('wronglyExcluded')]
    public function testWronglyExcludedProbeIsSelected(string $key, string $category): void
    {
        $candidate = self::probes()[0][$key] ?? null;
        $exclusions = implode('; ', array_map(static fn (Exclusion $e): string => ($e->category->value ?? '*').': '.$e->reason.' ['.$e->checkSource.']', array_filter(self::probes()[1], static fn (Exclusion $e): bool => $e->routeKey === $key)));
        self::assertNotNull($candidate, $key.' not selected: '.$exclusions);
        self::assertContains($category, array_map(static fn (Category $c): string => $c->value, $candidate->categories), $key.': '.$exclusions);
    }

    /** @return array<string, array{string}> */
    public static function staysSelfScoped(): array
    {
        return [
            'auth()->id() where-scoped write' => ['POST /k1'],
            'write on a relation hop variable' => ['POST /k2'],
            'compact() variable names' => ['POST /k3'],
        ];
    }

    #[DataProvider('staysSelfScoped')]
    public function testSelfScopedControlStaysExcluded(string $key): void
    {
        $candidate = self::probes()[0][$key] ?? null;
        self::assertTrue($candidate === null || ! in_array(Category::MissingAuthorization, $candidate->categories, true), $key.' selected: '.implode('; ', $candidate->reasons ?? []));
    }

    /** @return array{0: array<string, Candidate>, 1: list<Exclusion>} */
    private static function probes(): array
    {
        if (self::$probes !== null) {
            return self::$probes;
        }
        /** @var array<string, string> $sources */
        $sources = require __DIR__.'/Fixtures/round4.php';
        $files = [];
        foreach ($sources as $path => $code) {
            $files[] = (new AstGenerator())->parse(new SourceFile($path, '/nonexistent/'.$path, $code));
        }
        $parsed = new ParseResult($files, []);
        $symbols = (new SymbolTableBuilder())->build($parsed);
        $config = new Config('/nonexistent', 'anthropic', null, null, null, 5, null, 8000, 3, Severity::High, Confidence::Medium, [], [], [], Config::DEFAULT_SENSITIVE_FIELDS, [], []);
        $framework = new DetectedFramework('laravel', 11);
        $context = new LaravelContext();
        $selector = $context->candidateSelector($parsed, $symbols, $config, $framework);
        [$candidates] = $selector->select($context->buildAuthorizationMap($parsed, $symbols, $config, $framework), false);
        $byKey = [];
        foreach ($candidates as $candidate) {
            foreach ($candidate->route->keys() as $key) {
                $byKey[$key] = $candidate;
            }
        }

        return self::$probes = [$byKey, $selector->exclusions()];
    }
}
