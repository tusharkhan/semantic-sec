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

/** Final review: pivot writes from input, state changes on GET, ids through request arrays, widened builders. */
final class CandidateSelectorRegression6Test extends TestCase
{
    /** @var array{0: array<string, Candidate>, 1: list<Exclusion>}|null */
    private static ?array $probes = null;

    /** @return array<string, array{string, string}> */
    public static function wronglyExcluded(): array
    {
        return [
            'pivot sync from input on the auth user (POST)' => ['POST /q1', 'missing_authorization'],
            'pivot sync from input selects idor' => ['POST /q1', 'idor'],
            'pivot attach of an id-named input' => ['POST /q2', 'missing_authorization'],
            'pivot attach id selects idor' => ['POST /q2', 'idor'],
            'syncWithoutDetaching from input' => ['POST /q6', 'missing_authorization'],
            'toggle from input' => ['POST /q7', 'missing_authorization'],
            'updateExistingPivot from input' => ['POST /q8', 'missing_authorization'],
            'sync of an input variable' => ['POST /q9', 'missing_authorization'],
            'sync of an input variable selects idor' => ['POST /q9', 'idor'],
            'pivot sync from input on GET' => ['GET /p4', 'missing_authorization'],
            'write in an app global function' => ['GET /p1', 'missing_authorization'],
            'write two app functions deep' => ['GET /p20', 'missing_authorization'],
            'write in a function_exists-guarded helper' => ['GET /p21', 'missing_authorization'],
            'write in a namespaced app function' => ['GET /p22', 'missing_authorization'],
            'DB::table()->truncate()' => ['GET /p2', 'missing_authorization'],
            'DB::delete()' => ['GET /p9', 'missing_authorization'],
            'DB::insert()' => ['GET /p14', 'missing_authorization'],
            'DB::statement()' => ['GET /p15', 'missing_authorization'],
            'DB::unprepared()' => ['GET /p16', 'missing_authorization'],
            'DB::table()->insert()' => ['GET /p17', 'missing_authorization'],
            'DB::table()->upsert()' => ['GET /p18', 'missing_authorization'],
            'DB::table()->decrement()' => ['GET /p19', 'missing_authorization'],
            'increment on a model' => ['GET /p3', 'missing_authorization'],
            'updateOrCreate on a model' => ['GET /p7', 'missing_authorization'],
            'scoped builder reassigned from an app method' => ['GET /p5/{id}', 'idor'],
            'scoped builder passed into an app method' => ['GET /p5b/{id}', 'idor'],
            'scoped builder widened by orWhere statement' => ['GET /p5c/{id}', 'idor'],
            'id through $request->all() array' => ['GET /r1', 'idor'],
            'id through $request->all() array in a closure' => ['GET /r2', 'idor'],
            'post_id through $request->all() array' => ['GET /r4', 'idor'],
            'post_id through validated()' => ['GET /r5', 'idor'],
            'post_id through only()' => ['GET /r6', 'idor'],
            'post_id through input()' => ['GET /r7', 'idor'],
            'post_id through except()' => ['GET /r8', 'idor'],
            'post_id through request()->all()' => ['GET /r9', 'idor'],
            'post_id through $request->all()[...]' => ['GET /r10', 'idor'],
            'post_id through a request array passed to a callee' => ['GET /r11', 'idor'],
            'destroy action' => ['GET /d/destroy', 'missing_authorization'],
            'delete* action' => ['GET /d/deleteAll', 'missing_authorization'],
            'remove* action' => ['GET /d/removeOld', 'missing_authorization'],
            'purge* action' => ['GET /d/purgeCache', 'missing_authorization'],
            'truncate* action' => ['GET /d/truncateLogs', 'missing_authorization'],
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
            'detach() with no arguments' => ['POST /k1'],
            'sync() of a constant list' => ['POST /k2'],
            'own posts create from validated input' => ['POST /k3'],
        ];
    }

    #[DataProvider('staysSelfScoped')]
    public function testSelfScopedControlStaysExcluded(string $key): void
    {
        $candidate = self::probes()[0][$key] ?? null;
        self::assertTrue($candidate === null || ! in_array(Category::MissingAuthorization, $candidate->categories, true), $key.' selected: '.implode('; ', $candidate->reasons ?? []));
    }

    /** @return array<string, array{string}> */
    public static function staysCovered(): array
    {
        return [
            'scoped builder kept in a variable' => ['GET /k4/{id}'],
            'scoped builder extended by a builder method' => ['GET /k5/{id}'],
        ];
    }

    #[DataProvider('staysCovered')]
    public function testCoveredControlStaysExcluded(string $key): void
    {
        $candidate = self::probes()[0][$key] ?? null;
        self::assertTrue($candidate === null || ! in_array(Category::Idor, $candidate->categories, true), $key.' selected: '.implode('; ', $candidate->reasons ?? []));
    }

    public function testNonDestroyStyleActionStaysUnselected(): void
    {
        self::assertArrayNotHasKey('GET /d/show', self::probes()[0]);
    }

    /** @return array{0: array<string, Candidate>, 1: list<Exclusion>} */
    private static function probes(): array
    {
        if (self::$probes !== null) {
            return self::$probes;
        }
        /** @var array<string, string> $sources */
        $sources = require __DIR__.'/Fixtures/round6.php';
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
