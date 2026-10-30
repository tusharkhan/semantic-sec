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

/** Review round 5: one taint walk for callees (foreach, by-ref, yield), callable arguments, default-deny self-scoped exemption. */
final class CandidateSelectorRegression5Test extends TestCase
{
    /** @var array{0: array<string, Candidate>, 1: list<Exclusion>}|null */
    private static ?array $probes = null;

    /** @return array<string, array{string, string}> */
    public static function wronglyExcluded(): array
    {
        return [
            'id written to a by-ref internal function output' => ['GET /j7/{id}', 'idor'],
            'id through a foreach in the route' => ['GET /j8/{id}', 'idor'],
            'id written to a by-ref parameter' => ['GET /j1/{id}', 'idor'],
            'id returned from a callee foreach (copyLoop)' => ['GET /j2/{id}', 'idor'],
            'id yielded by a callee generator' => ['GET /j3/{id}', 'idor'],
            'j4 stays selected' => ['GET /j4/{id}', 'idor'],
            'j5 stays selected' => ['GET /j5/{id}', 'idor'],
            'j6 stays selected' => ['GET /j6/{id}', 'idor'],
            'i10 stays selected' => ['GET /i10/{id}', 'idor'],
            'i11 stays selected' => ['GET /i11/{id}', 'idor'],
            'i12 stays selected' => ['GET /i12/{id}', 'idor'],
            'i13 stays selected' => ['GET /i13/{id}', 'idor'],
            'i14 stays selected' => ['GET /i14/{id}', 'idor'],
            'i15 stays selected' => ['GET /i15/{id}', 'idor'],
            'i16 stays selected' => ['GET /i16/{id}', 'idor'],
            'id written to a by-ref parameter (findRef)' => ['GET /i18/{id}', 'idor'],
            'i19 stays selected' => ['GET /i19/{id}', 'idor'],
            'i20 stays selected' => ['GET /i20/{id}', 'idor'],
            'i21 stays selected' => ['GET /i21/{id}', 'idor'],
            'i22 stays selected' => ['GET /i22/{id}', 'idor'],
            'i23 stays selected' => ['GET /i23/{id}', 'idor'],
            'i24 stays selected' => ['GET /i24/{id}', 'idor'],
            'id returned from a callee foreach (findLoop)' => ['GET /i25/{id}', 'idor'],
            'i26 stays selected' => ['GET /i26/{id}', 'idor'],
            'i27 stays selected' => ['GET /i27/{id}', 'idor'],
            'id yielded to a route foreach (findGen)' => ['GET /i28/{id}', 'idor'],
            'i29 stays selected' => ['GET /i29/{id}', 'idor'],
            'c7 stays selected' => ['POST /c7', 'missing_authorization'],
            'c8 stays selected' => ['POST /c8', 'missing_authorization'],
            'c9 stays selected' => ['POST /c9', 'missing_authorization'],
            'callable variable passed to ob_start' => ['POST /c10', 'missing_authorization'],
            'c11 stays selected' => ['POST /c11', 'missing_authorization'],
            'c12 stays selected' => ['POST /c12', 'missing_authorization'],
            'c13 stays selected' => ['POST /c13', 'missing_authorization'],
            'c14 stays selected' => ['POST /c14', 'missing_authorization'],
            'c15 stays selected' => ['POST /c15', 'missing_authorization'],
            'c16 stays selected' => ['POST /c16', 'missing_authorization'],
            'concatenated callable passed to ob_start' => ['POST /c18', 'missing_authorization'],
            'c19 stays selected' => ['POST /c19', 'missing_authorization'],
            'c20 stays selected' => ['POST /c20', 'missing_authorization'],
            's13 stays selected' => ['POST /s13', 'missing_authorization'],
            's14 stays selected' => ['POST /s14', 'missing_authorization'],
            'unknown method on an unscoped model variable' => ['POST /s15', 'missing_authorization'],
            'unknown method on Team::find(1)' => ['POST /s16', 'missing_authorization'],
            's17 stays selected' => ['POST /s17', 'missing_authorization'],
            'unknown method past a hop variable member chain' => ['POST /s18', 'missing_authorization'],
            'unknown method on a member of a hop variable' => ['POST /s19', 'missing_authorization'],
            's20 stays selected' => ['POST /s20', 'missing_authorization'],
            'unknown method on a where-filtered model' => ['POST /s21', 'missing_authorization'],
            's22 stays selected' => ['POST /s22', 'missing_authorization'],
            's23 stays selected' => ['POST /s23', 'missing_authorization'],
            'unknown method on Team::first()' => ['POST /s25', 'missing_authorization'],
            's29 stays selected' => ['POST /s29', 'missing_authorization'],
            's30 stays selected' => ['POST /s30', 'missing_authorization'],
            's31 stays selected' => ['POST /s31', 'missing_authorization'],
            's32 stays selected' => ['POST /s32', 'missing_authorization'],
            'v1 stays selected' => ['POST /v1', 'missing_authorization'],
            'Team::find(1)->syncRoles()' => ['POST /v2', 'missing_authorization'],
            'v3 stays selected' => ['POST /v3', 'missing_authorization'],
            'v4 stays selected' => ['POST /v4', 'missing_authorization'],
            'v5 stays selected' => ['POST /v5', 'missing_authorization'],
            'v6 stays selected' => ['POST /v6', 'missing_authorization'],
            'unknown method on an unscoped model member chain' => ['POST /v7', 'missing_authorization'],
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
            'write on the own-team variable' => ['POST /k4'],
            'read on the own-team relation' => ['POST /k5'],
            'compact() variable names' => ['POST /k6'],
            'own posts write with only reads' => ['POST /k7'],
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
        $sources = require __DIR__.'/Fixtures/round5.php';
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
