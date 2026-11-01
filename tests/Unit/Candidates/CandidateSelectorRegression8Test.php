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

/** M8 tuning: a GET list endpoint reading an owned collection without a user scope is an idor candidate. */
final class CandidateSelectorRegression8Test extends TestCase
{
    /** @var array{0: array<string, Candidate>, 1: list<Exclusion>, 2: array<string, Candidate>}|null */
    private static ?array $probes = null;

    /** @return array<string, array{string, string}> */
    public static function selectedLists(): array
    {
        return [
            'belongsTo the auth user model' => ['GET /owned-by-user', 'unscoped read of owned Ticket collection'],
            'team_id in $fillable' => ['GET /team-key', 'unscoped read of owned Note collection'],
            'the auth user hasMany the model' => ['GET /inverse', 'unscoped read of owned Invoice collection'],
            'columns unknown, so ownership unknown' => ['GET /unknown-columns', 'unscoped read of owned Widget collection (ownership unknown)'],
            'read in a callee' => ['GET /via-callee', 'unscoped read of owned Note collection'],
            'builder held in a variable' => ['GET /var-built', 'unscoped read of owned Note collection'],
            'scoped builder widened by orWhere' => ['GET /var-widened', 'unscoped read of owned Ticket collection'],
            'builder returned by a callee' => ['GET /via-builder', 'unscoped read of owned Note collection'],
        ];
    }

    #[DataProvider('selectedLists')]
    public function testUnscopedOwnedListIsAnIdorCandidate(string $key, string $reason): void
    {
        $candidate = self::probes()[0][$key] ?? null;
        self::assertNotNull($candidate, $key.' not selected; exclusions: '.self::excluded($key));
        self::assertSame([Category::Idor], $candidate->categories);
        self::assertSame($reason, $candidate->reasons['idor']);
    }

    /** @return array<string, array{string, string}> */
    public static function excludedLists(): array
    {
        return [
            'model with no owner key' => ['GET /not-owned', 'no trigger'],
            'relation read rooted at the auth user' => ['GET /relation-scoped', 'scoped to the user'],
            'where(col, auth id)' => ['GET /where-scoped', 'scoped to the user'],
            'scoped builder held in a variable' => ['GET /var-scoped', 'scoped to the user'],
            'behind a can: check' => ['GET /gated', 'covered by an authorization check'],
            'no collection read' => ['GET /count', 'no trigger'],
        ];
    }

    #[DataProvider('excludedLists')]
    public function testScopedGatedOrUnownedListIsNotSelected(string $key, string $why): void
    {
        self::assertArrayNotHasKey($key, self::probes()[0], $key.' selected');
        self::assertStringContainsString($why, self::excluded($key));
    }

    public function testExclusionsNameTheirJustification(): void
    {
        $checked = 0;
        foreach (self::probes()[1] as $e) {
            if ($e->category === Category::Idor && ! str_starts_with($e->reason, 'no trigger: no route')) {
                self::assertNotSame('', $e->checkSource, $e->routeKey.': '.$e->reason);
                $checked++;
            }
        }
        self::assertGreaterThanOrEqual(4, $checked);
    }

    public function testOnlyGetRoutesUseTheListRule(): void
    {
        $candidate = self::probes()[0]['POST /store'] ?? null;
        self::assertNotNull($candidate);
        self::assertNotContains(Category::Idor, $candidate->categories);
    }

    public function testDeepSelectsScopedAndGatedLists(): void
    {
        foreach (['GET /relation-scoped', 'GET /where-scoped', 'GET /gated'] as $key) {
            $candidate = self::probes()[2][$key] ?? null;
            self::assertNotNull($candidate, $key);
            self::assertStringStartsWith('--deep: ', $candidate->reasons['idor']);
        }
        self::assertSame('--deep: unscoped read of owned Ticket collection', self::probes()[2]['GET /owned-by-user']->reasons['idor']);
        self::assertArrayNotHasKey('GET /not-owned', self::probes()[2]);
    }

    private static function excluded(string $key): string
    {
        $out = [];
        foreach (self::probes()[1] as $e) {
            if ($e->routeKey === $key) {
                $out[] = ($e->category->value ?? '*').': '.$e->reason.' ['.$e->checkSource.']';
            }
        }

        return implode('; ', $out);
    }

    /** @return array{0: array<string, Candidate>, 1: list<Exclusion>, 2: array<string, Candidate>} */
    private static function probes(): array
    {
        if (self::$probes !== null) {
            return self::$probes;
        }
        /** @var array<string, string> $sources */
        $sources = require __DIR__.'/Fixtures/round8.php';
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
        $map = $context->buildAuthorizationMap($parsed, $symbols, $config, $framework);
        $byKey = static function (array $candidates): array {
            $out = [];
            foreach ($candidates as $candidate) {
                foreach ($candidate->route->keys() as $key) {
                    $out[$key] = $candidate;
                }
            }

            return $out;
        };
        [$normal] = $selector->select($map, false);
        $exclusions = $selector->exclusions();
        [$deep] = $selector->select($map, true);

        return self::$probes = [$byKey($normal), $exclusions, $byKey($deep)];
    }
}
