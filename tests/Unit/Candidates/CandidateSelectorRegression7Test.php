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
use TusharKhan\SemanticSec\Framework\Laravel\AuthCheck;
use TusharKhan\SemanticSec\Framework\Laravel\AuthCheckKind;
use TusharKhan\SemanticSec\Framework\Laravel\AuthorizationMap;
use TusharKhan\SemanticSec\Framework\Laravel\AuthStrength;
use TusharKhan\SemanticSec\Framework\Laravel\LaravelContext;
use TusharKhan\SemanticSec\Parsing\AstGenerator;
use TusharKhan\SemanticSec\Parsing\ParseResult;
use TusharKhan\SemanticSec\Parsing\SourceFile;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTableBuilder;

/** M6: an authorization_middleware entry excludes missing_authorization but covers no identifier. */
final class CandidateSelectorRegression7Test extends TestCase
{
    /** @var array{0: array<string, Candidate>, 1: list<Exclusion>, 2: AuthorizationMap}|null */
    private static ?array $probes = null;

    public function testListedMiddlewareExcludesMissingAuthorizationButKeepsIdor(): void
    {
        $this->assertListed('PUT /x/{id}');
    }

    /** @return array<string, array{string}> */
    public static function listedRoutes(): array
    {
        return [
            'class FQN entry' => ['PUT /f/{id}'],
            'applied through a group' => ['PUT /g/{id}'],
            'applied by the controller constructor' => ['PUT /c/{id}'],
        ];
    }

    #[DataProvider('listedRoutes')]
    public function testListedMiddlewareAppliedElsewhere(string $key): void
    {
        $this->assertListed($key);
    }

    public function testUnlistedRouteStaysMissingAuthorization(): void
    {
        $candidate = self::probes()[0]['PUT /y/{id}'] ?? null;
        self::assertNotNull($candidate);
        self::assertContains(Category::MissingAuthorization, $candidate->categories);
    }

    public function testUnresolvedWithoutMiddlewareMakesTheCheckNone(): void
    {
        $candidate = self::probes()[0]['PUT /w/{id}'] ?? null;
        self::assertNotNull($candidate);
        self::assertContains(Category::MissingAuthorization, $candidate->categories);
        $check = $this->listedCheck('/w/{id}');
        self::assertSame(AuthStrength::None, $check->strength);
    }

    public function testMapCheckShape(): void
    {
        $check = $this->listedCheck('/x/{id}');
        self::assertSame(AuthCheckKind::Middleware, $check->kind);
        self::assertSame(AuthStrength::Authorization, $check->strength);
        self::assertNull($check->covers);
        self::assertTrue($check->routeWide);
        self::assertSame('permission:manage (authorization_middleware)', $check->source);
    }

    private function assertListed(string $key): void
    {
        $candidate = self::probes()[0][$key] ?? null;
        self::assertNotNull($candidate, $key.' not selected');
        self::assertContains(Category::Idor, $candidate->categories, $key);
        self::assertNotContains(Category::MissingAuthorization, $candidate->categories, $key);
        $sources = array_map(static fn (Exclusion $e): string => $e->checkSource, array_filter(self::probes()[1], static fn (Exclusion $e): bool => $e->routeKey === $key && $e->category === Category::MissingAuthorization));
        self::assertCount(1, $sources, $key);
        self::assertStringContainsString('(authorization_middleware)', implode('', $sources));
    }

    private function listedCheck(string $uri): AuthCheck
    {
        foreach (self::probes()[2]->routes as $route) {
            if ($route->uri === $uri) {
                foreach ($route->checks as $c) {
                    if (str_contains($c->source, 'authorization_middleware')) {
                        return $c;
                    }
                }
            }
        }
        self::fail('no authorization_middleware check on '.$uri);
    }

    /** @return array{0: array<string, Candidate>, 1: list<Exclusion>, 2: AuthorizationMap} */
    private static function probes(): array
    {
        if (self::$probes !== null) {
            return self::$probes;
        }
        /** @var array<string, string> $sources */
        $sources = require __DIR__.'/Fixtures/round7.php';
        $files = [];
        foreach ($sources as $path => $code) {
            $files[] = (new AstGenerator())->parse(new SourceFile($path, '/nonexistent/'.$path, $code));
        }
        $parsed = new ParseResult($files, []);
        $symbols = (new SymbolTableBuilder())->build($parsed);
        $config = new Config('/nonexistent', 'anthropic', null, null, null, 5, null, 8000, 3, Severity::High, Confidence::Medium, [], [], [], Config::DEFAULT_SENSITIVE_FIELDS, [], [], authorizationMiddleware: ['permission', '\App\Http\Middleware\CLASSLISTED']);
        $framework = new DetectedFramework('laravel', 11);
        $context = new LaravelContext();
        $selector = $context->candidateSelector($parsed, $symbols, $config, $framework);
        $map = $context->buildAuthorizationMap($parsed, $symbols, $config, $framework);
        [$candidates] = $selector->select($map, false);
        $byKey = [];
        foreach ($candidates as $candidate) {
            foreach ($candidate->route->keys() as $key) {
                $byKey[$key] = $candidate;
            }
        }

        return self::$probes = [$byKey, $selector->exclusions(), $map];
    }
}
