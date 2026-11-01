<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Integration\Benchmark;

use PhpParser\Node\Stmt\ClassMethod;
use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;
use TusharKhan\SemanticSec\Tests\Support\CorpusValidator;

final class CorpusValidatorTest extends TestCase
{
    private const SOURCE = <<<'PHP'
<?php

namespace App\Http\Controllers;

class ShowController
{
    // @semantic-sec-ignore idor: public by contract
    public function ignored(int $id): array
    {
        $item = Item::findOrFail($id);

        return [$item];
    }

    /**
     * @return array  Ownership is enforced elsewhere.
     */
    public function plain(int $id): array
    {
        $item = Item::query()
            ->findOrFail($id);

        return [$item];
    }

    /**
     * @semantic-sec-ignore all
     */
    public function docIgnored(): void
    {
    }
}
PHP;

    public function testWellFormedCaseHasNoErrors(): void
    {
        self::assertSame([], CorpusValidator::caseErrors($this->validCase(), BenchmarkCorpus::root()));
    }

    public function testUnknownCaseKeyIsRejected(): void
    {
        $case = $this->validCase();
        $case['severity'] = 'high';

        $this->assertSingleError('sample-case: unknown key "severity"', $case);
    }

    public function testUnknownVariantKeyIsRejected(): void
    {
        $case = $this->validCase();
        $case['safe']['lines'] = 12;

        $this->assertSingleError('sample-case.safe: unknown key "lines"', $case);
    }

    public function testMapNoteExplainsAMapByDecision(): void
    {
        $case = $this->validCase();
        $case['safe']['map_note'] = 'scopeBindings counted as query_scope by maintainer decision 2026-11-01';
        self::assertSame([], CorpusValidator::caseErrors($case, BenchmarkCorpus::root()));

        $case['safe']['map_note'] = '';
        $this->assertSingleError('sample-case.safe: map_note must be a non-empty string', $case);
    }

    public function testAppMustBeAnExistingAppDirectory(): void
    {
        $case = $this->validCase();
        $case['app'] = 'laravel99-app';

        $this->assertSingleError('sample-case: app "laravel99-app" is not a benchmark app', $case);
    }

    public function testSetIsRequiredAndMustBeExistingOrBlind(): void
    {
        $case = $this->validCase();
        unset($case['set']);
        $this->assertSingleError('sample-case: missing key "set"', $case);

        $case['set'] = 'hidden';
        $this->assertSingleError('sample-case: set must be existing or blind', $case);

        $case['set'] = 'blind';
        self::assertSame([], CorpusValidator::caseErrors($case, BenchmarkCorpus::root()));
    }

    public function testAcceptIsAListOfSymbols(): void
    {
        $case = $this->validCase();
        $case['vulnerable']['accept'] = ['App\Policies\SamplePolicy::view'];
        self::assertSame([], CorpusValidator::caseErrors($case, BenchmarkCorpus::root()));

        $case['vulnerable']['accept'] = 'App\Policies\SamplePolicy::view';
        $this->assertSingleError('sample-case.vulnerable: accept must be a non-empty list of App\Class::method symbols', $case);

        $case['vulnerable']['accept'] = ['SamplePolicy'];
        $this->assertSingleError('sample-case.vulnerable: accept must be a non-empty list of App\Class::method symbols', $case);

        $case['vulnerable']['accept'] = ['App\Http\Controllers\Vuln\SampleController::show'];
        $this->assertSingleError('sample-case.vulnerable: accept repeats the case symbol', $case);

        $case = $this->validCase();
        $case['safe']['accept'] = ['App\Policies\SamplePolicy::view'];
        self::assertSame([], CorpusValidator::caseErrors($case, BenchmarkCorpus::root()));
    }

    public function testPosthocMarksAnAcceptList(): void
    {
        $case = $this->validCase();
        $case['vulnerable']['accept'] = ['App\Policies\SamplePolicy::view'];
        $case['vulnerable']['posthoc'] = true;
        self::assertSame([], CorpusValidator::caseErrors($case, BenchmarkCorpus::root()));

        $case['vulnerable']['posthoc'] = 'yes';
        $this->assertSingleError('sample-case.vulnerable: posthoc must be a bool', $case);

        $case = $this->validCase();
        $case['vulnerable']['posthoc'] = true;
        $this->assertSingleError('sample-case.vulnerable: posthoc needs an accept list', $case);
    }

    public function testPublicRouteSetIsOptionalButChecked(): void
    {
        $route = ['app' => 'laravel11-app', 'route' => 'GET /posts/{post}', 'symbol' => 'App\Http\Controllers\PostController::show'];
        self::assertSame([], CorpusValidator::publicRouteErrors('p', $route, BenchmarkCorpus::root()));
        self::assertSame([], CorpusValidator::publicRouteErrors('p', [...$route, 'set' => 'blind'], BenchmarkCorpus::root()));
        self::assertSame(['p: set must be existing or blind'], CorpusValidator::publicRouteErrors('p', [...$route, 'set' => 'x'], BenchmarkCorpus::root()));
        self::assertSame(['p: unknown key "line"'], CorpusValidator::publicRouteErrors('p', [...$route, 'line' => 3], BenchmarkCorpus::root()));
    }

    public function testFlagsMustBeBooleans(): void
    {
        $case = $this->validCase();
        $case['vulnerable']['suppressed'] = 'yes';
        $case['safe']['candidate'] = 0;

        self::assertSame([
            'sample-case.vulnerable: suppressed must be a bool',
            'sample-case.safe: candidate must be a bool',
        ], CorpusValidator::caseErrors($case, BenchmarkCorpus::root()));
    }

    public function testLineIsRequiredOnVulnerableAndForbiddenOnSafe(): void
    {
        $case = $this->validCase();
        $case['vulnerable']['line'] = '19';
        $case['safe']['line'] = 19;

        self::assertSame([
            'sample-case.vulnerable: line must be an int',
            'sample-case.safe: line is only allowed on vulnerable',
        ], CorpusValidator::caseErrors($case, BenchmarkCorpus::root()));
    }

    public function testDuplicateMapKindsAreRejected(): void
    {
        $case = $this->validCase();
        $case['safe']['map'] = ['authentication', 'query_scope', 'authentication'];

        $this->assertSingleError('sample-case.safe: duplicate map kind "authentication"', $case);
    }

    public function testUnknownMapKindIsRejected(): void
    {
        $case = $this->validCase();
        $case['safe']['map'] = ['authentication', 'gateway'];

        $this->assertSingleError('sample-case.safe: bad map kind "gateway"', $case);
    }

    public function testMalformedEntriesReportErrorsInsteadOfWarnings(): void
    {
        $errors = CorpusValidator::caseErrors(['id' => 'broken', 'vulnerable' => 'oops', 'safe' => ['map' => 'x']], BenchmarkCorpus::root());

        self::assertContains('broken: missing key "app"', $errors);
        self::assertContains('broken.vulnerable: must be a mapping', $errors);
        self::assertContains('broken.safe: missing key "route"', $errors);
        self::assertContains('broken.safe: map must be a list', $errors);
        self::assertSame('?: missing key "id"', CorpusValidator::caseErrors([], BenchmarkCorpus::root())[0]);
    }

    public function testLineMustStartAStatementInsideTheMethod(): void
    {
        $method = $this->method('plain');

        self::assertSame([], CorpusValidator::lineErrors('c.vulnerable', $method, 20));
        self::assertSame([], CorpusValidator::lineErrors('c.vulnerable', $method, 23));
        self::assertSame(['c.vulnerable: no statement starts on line 21'], CorpusValidator::lineErrors('c.vulnerable', $method, 21));
        self::assertSame(['c.vulnerable: no statement starts on line 18'], CorpusValidator::lineErrors('c.vulnerable', $method, 18));
        self::assertSame(['c.vulnerable: no statement starts on line 16'], CorpusValidator::lineErrors('c.vulnerable', $method, 16));
    }

    public function testSuppressionMustMatchTheFlag(): void
    {
        self::assertSame([], CorpusValidator::suppressionErrors('c.vulnerable', $this->method('ignored'), true));
        self::assertSame([], CorpusValidator::suppressionErrors('c.vulnerable', $this->method('docIgnored'), true));
        self::assertSame([], CorpusValidator::suppressionErrors('c.safe', $this->method('plain'), false));
        self::assertSame(
            ['c.vulnerable: suppressed: true but the method has no @semantic-sec-ignore comment'],
            CorpusValidator::suppressionErrors('c.vulnerable', $this->method('plain'), true),
        );
        self::assertSame(
            ['c.safe: @semantic-sec-ignore on a variant without suppressed: true'],
            CorpusValidator::suppressionErrors('c.safe', $this->method('ignored'), false),
        );
    }

    public function testRouteFormatIsChecked(): void
    {
        self::assertSame([
            'a.vulnerable: bad route "get /vuln/x"',
            'a.safe: bad route "GET safe/x"',
            'b.safe: bad route "HEAD /safe/x"',
        ], CorpusValidator::routeErrors([
            ['owner' => 'a.vulnerable', 'app' => 'laravel11-app', 'route' => 'get /vuln/x'],
            ['owner' => 'a.safe', 'app' => 'laravel11-app', 'route' => 'GET safe/x'],
            ['owner' => 'b.safe', 'app' => 'laravel11-app', 'route' => 'HEAD /safe/x'],
        ]));
    }

    public function testRoutesAreUniquePerApp(): void
    {
        self::assertSame(
            ['b.safe: route "GET /x/{id}" in laravel11-app already used by a.vulnerable'],
            CorpusValidator::routeErrors([
                ['owner' => 'a.vulnerable', 'app' => 'laravel11-app', 'route' => 'GET /x/{id}'],
                ['owner' => 'a.safe', 'app' => 'laravel10-app', 'route' => 'GET /x/{id}'],
                ['owner' => 'b.safe', 'app' => 'laravel11-app', 'route' => 'GET /x/{id}'],
            ]),
        );
    }

    /** @param array<mixed> $case */
    private function assertSingleError(string $expected, array $case): void
    {
        self::assertSame([$expected], CorpusValidator::caseErrors($case, BenchmarkCorpus::root()));
    }

    private function method(string $name): ClassMethod
    {
        $method = BenchmarkCorpus::findMethodInSource(self::SOURCE, 'App\Http\Controllers\ShowController', $name);
        self::assertInstanceOf(ClassMethod::class, $method);

        return $method;
    }

    /** @return array<string, mixed> */
    private function validCase(): array
    {
        return [
            'id' => 'sample-case',
            'app' => 'laravel11-app',
            'set' => 'existing',
            'category' => 'idor',
            'description' => 'Sample.',
            'vulnerable' => [
                'route' => 'GET /vuln/samples/{id}',
                'symbol' => 'App\Http\Controllers\Vuln\SampleController::show',
                'line' => 19,
                'map' => ['authentication'],
                'suppressed' => true,
            ],
            'safe' => [
                'route' => 'GET /safe/samples/{id}',
                'symbol' => 'App\Http\Controllers\Safe\SampleController::show',
                'map' => ['authentication', 'query_scope'],
                'candidate' => false,
            ],
        ];
    }
}
