<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Integration\Benchmark;

use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\ParserFactory;
use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;
use TusharKhan\SemanticSec\Tests\Support\CorpusValidator;

final class CorpusIntegrityTest extends TestCase
{
    public function testSkeletonAppsExist(): void
    {
        self::assertDirectoryExists(BenchmarkCorpus::root() . '/laravel11-app');
        self::assertDirectoryExists(BenchmarkCorpus::root() . '/laravel10-app');
    }

    public function testCaseIdsAreUnique(): void
    {
        $ids = array_map(static fn (array $case): mixed => $case['id'] ?? null, BenchmarkCorpus::cases());

        $duplicates = array_keys(array_filter(
            array_count_values(array_map(static fn (mixed $id): string => (string) $id, $ids)),
            static fn (int $count): bool => $count > 1,
        ));

        self::assertSame(count($ids), count(array_unique($ids, SORT_STRING)), 'duplicate case ids: ' . implode(', ', $duplicates));
    }

    public function testEveryCaseIsWellFormed(): void
    {
        $errors = [];
        foreach (BenchmarkCorpus::cases() as $case) {
            $errors = [...$errors, ...CorpusValidator::caseErrors($case, BenchmarkCorpus::root())];
        }

        self::assertSame([], $errors, implode("\n", $errors));
    }

    public function testPublicRoutesAreWellFormed(): void
    {
        $errors = [];
        foreach (BenchmarkCorpus::publicRoutes() as $index => $route) {
            $errors = [...$errors, ...$this->publicRouteErrors("public_routes[$index]", $route)];
        }

        self::assertSame([], $errors, implode("\n", $errors));
    }

    public function testRoutesAreWellFormedAndUnique(): void
    {
        $routes = [];
        foreach ($this->variants() as $label => $variant) {
            $routes[] = ['owner' => $label, 'app' => $variant['app'], 'route' => $variant['route']];
        }
        foreach ($this->publicRoutes() as $label => $route) {
            $routes[] = ['owner' => $label, 'app' => $route['app'], 'route' => $route['route']];
        }

        $errors = CorpusValidator::routeErrors($routes);

        self::assertSame([], $errors, implode("\n", $errors));
    }

    public function testEveryBenchmarkPhpFileParses(): void
    {
        $parser = (new ParserFactory())->createForNewestSupportedVersion();
        $count = 0;
        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(
            BenchmarkCorpus::root(),
            RecursiveDirectoryIterator::SKIP_DOTS,
        ));

        foreach ($files as $file) {
            if ($file->getExtension() !== 'php') {
                continue;
            }
            $count++;
            self::assertNotNull($parser->parse((string) file_get_contents($file->getPathname())), $file->getPathname());
        }

        self::assertGreaterThan(0, $count);
    }

    public function testVulnerableLineStartsAStatementInItsSymbol(): void
    {
        $errors = [];
        foreach ($this->variants() as $label => $variant) {
            if ($variant['line'] !== null) {
                $errors = [...$errors, ...CorpusValidator::lineErrors($label, $this->findMethod($label, $variant['app'], $variant['symbol']), $variant['line'])];
            }
        }

        self::assertSame([], $errors, implode("\n", $errors));
    }

    public function testSuppressionCommentMatchesTheFlag(): void
    {
        $errors = [];
        foreach ($this->variants() as $label => $variant) {
            $method = $this->findMethod($label, $variant['app'], $variant['symbol']);
            $errors = [...$errors, ...CorpusValidator::suppressionErrors($label, $method, $variant['suppressed'])];
        }

        self::assertSame([], $errors, implode("\n", $errors));
    }

    public function testSymbolsExist(): void
    {
        foreach ($this->variants() as $label => $variant) {
            $this->findMethod($label, $variant['app'], $variant['symbol']);
        }

        foreach ($this->publicRoutes() as $label => $route) {
            $this->findMethod($label, $route['app'], $route['symbol']);
        }

        $this->addToAssertionCount(1);
    }

    public function testFindMethodIgnoresSameNamedMethodInAnotherClass(): void
    {
        $code = <<<'PHP'
<?php

namespace App\Http\Controllers;

class First
{
    public function show(): void
    {
    }
}

class Second
{
    public function other(): void
    {
    }

    public function show(): void
    {
    }
}
PHP;

        $method = BenchmarkCorpus::findMethodInSource($code, 'App\Http\Controllers\Second', 'show');

        self::assertInstanceOf(ClassMethod::class, $method);
        self::assertSame(18, $method->getStartLine());
        self::assertNull(BenchmarkCorpus::findMethodInSource($code, 'App\Http\Controllers\First', 'other'));
    }

    // Fails on a malformed corpus first, so later tests can index variants safely.
    /** @return array<string, array{app: string, route: string, symbol: string, line: int|null, suppressed: bool}> */
    private function variants(): array
    {
        $variants = [];
        foreach (BenchmarkCorpus::cases() as $case) {
            $errors = CorpusValidator::caseErrors($case, BenchmarkCorpus::root());
            self::assertSame([], $errors, implode("\n", $errors));

            foreach (CorpusValidator::VARIANTS as $name) {
                /** @var array{route: string, symbol: string, line?: int, suppressed?: bool} $variant */
                $variant = $case[$name];
                /** @var string $app */
                $app = $case['app'];
                $variants[CorpusValidator::caseId($case) . ".$name"] = [
                    'app' => $app,
                    'route' => $variant['route'],
                    'symbol' => $variant['symbol'],
                    'line' => $variant['line'] ?? null,
                    'suppressed' => $variant['suppressed'] ?? false,
                ];
            }
        }

        return $variants;
    }

    /** @return array<string, array{app: string, route: string, symbol: string}> */
    private function publicRoutes(): array
    {
        $routes = [];
        foreach (BenchmarkCorpus::publicRoutes() as $index => $route) {
            $label = "public_routes[$index]";
            $errors = $this->publicRouteErrors($label, $route);
            self::assertSame([], $errors, implode("\n", $errors));

            /** @var array{app: string, route: string, symbol: string} $route */
            $routes[$label] = $route;
        }

        return $routes;
    }

    /**
     * @param array<mixed> $route
     *
     * @return list<string>
     */
    private function publicRouteErrors(string $label, array $route): array
    {
        $errors = [];
        foreach (['app', 'route', 'symbol'] as $key) {
            if (! is_string($route[$key] ?? null) || $route[$key] === '') {
                $errors[] = "$label: $key must be a non-empty string";
            }
        }
        foreach (array_keys($route) as $key) {
            if (! in_array($key, ['app', 'route', 'symbol'], true)) {
                $errors[] = "$label: unknown key \"$key\"";
            }
        }
        if (is_string($route['app'] ?? null) && ! CorpusValidator::isApp($route['app'], BenchmarkCorpus::root())) {
            $errors[] = "$label: app \"{$route['app']}\" is not a benchmark app";
        }

        return $errors;
    }

    private function findMethod(string $label, string $app, string $symbol): ClassMethod
    {
        $file = BenchmarkCorpus::fileForSymbol($app, $symbol);
        self::assertFileExists($file, "$label: no file for $symbol");

        [$class, $name] = explode('::', $symbol, 2) + [1 => ''];
        $method = BenchmarkCorpus::findMethodInSource((string) file_get_contents($file), $class, $name);

        self::assertInstanceOf(ClassMethod::class, $method, "$label: method $symbol not found");

        return $method;
    }
}
