<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Integration\Benchmark;

use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\NodeFinder;
use PhpParser\ParserFactory;
use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use TusharKhan\SemanticSec\Analysis\Category;
use TusharKhan\SemanticSec\Framework\Laravel\AuthCheckKind;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;

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

        self::assertCount(count(BenchmarkCorpus::cases()), $ids);
        self::assertSame(array_values(array_unique($ids, SORT_REGULAR)), $ids);
    }

    public function testEveryCaseHasValidCategoryAndBothVariants(): void
    {
        self::assertContainsOnly('array', BenchmarkCorpus::cases());

        foreach (BenchmarkCorpus::cases() as $case) {
            $id = (string) ($case['id'] ?? '?');
            self::assertNotNull(Category::tryFrom((string) ($case['category'] ?? '')), "bad category in $id");

            foreach (['vulnerable', 'safe'] as $variant) {
                self::assertIsArray($case[$variant] ?? null, "$id lacks $variant");
                foreach (['route', 'symbol', 'map'] as $key) {
                    self::assertArrayHasKey($key, $case[$variant], "$id.$variant lacks $key");
                }
            }
        }
    }

    public function testMapKindsAreValid(): void
    {
        self::assertContainsOnly('array', BenchmarkCorpus::cases());

        foreach (BenchmarkCorpus::cases() as $case) {
            foreach (['vulnerable', 'safe'] as $variant) {
                $map = $case[$variant]['map'] ?? [];
                self::assertIsArray($map);
                foreach ($map as $kind) {
                    self::assertNotNull(AuthCheckKind::tryFrom((string) $kind), 'bad map kind ' . json_encode($kind));
                }
            }
        }
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

    public function testVulnerableLineIsInsideItsSymbol(): void
    {
        self::assertContainsOnly('array', BenchmarkCorpus::cases());

        foreach (BenchmarkCorpus::cases() as $case) {
            $vulnerable = $case['vulnerable'];
            $method = $this->findMethod((string) $case['app'], (string) $vulnerable['symbol']);
            $line = (int) $vulnerable['line'];

            self::assertGreaterThanOrEqual($method->getStartLine(), $line, "{$case['id']} line before method");
            self::assertLessThanOrEqual($method->getEndLine(), $line, "{$case['id']} line after method");
        }
    }

    public function testSymbolsExist(): void
    {
        self::assertContainsOnly('array', BenchmarkCorpus::cases());
        self::assertContainsOnly('array', BenchmarkCorpus::publicRoutes());

        foreach (BenchmarkCorpus::cases() as $case) {
            self::assertInstanceOf(ClassMethod::class, $this->findMethod((string) $case['app'], (string) $case['safe']['symbol']));
        }

        foreach (BenchmarkCorpus::publicRoutes() as $route) {
            self::assertInstanceOf(ClassMethod::class, $this->findMethod((string) $route['app'], (string) $route['symbol']));
        }
    }

    private function findMethod(string $app, string $symbol): ClassMethod
    {
        $name = explode('::', $symbol)[1];
        $ast = (new ParserFactory())->createForNewestSupportedVersion()
            ->parse((string) file_get_contents(BenchmarkCorpus::fileForSymbol($app, $symbol))) ?? [];
        $method = (new NodeFinder())->findFirst(
            $ast,
            static fn ($node): bool => $node instanceof ClassMethod && $node->name->toString() === $name,
        );

        self::assertInstanceOf(ClassMethod::class, $method, "method $symbol not found");

        return $method;
    }
}
