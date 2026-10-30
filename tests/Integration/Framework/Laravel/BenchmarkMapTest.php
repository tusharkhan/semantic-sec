<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Integration\Framework\Laravel;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Framework\Laravel\AuthStrength;
use TusharKhan\SemanticSec\Framework\Laravel\LaravelContext;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkMaps;

final class BenchmarkMapTest extends TestCase
{
    private const APPS = ['laravel11-app', 'laravel10-app'];

    public function testContextName(): void
    {
        self::assertSame('laravel', (new LaravelContext())->name());
    }

    public function testEveryExpectedMapMatches(): void
    {
        $checked = 0;
        foreach (self::APPS as $app) {
            $map = BenchmarkMaps::build($app);
            foreach (BenchmarkCorpus::cases() as $case) {
                if ($case['app'] !== $app) {
                    continue;
                }
                foreach (['vulnerable', 'safe'] as $variant) {
                    $expected = (array) $case[$variant]['map'];
                    $route = $map->find((string) $case[$variant]['route']);
                    self::assertNotNull($route, sprintf('%s %s: route %s not found', $case['id'], $variant, $case[$variant]['route']));
                    $actual = [];
                    foreach ($route->checks as $check) {
                        if ($check->strength !== AuthStrength::None) {
                            $actual[$check->kind->value] = true;
                        }
                    }
                    $actual = array_keys($actual);
                    sort($expected);
                    sort($actual);
                    self::assertSame($expected, $actual, sprintf(
                        '%s %s: expected [%s] actual [%s]',
                        $case['id'],
                        $variant,
                        implode(', ', $expected),
                        implode(', ', $actual),
                    ));
                    $checked++;
                }
            }
        }
        self::assertSame(30, $checked);
    }

    public function testPublicRoutesHaveNoChecks(): void
    {
        $routes = BenchmarkCorpus::publicRoutes();
        self::assertNotSame([], $routes);
        foreach ($routes as $public) {
            $route = BenchmarkMaps::build((string) $public['app'])->find((string) $public['route']);
            self::assertNotNull($route, (string) $public['route']);
            foreach ($route->checks as $check) {
                self::assertSame(AuthStrength::None, $check->strength, sprintf('%s has %s', $public['route'], $check->kind->value));
            }
        }
    }

    public function testEveryExpectedRoutePointsAtItsSymbol(): void
    {
        $items = BenchmarkCorpus::publicRoutes();
        foreach (BenchmarkCorpus::cases() as $case) {
            foreach (['vulnerable', 'safe'] as $variant) {
                $items[] = ['app' => $case['app'], 'route' => $case[$variant]['route'], 'symbol' => $case[$variant]['symbol'], 'id' => $case['id'].' '.$variant];
            }
        }
        foreach ($items as $item) {
            $route = BenchmarkMaps::build((string) $item['app'])->find((string) $item['route']);
            self::assertNotNull($route, (string) $item['route']);
            self::assertSame(
                ltrim((string) $item['symbol'], '\\'),
                ltrim((string) $route->action->symbol(), '\\'),
                (string) ($item['id'] ?? $item['route']),
            );
        }
    }

    public function testNoUnexpectedWarningsOnBenchmark(): void
    {
        foreach (self::APPS as $app) {
            self::assertSame([], BenchmarkMaps::build($app)->warnings, $app);
        }
    }
}
