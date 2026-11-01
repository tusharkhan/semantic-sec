<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Benchmark;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\DisguiseMap;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\ExpectedCases;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\Scorer;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\Undisguise;

final class UndisguiseTest extends TestCase
{
    private static function map(): DisguiseMap
    {
        return DisguiseMap::load(__DIR__.'/../../Fixtures/benchmark/competitor/disguise-map.json');
    }

    public function testAnalyzeFindingsGoBackToOriginalSymbolsAndFiles(): void
    {
        $finding = [
            'category' => 'idor',
            'confidence' => 'high',
            'file' => 'app/Http/Controllers/Beta/ItemController.php',
            'line' => 13,
            'symbol' => 'App\Http\Controllers\Beta\ItemController::show',
            'title' => 't',
            'path' => [['file' => 'app/Http/Controllers/Alpha/TransferController.php', 'line' => 12, 'symbol' => 'App\Http\Controllers\Alpha\TransferController::approve']],
        ];
        $analyze = Undisguise::analyze(self::map(), 'app-a', ['findings' => [$finding], 'suppressed' => [$finding], 'filtered' => 'not a list']);

        foreach (['findings', 'suppressed'] as $list) {
            self::assertSame('app/Http/Controllers/Vuln/ItemController.php', $analyze[$list][0]['file']);
            self::assertSame('App\Http\Controllers\Vuln\ItemController::show', $analyze[$list][0]['symbol']);
            self::assertSame('App\Http\Controllers\Vuln\TransferController::approve', $analyze[$list][0]['path'][0]['symbol']);
            self::assertSame('app/Http/Controllers/Vuln/TransferController.php', $analyze[$list][0]['path'][0]['file']);
        }
        self::assertSame('not a list', $analyze['filtered']);
        self::assertSame(13, $analyze['findings'][0]['line']);
    }

    public function testMapRoutesAndDryRunSelectionGoBack(): void
    {
        $json = Undisguise::map(self::map(), 'app-a', ['routes' => [
            ['methods' => ['GET', 'HEAD'], 'uri' => '/beta/items/{id}', 'action' => ['class' => 'App\Http\Controllers\Beta\ItemController', 'method' => 'show'], 'checks' => []],
            ['methods' => ['GET'], 'uri' => '/posts/{post:slug}', 'action' => ['class' => 'App\Http\Controllers\PostController', 'method' => 'show'], 'checks' => []],
        ]]);
        $dry = Undisguise::dryRun(self::map(), 'app-a', ['candidates' => [['route' => 'GET|HEAD /beta/items/{id}', 'categories' => ['idor']], ['route' => 'POST /alpha/transfers/{transfer}/approve', 'categories' => []]]]);

        self::assertSame('/vuln/items/{id}', $json['routes'][0]['uri']);
        self::assertSame('App\Http\Controllers\Vuln\ItemController', $json['routes'][0]['action']['class']);
        self::assertSame('/posts/{post:slug}', $json['routes'][1]['uri']);
        self::assertSame('GET|HEAD /vuln/items/{id}', $dry['candidates'][0]['route']);
        self::assertSame('POST /vuln/transfers/{transfer}/approve', $dry['candidates'][1]['route']);
        self::assertSame('GET /beta/items/{id}', self::map()->disguisedRoute('app-a', 'GET /vuln/items/{id}'));
    }

    public function testScorerSeesTheOriginalCase(): void
    {
        $cases = array_values(array_filter(ExpectedCases::load(ScorerTest::YAML), static fn ($c): bool => $c->app === 'app-a'));
        $analyze = Undisguise::analyze(self::map(), 'app-a', ['findings' => [['category' => 'idor', 'confidence' => 'high', 'file' => 'app/Http/Controllers/Beta/ItemController.php', 'line' => 13, 'symbol' => 'App\Http\Controllers\Beta\ItemController::show', 'title' => 't']]]);
        $map = Undisguise::map(self::map(), 'app-a', ['routes' => [['methods' => ['GET'], 'uri' => '/beta/items/{id}', 'checks' => [['kind' => 'authentication', 'strength' => 'authentication']]]]]);

        $verdict = Scorer::score($cases, ['app-a' => $analyze], ['app-a' => $map])->verdict('plain-idor');

        self::assertTrue($verdict->found);
        self::assertTrue($verdict->mapVulnerable['ok']);
    }
}
