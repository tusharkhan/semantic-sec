<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Integration\Parsing;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Parsing\AstGenerator;
use TusharKhan\SemanticSec\Parsing\FileFinder;
use TusharKhan\SemanticSec\Parsing\ProjectParser;
use TusharKhan\SemanticSec\Parsing\Symbols\RelationResolver;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTableBuilder;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;

final class BenchmarkSymbolTableTest extends TestCase
{
    public function testBenchmarkAppsIndex(): void
    {
        $tables = [];
        foreach (['laravel10-app', 'laravel11-app'] as $app) {
            $result = (new ProjectParser(new FileFinder(), new AstGenerator()))->parse(BenchmarkCorpus::root().'/'.$app);
            self::assertSame([], $result->failures, $app);
            $tables[$app] = (new SymbolTableBuilder())->build($result);
            self::assertNotSame([], $tables[$app]->all(), $app);
        }

        $checked = 0;
        foreach (BenchmarkCorpus::cases() as $case) {
            $app = (string) $case['app'];
            foreach (['vulnerable', 'safe'] as $variant) {
                $symbol = (string) $case[$variant]['symbol'];
                [$class, $method] = explode('::', $symbol);
                self::assertNotNull($tables[$app]->findMethod($class, $method), $case['id'].' '.$symbol);
                $checked++;
            }
        }
        self::assertGreaterThan(0, $checked);

        $this->assertServiceLayer($tables['laravel11-app']);
        $this->assertRelations($tables['laravel11-app']);
    }

    private function assertRelations(SymbolTable $table): void
    {
        $relations = new RelationResolver($table);
        self::assertSame('App\\Models\\Account', $relations->relatedClass('App\\Models\\User', 'account'));
        self::assertSame('App\\Models\\Invoice', $relations->relatedClass('App\\Models\\User', 'invoices'));
    }

    private function assertServiceLayer(SymbolTable $table): void
    {
        $vuln = $table->getClass('App\Http\Controllers\Vuln\DownloadController');
        $safe = $table->getClass('App\Http\Controllers\Safe\DownloadController');
        self::assertNotNull($vuln);
        self::assertNotNull($safe);
        self::assertStringEndsWith('DownloadService', (string) $vuln->properties['downloads']->type);
        self::assertStringEndsWith('DownloadRepository', (string) $safe->properties['downloads']->type);
    }
}
