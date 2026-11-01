<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Benchmark;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\CompetitorScope;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\DisguiseMap;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\ExpectedCases;

/** A case counts for the competitor only when its files were in the copy it reviewed. */
final class CompetitorScopeTest extends TestCase
{
    private const FIXTURE = __DIR__.'/../../Fixtures/benchmark/competitor';

    public function testCasesWhoseFilesExistInTheSourceRan(): void
    {
        $scope = new CompetitorScope(DisguiseMap::load(self::FIXTURE.'/disguise-map.json'), self::FIXTURE.'/bench');

        self::assertSame(['plain-idor', 'policy-accept'], self::ran($scope));
    }

    public function testWithoutASourceTheMapFileListDecides(): void
    {
        $scope = new CompetitorScope(DisguiseMap::load(self::FIXTURE.'/disguise-map.json'), null);

        self::assertSame(['plain-idor', 'policy-accept'], self::ran($scope));
    }

    public function testAMissingDisguisedFileMeansNotRun(): void
    {
        $dir = sys_get_temp_dir().'/semsec-scope-'.bin2hex(random_bytes(4));
        mkdir($dir.'/app-a/app/Http/Controllers/Alpha', 0o777, true);
        mkdir($dir.'/app-a/app/Http/Controllers/Beta', 0o777, true);
        touch($dir.'/app-a/app/Http/Controllers/Alpha/ItemController.php');
        touch($dir.'/app-a/app/Http/Controllers/Beta/ItemController.php');
        try {
            self::assertSame(['plain-idor'], self::ran(new CompetitorScope(DisguiseMap::load(self::FIXTURE.'/disguise-map.json'), $dir)));
        } finally {
            exec('rm -rf '.escapeshellarg($dir));
        }
    }

    /** @return list<string> */
    private static function ran(CompetitorScope $scope): array
    {
        $ids = [];
        foreach (ExpectedCases::load(ScorerTest::YAML) as $case) {
            if ($scope->ran($case)) {
                $ids[] = $case->id;
            }
        }

        return $ids;
    }
}
