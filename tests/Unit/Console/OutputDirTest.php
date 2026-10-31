<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Console;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Console\OutputDir;

final class OutputDirTest extends TestCase
{
    private string $base;

    private string $root;

    private string $outside;

    protected function setUp(): void
    {
        $this->base = sys_get_temp_dir().'/semsec-outdir-'.bin2hex(random_bytes(4));
        $this->root = $this->base.'/project';
        mkdir($this->root, 0777, true);
        // A sibling dir outside the project, holding dry-run/sub/keep.txt and cache/sub/keep.txt.
        $this->outside = $this->base.'/outside';
        foreach (['dry-run', 'cache'] as $leaf) {
            mkdir($this->outside.'/'.$leaf.'/sub', 0777, true);
            file_put_contents($this->outside.'/'.$leaf.'/sub/keep.txt', 'keep');
        }
    }

    protected function tearDown(): void
    {
        exec('rm -rf '.escapeshellarg($this->base));
    }

    public function testCreatesNestedDirAndReturnsIt(): void
    {
        $dir = OutputDir::prepare($this->root, '.semantic-sec/cache');

        self::assertSame($this->root.'/.semantic-sec/cache', $dir);
        self::assertDirectoryExists($dir);
        self::assertFalse(is_link($dir));
    }

    public function testExistingDirIsKeptNotWiped(): void
    {
        mkdir($this->root.'/.semantic-sec/cache', 0777, true);
        file_put_contents($this->root.'/.semantic-sec/cache/a.json', 'x');

        OutputDir::prepare($this->root, '.semantic-sec/cache');

        self::assertSame('x', file_get_contents($this->root.'/.semantic-sec/cache/a.json'));
    }

    public function testCheckDoesNotCreate(): void
    {
        OutputDir::check($this->root, '.semantic-sec/dry-run');

        self::assertFileDoesNotExist($this->root.'/.semantic-sec');
    }

    public function testSymlinkedSemanticSecDirIsRefused(): void
    {
        symlink('../outside', $this->root.'/.semantic-sec');

        foreach (['.semantic-sec/dry-run', '.semantic-sec/cache'] as $relative) {
            $this->assertRefused($relative, 'is a symlink', true);
            $this->assertRefused($relative, 'is a symlink', false);
        }
    }

    public function testSymlinkedDryRunDirIsRefused(): void
    {
        mkdir($this->root.'/.semantic-sec');
        symlink('../../outside/dry-run', $this->root.'/.semantic-sec/dry-run');

        $this->assertRefused('.semantic-sec/dry-run', 'Refusing to write dry-run output: '.$this->root.'/.semantic-sec/dry-run is a symlink', true);
        $this->assertRefused('.semantic-sec/dry-run', 'is a symlink', false);
    }

    public function testSymlinkedCacheDirIsRefused(): void
    {
        mkdir($this->root.'/.semantic-sec');
        symlink('../../outside/cache', $this->root.'/.semantic-sec/cache');

        $this->assertRefused('.semantic-sec/cache', 'Refusing to write cache output: '.$this->root.'/.semantic-sec/cache is a symlink', true);
    }

    public function testFileInPlaceOfDirIsRefused(): void
    {
        file_put_contents($this->root.'/.semantic-sec', 'x');

        $this->assertRefused('.semantic-sec/cache', 'is not a directory inside '.realpath($this->root), true);
    }

    public function testDotDotAndAbsoluteRelativeAreRefused(): void
    {
        foreach (['../outside/cache', '/tmp/x', '', '.semantic-sec/../../outside', '.semantic-sec//cache'] as $relative) {
            try {
                OutputDir::prepare($this->root, $relative);
                self::fail('accepted '.$relative);
            } catch (\RuntimeException) {
            }
        }
        self::assertSame(['keep.txt'], array_values(array_diff(scandir($this->outside.'/cache/sub') ?: [], ['.', '..'])));
    }

    public function testMissingRootIsRefused(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Project root does not exist: '.$this->base.'/missing');

        OutputDir::prepare($this->base.'/missing', '.semantic-sec/cache');
    }

    private function assertRefused(string $relative, string $message, bool $create): void
    {
        try {
            $create ? OutputDir::prepare($this->root, $relative) : OutputDir::check($this->root, $relative);
            self::fail('no exception for '.$relative);
        } catch (\RuntimeException $e) {
            self::assertStringContainsString($message, $e->getMessage());
        }
        foreach (['dry-run', 'cache'] as $leaf) {
            self::assertSame('keep', file_get_contents($this->outside.'/'.$leaf.'/sub/keep.txt'));
            self::assertSame(['sub'], array_values(array_diff(scandir($this->outside.'/'.$leaf) ?: [], ['.', '..'])));
        }
    }
}
