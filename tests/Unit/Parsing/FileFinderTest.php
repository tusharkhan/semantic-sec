<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Parsing;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Parsing\FileFinder;

final class FileFinderTest extends TestCase
{
    private string $root;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir().'/ss-ff-'.bin2hex(random_bytes(6));
        mkdir($this->root, 0777, true);
    }

    protected function tearDown(): void
    {
        $this->remove($this->root);
    }

    public function testFindsOnlyPhpFilesSorted(): void
    {
        $this->touch('app/B.php');
        $this->touch('app/A.php');
        $this->touch('app/readme.md');
        $this->touch('app/Upper.PHP');

        self::assertSame(['app/A.php', 'app/B.php'], (new FileFinder())->find($this->root));
    }

    public function testAlwaysExcludedDirectoriesAreSkipped(): void
    {
        foreach (['vendor/a.php', 'node_modules/b.php', 'storage/c.php', 'bootstrap/cache/d.php', 'storagebox/e.php', 'bootstrap/app.php'] as $f) {
            $this->touch($f);
        }

        self::assertSame(
            ['bootstrap/app.php', 'storagebox/e.php'],
            (new FileFinder())->find($this->root.'/'),
        );
    }

    public function testExcludeGlobsApply(): void
    {
        $this->touch('app/Legacy/Old/X.php');
        $this->touch('app/Keep.php');

        self::assertSame(['app/Keep.php'], (new FileFinder())->find($this->root, ['app/Legacy/*']));
    }

    public function testSymlinkLoopDoesNotHangOrDuplicate(): void
    {
        $this->touch('app/A.php');
        symlink('..', $this->root.'/app/loop');
        symlink($this->root.'/app/A.php', $this->root.'/app/link.php');

        $paths = (new FileFinder())->find($this->root);

        self::assertSame(['app/A.php'], $paths);
    }

    public function testMissingRootThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Project root not found: /nope/missing');

        (new FileFinder())->find('/nope/missing');
    }

    private function touch(string $rel): void
    {
        $path = $this->root.'/'.$rel;
        if (! is_dir(dirname($path))) {
            mkdir(dirname($path), 0777, true);
        }
        file_put_contents($path, '<?php');
    }

    private function remove(string $path): void
    {
        if (is_link($path) || is_file($path)) {
            unlink($path);

            return;
        }
        foreach (scandir($path) ?: [] as $entry) {
            if ($entry !== '.' && $entry !== '..') {
                $this->remove($path.'/'.$entry);
            }
        }
        rmdir($path);
    }
}
