<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Output;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Output\SafeWriter;

final class SafeWriterTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir().'/semsec-safe-writer-'.bin2hex(random_bytes(4));
        mkdir($this->dir, 0777, true);
    }

    protected function tearDown(): void
    {
        exec('rm -rf '.escapeshellarg($this->dir));
    }

    public function testWritesAndReplacesAtomically(): void
    {
        $path = $this->dir.'/report.txt';
        SafeWriter::write($path, 'one');
        SafeWriter::write($path, 'two');

        self::assertSame('two', file_get_contents($path));
        self::assertSame(['report.txt'], array_values(array_diff(scandir($this->dir) ?: [], ['.', '..'])), 'no temp file left behind');
    }

    public function testUnwritableParentLeavesNoTempFileAnywhere(): void
    {
        if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
            self::markTestSkipped('root ignores directory permissions');
        }
        $locked = $this->dir.'/locked';
        mkdir($locked, 0555);
        $before = glob(sys_get_temp_dir().'/.semantic-sec-*') ?: [];
        try {
            SafeWriter::write($locked.'/report.txt', 'x');
            self::fail('expected a RuntimeException');
        } catch (\RuntimeException $e) {
            self::assertStringContainsString($locked, $e->getMessage());
        } finally {
            chmod($locked, 0755);
        }

        self::assertSame($before, glob(sys_get_temp_dir().'/.semantic-sec-*') ?: [], 'no temp file in the system temp dir');
        self::assertSame([], array_values(array_diff(scandir($locked) ?: [], ['.', '..'])));
    }

    public function testFailedRenameRemovesTheTempFile(): void
    {
        $path = $this->dir.'/report.txt';
        SafeWriter::write($path, 'ok');
        // A directory where the target should be makes the final checks refuse after the temp file exists.
        unlink($path);
        mkdir($path);
        try {
            SafeWriter::write($path, 'x');
            self::fail('expected a RuntimeException');
        } catch (\RuntimeException) {
        }

        self::assertSame(['report.txt'], array_values(array_diff(scandir($this->dir) ?: [], ['.', '..'])));
    }

    public function testCreatesMissingParent(): void
    {
        SafeWriter::write($this->dir.'/a/b/report.txt', 'x');

        self::assertSame('x', file_get_contents($this->dir.'/a/b/report.txt'));
    }

    public function testSymlinkTargetRefused(): void
    {
        file_put_contents($this->dir.'/victim', 'keep');
        symlink($this->dir.'/victim', $this->dir.'/report.txt');

        $this->assertRefused($this->dir.'/report.txt', 'is a symlink');
        self::assertSame('keep', file_get_contents($this->dir.'/victim'));
        self::assertTrue(is_link($this->dir.'/report.txt'));
    }

    public function testDanglingSymlinkTargetRefused(): void
    {
        symlink($this->dir.'/nowhere', $this->dir.'/report.txt');

        $this->assertRefused($this->dir.'/report.txt', 'is a symlink');
        self::assertFileDoesNotExist($this->dir.'/nowhere');
    }

    public function testDirectoryTargetRefused(): void
    {
        mkdir($this->dir.'/report.txt');

        $this->assertRefused($this->dir.'/report.txt', 'is not a regular file');
    }

    public function testSymlinkParentRefused(): void
    {
        mkdir($this->dir.'/real');
        symlink($this->dir.'/real', $this->dir.'/link');

        $this->assertRefused($this->dir.'/link/report.txt', 'is a symlink');
        self::assertFileDoesNotExist($this->dir.'/real/report.txt');
    }

    public function testSymlinkedAncestorRefused(): void
    {
        mkdir($this->dir.'/real/sub', 0777, true);
        symlink($this->dir.'/real', $this->dir.'/plink');

        $this->assertRefused($this->dir.'/plink/sub/f', 'is a symlink');
        $this->assertRefused($this->dir.'/plink/new/f', 'is a symlink');
        self::assertFileDoesNotExist($this->dir.'/real/sub/f');
        self::assertDirectoryDoesNotExist($this->dir.'/real/new');
    }

    public function testParentThatIsAFileRefused(): void
    {
        file_put_contents($this->dir.'/file', 'x');

        $this->assertRefused($this->dir.'/file/g/f', 'is not a directory');
    }

    public function testOverwriteKeepsMode(): void
    {
        file_put_contents($this->dir.'/r.txt', 'old');
        chmod($this->dir.'/r.txt', 0600);
        SafeWriter::write($this->dir.'/r.txt', 'new');
        clearstatcache();

        self::assertSame('new', file_get_contents($this->dir.'/r.txt'));
        self::assertSame(0600, fileperms($this->dir.'/r.txt') & 0777);
    }

    public function testNewFileIs0644WithinUmask(): void
    {
        $old = umask(0022);
        try {
            SafeWriter::write($this->dir.'/a.txt', 'x');
            umask(0077);
            SafeWriter::write($this->dir.'/b.txt', 'x');
        } finally {
            umask($old);
        }
        clearstatcache();

        self::assertSame(0644, fileperms($this->dir.'/a.txt') & 0777);
        self::assertSame(0600, fileperms($this->dir.'/b.txt') & 0777);
    }

    public function testCheckValidatesWithoutWriting(): void
    {
        SafeWriter::check($this->dir.'/x/y/r.txt');
        self::assertDirectoryDoesNotExist($this->dir.'/x');

        symlink($this->dir.'/victim', $this->dir.'/link');
        try {
            SafeWriter::check($this->dir.'/link');
            self::fail('expected a RuntimeException');
        } catch (\RuntimeException $e) {
            self::assertStringContainsString('is a symlink', $e->getMessage());
        }
    }

    public function testEmptyPathRefused(): void
    {
        $this->assertRefused('', 'empty');
    }

    private function assertRefused(string $path, string $message): void
    {
        try {
            SafeWriter::write($path, 'evil');
            self::fail('expected a RuntimeException');
        } catch (\RuntimeException $e) {
            self::assertStringContainsString($message, $e->getMessage());
        }
    }
}
