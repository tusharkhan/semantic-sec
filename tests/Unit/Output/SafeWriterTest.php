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
