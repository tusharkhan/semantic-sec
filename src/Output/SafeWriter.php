<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Output;

/** Writes a report or baseline file: never through a symlink anywhere on its path, never over a directory, atomically via temp-then-rename. */
final class SafeWriter
{
    public static function write(string $path, string $contents): void
    {
        self::check($path);
        $parent = dirname($path);
        if (! is_dir($parent) && ! @mkdir($parent, 0777, true) && ! is_dir($parent)) {
            throw new \RuntimeException('Cannot create '.$parent);
        }
        // A symlink swapped in while the parent was being created is caught here.
        self::check($path);
        clearstatcache();
        $mode = is_file($path) ? fileperms($path) & 0777 : 0644 & ~umask();

        $temp = @tempnam($parent, '.semantic-sec-');
        if ($temp === false || realpath(dirname($temp)) !== realpath($parent)) {
            throw new \RuntimeException('Cannot create a temporary file in '.$parent);
        }
        try {
            if (@file_put_contents($temp, $contents) !== strlen($contents) || ! @chmod($temp, $mode)) {
                throw new \RuntimeException('Cannot write '.$path);
            }
            // Re-checked just before the rename, which replaces a link itself and never follows it.
            self::checkTarget($path);
            if (! @rename($temp, $path)) {
                throw new \RuntimeException('Cannot write '.$path);
            }
        } finally {
            if (is_file($temp)) {
                @unlink($temp);
            }
        }
    }

    // Pre-flight: the same refusals as write(), creating and writing nothing.
    public static function check(string $path): void
    {
        if ($path === '' || str_contains($path, "\0")) {
            throw new \RuntimeException('Refusing to write an empty or invalid path');
        }
        self::checkTarget($path);
        self::checkAncestors($path);
    }

    private static function checkTarget(string $path): void
    {
        if (is_link($path)) {
            throw new \RuntimeException(sprintf('Refusing to write %s: it is a symlink', $path));
        }
        if (file_exists($path) && ! is_file($path)) {
            throw new \RuntimeException(sprintf('Refusing to write %s: it is not a regular file', $path));
        }
    }

    // Walks every existing ancestor from the filesystem root down; none may be a symlink or a non-directory.
    private static function checkAncestors(string $path): void
    {
        $cwd = getcwd();
        $absolute = str_starts_with($path, '/') ? $path : ($cwd === false ? '.' : $cwd).'/'.$path;
        $parts = array_values(array_filter(explode('/', dirname($absolute)), static fn (string $p): bool => $p !== '' && $p !== '.'));
        $current = '';
        foreach ($parts as $part) {
            $current .= '/'.$part;
            if (is_link($current)) {
                throw new \RuntimeException(sprintf('Refusing to write %s: %s is a symlink', $path, $current));
            }
            if (! file_exists($current)) {
                return;
            }
            if (! is_dir($current)) {
                throw new \RuntimeException(sprintf('Refusing to write %s: %s is not a directory', $path, $current));
            }
        }
    }
}
