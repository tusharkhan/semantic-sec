<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Output;

/** Writes a report or baseline file: never through a symlink, never over a directory, atomically via temp-then-rename. */
final class SafeWriter
{
    public static function write(string $path, string $contents): void
    {
        if ($path === '' || str_contains($path, "\0")) {
            throw new \RuntimeException('Refusing to write an empty or invalid path');
        }
        $parent = dirname($path);
        self::checkTarget($path);
        if (is_link($parent)) {
            throw new \RuntimeException(sprintf('Refusing to write %s: %s is a symlink', $path, $parent));
        }
        if (! is_dir($parent)) {
            if (file_exists($parent)) {
                throw new \RuntimeException(sprintf('Refusing to write %s: %s is not a directory', $path, $parent));
            }
            if (! @mkdir($parent, 0777, true) && ! is_dir($parent)) {
                throw new \RuntimeException('Cannot create '.$parent);
            }
        }

        $temp = @tempnam($parent, '.semantic-sec-');
        if ($temp === false || realpath(dirname($temp)) !== realpath($parent)) {
            throw new \RuntimeException('Cannot create a temporary file in '.$parent);
        }
        try {
            if (@file_put_contents($temp, $contents) !== strlen($contents)) {
                throw new \RuntimeException('Cannot write '.$path);
            }
            @chmod($temp, 0666 & ~umask());
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

    private static function checkTarget(string $path): void
    {
        if (is_link($path)) {
            throw new \RuntimeException(sprintf('Refusing to write %s: it is a symlink', $path));
        }
        if (file_exists($path) && ! is_file($path)) {
            throw new \RuntimeException(sprintf('Refusing to write %s: it is not a regular file', $path));
        }
    }
}
