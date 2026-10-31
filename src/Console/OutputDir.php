<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Console;

/** Guards every write under <root>/.semantic-sec: no symlinked directory, nothing that resolves outside the root. */
final class OutputDir
{
    // Creates each missing level one at a time and returns the absolute dir; an existing dir is kept as is.
    public static function prepare(string $root, string $relative): string
    {
        return self::walk($root, $relative, true);
    }

    // Same refusals as prepare(), without creating anything.
    public static function check(string $root, string $relative): void
    {
        self::walk($root, $relative, false);
    }

    private static function walk(string $root, string $relative, bool $create): string
    {
        $parts = explode('/', $relative);
        if ($relative === '' || str_starts_with($relative, '/') || array_intersect($parts, ['', '.', '..']) !== []) {
            throw new \RuntimeException('Invalid output directory: '.$relative);
        }
        $realRoot = realpath($root);
        if ($realRoot === false) {
            throw new \RuntimeException('Project root does not exist: '.$root);
        }
        $label = end($parts).' output';
        $path = $root;
        foreach ($parts as $part) {
            $path .= '/'.$part;
            if (is_link($path)) {
                throw new \RuntimeException(sprintf('Refusing to write %s: %s is a symlink', $label, $path));
            }
            if (file_exists($path)) {
                $real = realpath($path);
                if (! is_dir($path) || $real === false || ! str_starts_with($real.'/', $realRoot.'/')) {
                    throw new \RuntimeException(sprintf('Refusing to write %s: %s is not a directory inside %s', $label, $path, $realRoot));
                }
            }
            if ($create && ! is_dir($path) && ! @mkdir($path, 0777) && ! is_dir($path)) {
                throw new \RuntimeException('Cannot create '.$path);
            }
        }

        return $path;
    }
}
