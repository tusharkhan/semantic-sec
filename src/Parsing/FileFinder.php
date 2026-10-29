<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Parsing;

final class FileFinder
{
    public const ALWAYS_EXCLUDED = ['vendor', 'node_modules', 'storage', 'bootstrap/cache', '.git', '.semantic-sec'];

    /**
     * @param  list<string>  $excludeGlobs
     * @return list<string>
     */
    public function find(string $root, array $excludeGlobs = []): array
    {
        $base = rtrim($root, '/');
        if ($base === '' || ! is_dir($base)) {
            throw new \InvalidArgumentException("Project root not found: {$root}");
        }

        $prefix = strlen($base) + 1;
        $filter = new \RecursiveCallbackFilterIterator(
            new \RecursiveDirectoryIterator($base, \FilesystemIterator::SKIP_DOTS),
            function (\SplFileInfo $file) use ($prefix): bool {
                if ($file->isLink()) {
                    return false;
                }

                // Prune excluded directories before descending.
                return ! $file->isDir() || ! $this->isAlwaysExcluded(substr($file->getPathname(), $prefix));
            },
        );

        $paths = [];
        /** @var \SplFileInfo $file */
        foreach (new \RecursiveIteratorIterator($filter, \RecursiveIteratorIterator::LEAVES_ONLY, \RecursiveIteratorIterator::CATCH_GET_CHILD) as $file) {
            if (! $file->isFile() || $file->getExtension() !== 'php') {
                continue;
            }
            $relative = str_replace('\\', '/', substr($file->getPathname(), $prefix));
            if ($this->matchesGlob($relative, $excludeGlobs)) {
                continue;
            }
            $paths[] = $relative;
        }

        sort($paths, SORT_STRING);

        return $paths;
    }

    private function isAlwaysExcluded(string $relative): bool
    {
        foreach (self::ALWAYS_EXCLUDED as $entry) {
            if ($relative === $entry || str_starts_with($relative, $entry.'/')) {
                return true;
            }
        }

        return false;
    }

    /** @param list<string> $globs */
    private function matchesGlob(string $relative, array $globs): bool
    {
        foreach ($globs as $glob) {
            if (fnmatch($glob, $relative)) {
                return true;
            }
        }

        return false;
    }
}
