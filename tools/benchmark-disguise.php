#!/usr/bin/env php
<?php

declare(strict_types=1);

use TusharKhan\SemanticSec\Tests\Support\Benchmark\Disguise;

// Dev only (export-ignored): writes the competitor's disguised copy of benchmark/ and the map back to the original.
require __DIR__.'/../vendor/autoload.php';

$args = array_values(array_filter(array_slice($argv, 1), static fn (string $a): bool => ! str_starts_with($a, '--seed=')));
$seed = Disguise::SEED;
foreach ($argv as $arg) {
    if (str_starts_with($arg, '--seed=')) {
        $seed = (int) substr($arg, 7);
    }
}
if (count($args) !== 2 || ! class_exists(Disguise::class)) {
    fwrite(STDERR, "usage: tools/benchmark-disguise.php <out-dir> <disguise-map.json> [--seed=N]\nNeeds the dev autoloader. Keep the map out of the copy and out of git.\n");
    exit(2);
}
[$out, $mapPath] = $args;
if (str_starts_with((string) realpath(dirname($mapPath)).'/', rtrim($out, '/').'/')) {
    fwrite(STDERR, "the map must not sit inside the copy\n");
    exit(2);
}

try {
    $map = Disguise::run(dirname(__DIR__).'/benchmark', $out, $seed);
    Disguise::writeMap($map, $mapPath);
} catch (RuntimeException $e) {
    fwrite(STDERR, $e->getMessage()."\n");
    exit(1);
}

foreach ($map['apps'] as $app => $entry) {
    printf(
        "%s: %d classes renamed, %d route keys, vulnerable variants Alpha %d / Beta %d, %d comments stripped\n",
        $app,
        count($entry['classes']),
        count($entry['routes']),
        $entry['vulnerableVariantsByLetter']['Alpha'],
        $entry['vulnerableVariantsByLetter']['Beta'],
        count($entry['strippedComments']),
    );
}
printf("seed %d; copy in %s, map in %s\n", $seed, $out, $mapPath);
