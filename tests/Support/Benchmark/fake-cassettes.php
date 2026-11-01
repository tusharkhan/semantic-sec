<?php

declare(strict_types=1);

// Records benchmark-<app>.json cassettes from FakeAnthropicHandler into the given directory; no network, no key.

use TusharKhan\SemanticSec\Tests\Support\Benchmark\ExpectedCases;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\FakeAnthropicHandler;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\Runner;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;

require dirname(__DIR__, 3) . '/vendor/autoload.php';

$dir = $argv[1] ?? '';
if ($dir === '') {
    fwrite(STDERR, "usage: php tests/Support/Benchmark/fake-cassettes.php <dir> [app ...]\n");
    exit(2);
}
$apps = array_slice($argv, 2) ?: BenchmarkCorpus::APPS;
$key = 'fake-key';
putenv(Runner::KEY_ENV . '=' . $key);
$cases = ExpectedCases::load((string) file_get_contents(BenchmarkCorpus::root() . '/expected.yaml'));
$runner = new Runner($dir);
foreach ($apps as $app) {
    $handler = new FakeAnthropicHandler($cases);
    $runner->run($app, 'record', $handler, $key);
    fwrite(STDOUT, sprintf("%s: %d fake answers -> %s\n", $app, $handler->calls, $runner->cassette($app)));
}
