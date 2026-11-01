<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support\Benchmark;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use TusharKhan\SemanticSec\Config\Config;
use TusharKhan\SemanticSec\Console\Application;
use TusharKhan\SemanticSec\Console\Commands\AnalyzeCommand;
use TusharKhan\SemanticSec\Llm\ClientFactory;
use TusharKhan\SemanticSec\Llm\ClientInterface;
use TusharKhan\SemanticSec\Llm\Http\Cassette;
use TusharKhan\SemanticSec\Llm\Http\CassetteHandler;
use TusharKhan\SemanticSec\Llm\SecurityPrompt;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;
use TusharKhan\SemanticSec\Tests\Support\NetworkTrap;

/** Runs map, the dry run and `analyze --format json` on a temp copy of one benchmark app, replaying or recording its cassette. */
final class Runner
{
    public const KEY_ENV = 'ANTHROPIC_API_KEY';

    // Same flags for record and replay, so body-matched requests line up.
    private const ANALYZE = ['--no-cache' => true, '--no-baseline' => true, '--level' => 'low', '--min-confidence' => 'low', '--provider' => 'anthropic', '--format' => 'json'];

    public const PREFIX = 'benchmark';

    public const DISGUISED_PREFIX = 'benchmark-disguised';

    // $source holds the apps (default benchmark/); $prefix names the cassettes, so disguised runs never touch the originals.
    public function __construct(private readonly string $cassetteDir, private readonly ?string $source = null, private readonly string $prefix = self::PREFIX)
    {
    }

    public function cassette(string $app): string
    {
        return rtrim($this->cassetteDir, '/')."/{$this->prefix}-{$app}.json";
    }

    /**
     * @param 'replay'|'record' $mode
     * @param callable|null $inner record mode's real handler; null is cURL (live)
     * @param string $key the API key; scrubbed from recordings and checked against the output
     */
    public function run(string $app, string $mode, ?callable $inner, #[\SensitiveParameter] string $key, ?string $budget = null): AppRun
    {
        $cassette = $this->cassette($app);
        if ($mode === 'replay' && ! is_file($cassette)) {
            throw new \RuntimeException("replay cassette missing: {$cassette}; the controller records it with bin/benchmark --live");
        }
        $base = sys_get_temp_dir().'/semsec-bench-'.bin2hex(random_bytes(4));
        try {
            $dry = $this->copy($app, $base.'/dry');
            $root = $this->copy($app, $base.'/run');
            $dryRun = self::json(new AnalyzeCommand(), ['--project-root' => $dry, '--dry-run' => true, '--format' => 'json'], "dry run of {$app}", [0]);
            $map = self::json((new Application())->find('map'), ['--project-root' => $dry, '--format' => 'json'], "map of {$app}", [0]);

            $handler = new CassetteHandler(Cassette::load($cassette), $mode, $inner, secrets: [$key], match: 'body');
            $command = new AnalyzeCommand(static fn (Config $c): ClientInterface => ClientFactory::create($c, $handler));
            $args = ['--project-root' => $root, ...self::ANALYZE];
            if ($budget !== null) {
                $args['--budget'] = $budget;
            }
            if ($mode === 'replay') {
                NetworkTrap::install();
            }
            try {
                $analyze = self::json($command, $args, "analyze of {$app}", [0, 1, 2, 3], $key);
            } finally {
                $calls = $mode === 'replay' ? NetworkTrap::uninstall() : [];
            }
            if ($calls !== []) {
                throw new \RuntimeException("replay of {$app} touched the network");
            }
            self::checkComplete($app, $mode, $analyze, $handler);
        } finally {
            exec('rm -rf '.escapeshellarg($base));
        }
        $usage = CassetteUsage::read($cassette);

        return new AppRun($app, $analyze, $map, $dryRun, $usage['usage'], $usage['models'], $usage['requests']);
    }

    // A replay with a failed request or an unused interaction means the cassette no longer matches the payloads.
    /** @param array<mixed> $analyze */
    private static function checkComplete(string $app, string $mode, array $analyze, CassetteHandler $handler): void
    {
        $summary = is_array($analyze['summary'] ?? null) ? $analyze['summary'] : [];
        $failed = is_int($summary['failed'] ?? null) ? $summary['failed'] : 0;
        $unsent = is_int($summary['unsent'] ?? null) ? $summary['unsent'] : 0;
        $stale = $mode === 'replay' ? sprintf('; the cassette is stale (a changed selection or prompt v%s changes request bodies), so the controller must re-record it with bin/benchmark --live', SecurityPrompt::VERSION) : '';
        if ($failed > 0 || $unsent > 0) {
            throw new \RuntimeException("analyze of {$app}: {$failed} requests failed and {$unsent} payloads went unsent{$stale}");
        }
        try {
            $handler->assertExhausted();
        } catch (\LogicException $e) {
            throw new \RuntimeException($e->getMessage().$stale, 0, $e);
        }
    }

    private function copy(string $app, string $dir): string
    {
        if (! is_dir($dir) && ! mkdir($dir, 0o777, true)) {
            throw new \RuntimeException("cannot create {$dir}");
        }
        exec('cp -R '.escapeshellarg(($this->source ?? BenchmarkCorpus::root()).'/'.$app).' '.escapeshellarg($dir.'/'.$app), $out, $code);
        if ($code !== 0) {
            throw new \RuntimeException("cannot copy {$app} to {$dir}");
        }

        return $dir.'/'.$app;
    }

    /**
     * @param array<string, mixed> $args
     * @param list<int> $okExits
     *
     * @return array<mixed>
     */
    private static function json(Command $command, array $args, string $what, array $okExits, #[\SensitiveParameter] ?string $key = null): array
    {
        $tester = new CommandTester($command);
        $exit = $tester->execute($args, ['capture_stderr_separately' => true]);
        $stdout = $tester->getDisplay();
        $stderr = $tester->getErrorOutput();
        if ($key !== null && $key !== '' && (str_contains($stdout, $key) || str_contains($stderr, $key))) {
            throw new \RuntimeException("{$what}: the API key appeared in the output; nothing was kept");
        }
        if (! in_array($exit, $okExits, true)) {
            throw new \RuntimeException("{$what} exited {$exit}: ".trim($stderr));
        }
        $data = json_decode($stdout, true);
        if (! is_array($data)) {
            throw new \RuntimeException("{$what} exited {$exit} without JSON: ".trim($stderr));
        }

        return $data;
    }
}
