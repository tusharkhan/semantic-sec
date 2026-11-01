<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support\Benchmark;

use Random\Engine\Mt19937;
use Random\Randomizer;
use TusharKhan\SemanticSec\Console\MapBuilder;
use TusharKhan\SemanticSec\Framework\Laravel\RouteEntry;

/** Copies the benchmark apps for the competitor with Vuln/Safe renamed to Alpha/Beta per class pair (M8 Task 5). */
final class Disguise
{
    public const SEED = 20261101;

    public const LETTERS = ['Alpha', 'Beta'];

    // Any of these in the copy fails the run; the M1 suppression comment is part of its case and allowed.
    public const LEAK = '/vuln|(?<![a-z])safe(?![a-z])|insecure|exploit|\bidor\b|benchmark|expected\.yaml/i';

    private const SIDE = '/\\\\(Vuln|Safe)\\\\/';

    /**
     * @param list<string>|null $apps default BenchmarkCorpus::APPS
     *
     * @return array<string, mixed> the disguise map; write it with writeMap(), never into the copy
     */
    public static function run(string $corpus, string $out, int $seed = self::SEED, ?array $apps = null): array
    {
        $apps ??= \TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus::APPS;
        if (file_exists($out) && array_diff((array) scandir($out), ['.', '..']) !== []) {
            throw new \RuntimeException("output directory is not empty: {$out}");
        }
        $cases = ExpectedCases::load((string) file_get_contents($corpus.'/expected.yaml'));
        $random = new Randomizer(new Mt19937($seed));
        $map = ['version' => 1, 'seed' => $seed, 'letters' => self::LETTERS, 'root' => $out, 'apps' => []];
        foreach ($apps as $app) {
            $map['apps'][$app] = self::app($corpus.'/'.$app, $out.'/'.$app, array_values(array_filter($cases, static fn (BenchmarkCase $c): bool => $c->app === $app)), $random);
        }

        return $map;
    }

    // Stores root relative to the map file when the copy sits beside it, so the pair can be mounted anywhere.
    /** @param array<string, mixed> $map */
    public static function writeMap(array $map, string $path): void
    {
        $root = is_string($map['root'] ?? null) ? $map['root'] : '';
        $dir = (string) realpath(dirname($path) === '' ? '.' : dirname($path));
        $real = (string) realpath($root);
        if ($dir !== '' && $real !== '' && str_starts_with($real, $dir.'/')) {
            $map['root'] = substr($real, strlen($dir) + 1);
        }
        if (file_put_contents($path, json_encode($map, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)."\n") === false) {
            throw new \RuntimeException("cannot write {$path}");
        }
    }

    /**
     * @param list<BenchmarkCase> $cases
     *
     * @return array<string, mixed>
     */
    private static function app(string $source, string $target, array $cases, Randomizer $random): array
    {
        $files = self::files($source);
        $sides = [];
        foreach ($files as $file) {
            $class = self::classOf($file);
            if ($class !== null && preg_match(self::SIDE, $class, $m) === 1) {
                $sides[$class] = $m[1];
            }
        }
        $letters = self::letters($sides, $cases, $random);

        $classes = $paths = $stripped = [];
        foreach ($files as $file) {
            $code = (string) file_get_contents($source.'/'.$file);
            $class = self::classOf($file);
            $path = $file;
            if ($class !== null && isset($letters[$class])) {
                $path = self::rename($file, $letters[$class], '/');
                $classes[self::rename($class, $letters[$class], '\\')] = $class;
                $paths[$path] = $file;
            }
            if (str_ends_with($file, '.php')) {
                foreach ($letters as $fqn => $letter) {
                    $code = str_replace($fqn, self::rename($fqn, $letter, '\\'), $code);
                }
                if ($class !== null && isset($letters[$class])) {
                    $code = (string) preg_replace('/^namespace (.*)\\\\(Vuln|Safe);$/m', 'namespace $1\\\\'.$letters[$class].';', $code);
                }
                if (str_starts_with($file, 'routes/')) {
                    $code = self::routes($code, $letters);
                }
                [$code, $removed] = self::stripHints($code);
                foreach ($removed as $line => $text) {
                    $stripped[] = ['file' => $file, 'line' => $line, 'text' => $text];
                }
            }
            if ($file === 'composer.json') {
                $code = (string) preg_replace('#"name": "benchmark/#', '"name": "acme/', $code);
            }
            self::write($target.'/'.$path, $code);
            self::assertNoLeak($target.'/'.$path, $code);
        }

        $vulnerable = array_fill_keys(self::LETTERS, 0);
        foreach ($cases as $case) {
            $class = explode('::', $case->vulnerable->symbol)[0];
            if (isset($letters[$class])) {
                $vulnerable[$letters[$class]]++;
            }
        }
        ksort($classes);
        ksort($paths);

        return [
            'classes' => $classes,
            'files' => $paths,
            'routes' => self::routeMap($source, $target, $classes),
            'vulnerableVariantsByLetter' => $vulnerable,
            'strippedComments' => $stripped,
        ];
    }

    /**
     * One letter per class; classes joined by a case or by sharing a short name get opposite letters on opposite sides.
     *
     * @param array<string, string> $sides class => Vuln|Safe
     * @param list<BenchmarkCase> $cases
     *
     * @return array<string, string> class => Alpha|Beta
     */
    private static function letters(array $sides, array $cases, Randomizer $random): array
    {
        ksort($sides);
        $parent = array_combine(array_keys($sides), array_keys($sides));
        $find = static function (string $c) use (&$parent): string {
            while ($parent[$c] !== $c) {
                $c = $parent[$c];
            }

            return $c;
        };
        $join = static function (string $a, string $b) use (&$parent, $find): void {
            $ra = $find($a);
            $rb = $find($b);
            if ($ra !== $rb) {
                $parent[max($ra, $rb)] = min($ra, $rb);
            }
        };
        foreach (array_keys($sides) as $class) {
            $twin = (string) preg_replace(self::SIDE, $sides[$class] === 'Vuln' ? '\\Safe\\' : '\\Vuln\\', $class);
            if (isset($sides[$twin])) {
                $join($class, $twin);
            }
        }
        foreach ($cases as $case) {
            $a = explode('::', $case->vulnerable->symbol)[0];
            $b = explode('::', $case->safe->symbol)[0];
            if (isset($sides[$a], $sides[$b]) && $sides[$a] !== $sides[$b]) {
                $join($a, $b);
            }
        }
        // Shuffled, then alternated: random per pair, yet neither letter ends up holding most vulnerable classes.
        $roots = array_values(array_unique(array_map($find, array_keys($sides))));
        $vulnLetter = [];
        foreach ($random->shuffleArray($roots) as $i => $root) {
            $vulnLetter[$root] = $i % 2;
        }
        $letters = [];
        foreach (array_keys($sides) as $class) {
            $v = $vulnLetter[$find($class)];
            $letters[$class] = self::LETTERS[$sides[$class] === 'Vuln' ? $v : 1 - $v];
        }

        return $letters;
    }

    /**
     * Rebuilds prefix('vuln') / prefix('safe') groups as alpha and beta, each route following its controller's letter.
     *
     * @param array<string, string> $letters
     */
    private static function routes(string $code, array $letters): string
    {
        $short = [];
        foreach ($letters as $fqn => $letter) {
            if (preg_match('/^App\\\\Http\\\\Controllers\\\\(Vuln|Safe)\\\\(\w+)$/', $fqn, $m) === 1) {
                $short[$m[1].'\\'.$m[2]] = $letter.'\\'.$m[2];
            }
        }
        $letterOf = static function (string $statement) use ($short): ?string {
            foreach ($short as $from => $to) {
                if (preg_match('/(?<![\w\\\\])'.preg_quote($from, '/').'(?![\w])/', $statement) === 1) {
                    return explode('\\', $to)[0];
                }
            }

            return null;
        };
        $relabel = static fn (string $text): string => (string) preg_replace_callback('/(?<![\w\\\\])(Vuln|Safe)\\\\(\w+)/', static fn (array $m): string => $short[$m[1].'\\'.$m[2]] ?? $m[0], $text);

        $lines = explode("\n", $code);
        $out = [];
        $buckets = [];
        $groupAt = null;
        $indent = '';
        for ($i = 0; $i < count($lines); $i++) {
            $line = $lines[$i];
            if (preg_match("/^(\s*)Route::prefix\('(vuln|safe)'\)->group\(function \(\) \{\s*$/", $line, $m) === 1) {
                $indent = $m[1];
                $groupAt ??= count($out);
                $statement = '';
                for ($i++; $i < count($lines) && $lines[$i] !== $indent.'});'; $i++) {
                    if (trim($lines[$i]) === '') {
                        continue;
                    }
                    $statement .= $lines[$i]."\n";
                    if (str_ends_with(rtrim($lines[$i]), ';')) {
                        $letter = $letterOf($statement) ?? throw new \RuntimeException('route without a Vuln/Safe controller: '.trim($statement));
                        $buckets[$letter][] = rtrim($relabel($statement), "\n");
                        $statement = '';
                    }
                }
                if (trim((string) end($out)) === '' && $groupAt < count($out)) {
                    array_pop($out);
                }

                continue;
            }
            if (preg_match("/Route::resource\('(vuln|safe)\//", $line) === 1) {
                $letter = $letterOf($line) ?? throw new \RuntimeException('resource without a Vuln/Safe controller: '.trim($line));
                $lower = strtolower($letter);
                $line = (string) preg_replace(["/\('(vuln|safe)\//", "/->names\('(vuln|safe)\./"], ["('{$lower}/", "->names('{$lower}."], $relabel($line));
                $out[] = $line;
                continue;
            }
            if (preg_match('/^use App\\\\Http\\\\Controllers\\\\(Vuln|Safe);$/', $line) === 1) {
                if (! in_array('use App\\Http\\Controllers\\'.self::LETTERS[0].';', $out, true)) {
                    foreach (self::LETTERS as $letter) {
                        $out[] = 'use App\\Http\\Controllers\\'.$letter.';';
                    }
                }
                continue;
            }
            $out[] = $line;
        }
        if ($groupAt !== null) {
            $groups = [];
            foreach (self::LETTERS as $n => $letter) {
                $statements = $buckets[$letter] ?? [];
                sort($statements);
                if ($statements === []) {
                    continue;
                }
                if ($n > 0 && $groups !== []) {
                    $groups[] = '';
                }
                $groups[] = $indent."Route::prefix('".strtolower($letter)."')->group(function () {";
                array_push($groups, ...$statements);
                $groups[] = $indent.'});';
            }
            array_splice($out, $groupAt, 0, $groups);
        }

        return self::sortUses(self::sortResources(implode("\n", $out)));
    }

    // The import block is re-sorted so the renamed lines do not stand out.
    private static function sortUses(string $code): string
    {
        return (string) preg_replace_callback('/(?:^use [^\n]+;\n)+/m', static function (array $m): string {
            $lines = explode("\n", rtrim($m[0], "\n"));
            sort($lines);

            return implode("\n", $lines)."\n";
        }, $code, 1);
    }

    // Adjacent resource lines are sorted so alpha does not always follow the old vuln-first order.
    private static function sortResources(string $code): string
    {
        return (string) preg_replace_callback('/(?:^[ \t]*Route::resource\((?:\'alpha|\'beta)[^\n]*\n)+/m', static function (array $m): string {
            $lines = explode("\n", rtrim($m[0], "\n"));
            sort($lines);

            return implode("\n", $lines)."\n";
        }, $code);
    }

    /**
     * Removes comments that hint at the answer, keeping each comment's line count so nothing below it moves.
     *
     * @return array{0: string, 1: array<int, string>} the code and the removed comments by line
     */
    private static function stripHints(string $code): array
    {
        $out = '';
        $removed = [];
        $line = 1;
        foreach (\PhpToken::tokenize($code) as $token) {
            $text = $token->text;
            if ($token->is([T_COMMENT, T_DOC_COMMENT]) && preg_match(self::LEAK, $text) === 1 && ! str_contains($text, '@semantic-sec-ignore')) {
                $removed[$line] = $text;
                $text = str_repeat("\n", substr_count($text, "\n"));
            }
            $out .= $text;
            $line += substr_count($token->text, "\n");
        }

        return [$out, $removed];
    }

    /**
     * Route keys of the disguised copy against the original, matched by action and verb.
     *
     * @param array<string, string> $classes disguised => original
     *
     * @return array<string, string>
     */
    private static function routeMap(string $source, string $target, array $classes): array
    {
        $original = (new MapBuilder())->project($source, null, null)->map->routes;
        $disguised = (new MapBuilder())->project($target, null, null)->map->routes;
        if (count($original) !== count($disguised)) {
            throw new \RuntimeException(sprintf('%s: %d routes in the copy, %d in the original', basename($source), count($disguised), count($original)));
        }
        $key = static fn (RouteEntry $r, ?string $class): string => implode('|', $r->methods).' '.($class ?? '').'::'.($r->action->method ?? '').' '.($r->action->isClosure() ? $r->uri : '');
        $byAction = [];
        foreach ($original as $route) {
            $k = $key($route, $route->action->class);
            $byAction[$k] = isset($byAction[$k]) ? throw new \RuntimeException("two routes share {$k}; the route map would be ambiguous") : $route;
        }
        $map = [];
        foreach ($disguised as $route) {
            $class = $route->action->class === null ? null : ($classes[$route->action->class] ?? $route->action->class);
            $match = $byAction[$key($route, $class)] ?? throw new \RuntimeException('no original route for '.$route->key());
            foreach ($route->methods as $i => $verb) {
                $map[$verb.' '.$route->uri] = $match->methods[$i].' '.$match->uri;
            }
        }
        ksort($map);

        return $map;
    }

    private static function rename(string $name, string $letter, string $separator): string
    {
        $quoted = preg_quote($separator, '#');

        return (string) preg_replace('#'.$quoted.'(Vuln|Safe)'.$quoted.'#', $separator.$letter.$separator, $name, 1);
    }

    // app/X/Y.php declares App\X\Y in every benchmark app.
    private static function classOf(string $file): ?string
    {
        if (! str_starts_with($file, 'app/') || ! str_ends_with($file, '.php')) {
            return null;
        }

        return 'App\\'.str_replace('/', '\\', substr($file, 4, -4));
    }

    private static function assertNoLeak(string $path, string $code): void
    {
        foreach (explode("\n", $code) as $n => $line) {
            if (preg_match(self::LEAK, $line) === 1 && ! str_contains($line, '@semantic-sec-ignore')) {
                throw new \RuntimeException(sprintf('%s:%d still names the answer: %s', $path, $n + 1, trim($line)));
            }
        }
    }

    private static function write(string $path, string $code): void
    {
        if (! is_dir(dirname($path)) && ! mkdir(dirname($path), 0o777, true)) {
            throw new \RuntimeException('cannot create '.dirname($path));
        }
        if (file_put_contents($path, $code) === false) {
            throw new \RuntimeException("cannot write {$path}");
        }
    }

    /** @return list<string> relative paths, sorted */
    private static function files(string $dir): array
    {
        $out = [];
        foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS)) as $file) {
            $out[] = substr((string) $file, strlen($dir) + 1);
        }
        sort($out);

        return $out;
    }
}
