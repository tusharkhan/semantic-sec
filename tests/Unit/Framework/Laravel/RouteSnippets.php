<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Framework\Laravel;

use TusharKhan\SemanticSec\Framework\Laravel\ConstantEvaluator;
use TusharKhan\SemanticSec\Framework\Laravel\RouteCollector;
use TusharKhan\SemanticSec\Framework\Laravel\RouteEntry;
use TusharKhan\SemanticSec\Framework\Laravel\RouteFile;
use TusharKhan\SemanticSec\Parsing\AstGenerator;
use TusharKhan\SemanticSec\Parsing\FileFinder;
use TusharKhan\SemanticSec\Parsing\ProjectParser;

/** Writes route-file snippets to a temp project and collects them. */
trait RouteSnippets
{
    /** @var list<string> */
    private array $dirs = [];

    protected function tearDown(): void
    {
        foreach ($this->dirs as $dir) {
            foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST) as $f) {
                $f->isDir() ? rmdir($f->getPathname()) : unlink($f->getPathname());
            }
            rmdir($dir);
        }
    }

    /** @return array{0: list<RouteEntry>, 1: list<string>} */
    private function collect(string $root, RouteFile $file): array
    {
        $parsed = (new ProjectParser(new FileFinder(), new AstGenerator()))->parse($root);

        return (new RouteCollector($parsed, new ConstantEvaluator()))->collect($file);
    }

    /**
     * @param  array<string, string>  $extra
     * @return array{0: list<RouteEntry>, 1: list<string>}
     */
    private function snippet(string $body, RouteFile $file = new RouteFile('routes/web.php', '', ['web'], null), array $extra = []): array
    {
        $dir = sys_get_temp_dir().'/ss-rc-'.bin2hex(random_bytes(4));
        mkdir($dir);
        $this->dirs[] = $dir;
        $files = ['routes/web.php' => "<?php\n\nuse Illuminate\\Support\\Facades\\Route;\nuse App\\Http\\Controllers\\FooController;\n\n".$body."\n"] + $extra;
        foreach ($files as $path => $code) {
            @mkdir(dirname($dir.'/'.$path), 0777, true);
            file_put_contents($dir.'/'.$path, $code);
        }

        return $this->collect($dir, $file);
    }

    /** @param list<RouteEntry> $routes */
    private function find(array $routes, string $key): RouteEntry
    {
        foreach ($routes as $route) {
            if (in_array($key, $route->keys(), true)) {
                return $route;
            }
        }
        self::fail('route not found: '.$key.' in '.implode(', ', $this->keys($routes)));
    }

    /**
     * @param  list<RouteEntry>  $routes
     * @return list<string>
     */
    private function keys(array $routes): array
    {
        return array_merge(...array_map(fn (RouteEntry $r): array => $r->keys(), $routes));
    }
}
