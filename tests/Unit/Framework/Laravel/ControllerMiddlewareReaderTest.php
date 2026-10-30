<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Framework\Laravel;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Framework\Laravel\ConstantEvaluator;
use TusharKhan\SemanticSec\Framework\Laravel\ControllerMiddlewareReader;
use TusharKhan\SemanticSec\Parsing\AstGenerator;
use TusharKhan\SemanticSec\Parsing\FileFinder;
use TusharKhan\SemanticSec\Parsing\ProjectParser;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTableBuilder;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;

final class ControllerMiddlewareReaderTest extends TestCase
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

    private function reader(string $root): ControllerMiddlewareReader
    {
        $parsed = (new ProjectParser(new FileFinder(), new AstGenerator()))->parse($root);

        return new ControllerMiddlewareReader((new SymbolTableBuilder())->build($parsed), new ConstantEvaluator());
    }

    /** @param array<string, string> $files */
    private function project(array $files): string
    {
        $dir = sys_get_temp_dir().'/ss-cmr-'.bin2hex(random_bytes(4));
        mkdir($dir);
        $this->dirs[] = $dir;
        foreach ($files as $path => $code) {
            @mkdir(dirname($dir.'/'.$path), 0777, true);
            file_put_contents($dir.'/'.$path, $code);
        }

        return $dir;
    }

    public function testConstructorMiddlewareOnlyExcept(): void
    {
        $reader = $this->reader(BenchmarkCorpus::root().'/laravel10-app');
        $class = 'App\\Http\\Controllers\\Safe\\ReportController';
        self::assertSame([['auth', 'can:view,report'], []], $reader->forAction($class, 'show'));
        self::assertSame([['auth'], []], $reader->forAction($class, 'index'));
        self::assertSame([['auth'], []], $reader->forAction('App\\Http\\Controllers\\Vuln\\ReportController', 'show'));
    }

    public function testHasMiddleware(): void
    {
        $reader = $this->reader(BenchmarkCorpus::root().'/laravel11-app');
        $class = 'App\\Http\\Controllers\\Safe\\DocumentController';
        self::assertSame([['auth', 'can:view,document'], []], $reader->forAction($class, 'show'));
        self::assertSame([['auth'], []], $reader->forAction($class, 'index'));
    }

    public function testInheritedConstructorMiddleware(): void
    {
        $root = $this->project(['app/C.php' => <<<'PHP'
<?php
namespace App;
class Base { public function __construct() { $this->middleware('auth'); } }
class Child extends Base { public function __construct() { $this->middleware(['verified', 'signed'])->except(['Index']); } public function index() {} public function show() {} }
PHP]);
        $reader = $this->reader($root);
        self::assertSame([['auth', 'verified', 'signed'], []], $reader->forAction('App\\Child', 'show'));
        self::assertSame([['auth'], []], $reader->forAction('App\\Child', 'index'));
    }

    public function testClosureMiddlewareWarns(): void
    {
        $root = $this->project(['app/C.php' => <<<'PHP'
<?php
namespace App;
use Illuminate\Routing\Controllers\HasMiddleware;
use Illuminate\Routing\Controllers\Middleware;
class C implements HasMiddleware {
    public static function middleware(): array { return ['auth', function ($r, $next) { return $next($r); }, new Middleware('can:x', except: ['index'])]; }
}
class D { public function __construct() { $this->middleware(function () {}); } }
class E implements HasMiddleware { public static function middleware(): array { return foo(); } }
PHP]);
        $reader = $this->reader($root);
        [$mw, $warnings] = $reader->forAction('App\\C', 'show');
        self::assertSame(['auth', 'can:x'], $mw);
        self::assertCount(1, $warnings);
        self::assertStringContainsString('app/C.php:6: controller middleware could not be resolved', $warnings[0]);
        self::assertSame(['auth'], $reader->forAction('App\\C', 'index')[0]);
        [, $w] = $reader->forAction('App\\D', 'a');
        self::assertCount(1, $w);
        [, $w] = $reader->forAction('App\\E', 'a');
        self::assertCount(1, $w);
    }

    public function testPositionalMiddlewareArgs(): void
    {
        $root = $this->project(['app/C.php' => <<<'PHP'
<?php
namespace App;
use Illuminate\Routing\Controllers\HasMiddleware;
use Illuminate\Routing\Controllers\Middleware;
class C implements HasMiddleware {
    public static function middleware(): array { return [new Middleware('a', ['show']), new Middleware('b', null, ['show'])]; }
}
PHP]);
        $reader = $this->reader($root);
        self::assertSame([['a'], []], $reader->forAction('App\\C', 'show'));
        self::assertSame([['b'], []], $reader->forAction('App\\C', 'edit'));
    }

    public function testUnknownClassReturnsEmpty(): void
    {
        $reader = $this->reader(BenchmarkCorpus::root().'/laravel10-app');
        self::assertSame([[], []], $reader->forAction('Nope\\Missing', 'show'));
    }
}
