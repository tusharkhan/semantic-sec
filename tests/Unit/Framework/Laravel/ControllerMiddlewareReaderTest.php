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
class Child extends Base { public function __construct() { parent::__construct(); $this->middleware(['verified', 'signed'])->except(['Index']); } public function index() {} public function show() {} }
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

    /** @return array{0: list<string>, 1: list<string>} */
    private function read(string $body, string $method = 'show'): array
    {
        $root = $this->project(['app/C.php' => "<?php\nnamespace App;\n".$body]);

        return $this->reader($root)->forAction('App\\C', $method);
    }

    public function testParentConstructorSkippedWhenNotCalled(): void
    {
        $root = $this->project(['app/C.php' => <<<'PHP'
<?php
namespace App;
class Base { public function __construct() { $this->middleware('auth'); } }
class NoCall extends Base { public function __construct() { $this->middleware('verified'); } }
class NoCtor extends Base {}
PHP]);
        $reader = $this->reader($root);
        self::assertSame([['verified'], []], $reader->forAction('App\\NoCall', 'show'));
        self::assertSame([['auth'], []], $reader->forAction('App\\NoCtor', 'show'));
    }

    public function testOptionsArrayForm(): void
    {
        $body = "class C { public function __construct() { \$this->middleware('can:x', ['only' => ['show']]); \$this->middleware('log', ['except' => 'index']); } }";
        self::assertSame([['can:x', 'log'], []], $this->read($body, 'show'));
        self::assertSame([[], []], $this->read($body, 'index'));
        self::assertSame([['log'], []], $this->read($body, 'edit'));
    }

    public function testUnresolvableOnlySkipsAndWarns(): void
    {
        [$mw, $w] = $this->read('class C { public function __construct() { $this->middleware(\'a\')->only($x); $this->middleware(\'b\', [\'only\' => $y]); } }');
        self::assertSame([], $mw);
        self::assertCount(2, $w);
    }

    public function testStringOnlyAndCaseInsensitiveMethod(): void
    {
        $body = "class C { public function __construct() { \$this->middleware('a')->only('Show'); } }";
        self::assertSame([['a'], []], $this->read($body, 'SHOW'));
        self::assertSame([[], []], $this->read($body, 'index'));
    }

    public function testConditionalMiddlewareWarnsAndIsSkipped(): void
    {
        $body = "class C { public function __construct() { if (\$x) { \$this->middleware('a'); } foreach ([1] as \$i) { \$this->middleware('b'); } \$f = function () { \$this->middleware('c'); }; \$this->middleware('d'); } }";
        [$mw, $w] = $this->read($body);
        self::assertSame(['d'], $mw);
        self::assertCount(3, $w);
        self::assertStringContainsString(':3: conditional controller middleware is not analysed', $w[0]);
    }

    public function testMultiNameMiddleware(): void
    {
        $body = "use Illuminate\\Routing\\Controllers\\HasMiddleware;\nuse Illuminate\\Routing\\Controllers\\Middleware;\nclass C implements HasMiddleware { public static function middleware(): array { return [new Middleware(['a', 'b'], only: ['show']), 'c', 'd']; } public function __construct() { \$this->middleware(['e', 'f', 'g'])->except('show'); } }";
        self::assertSame([['a', 'b', 'c', 'd'], []], $this->read($body, 'show'));
        self::assertSame([['e', 'f', 'g', 'c', 'd'], []], $this->read($body, 'index'));
    }

    public function testInheritedHasMiddleware(): void
    {
        $body = "use Illuminate\\Routing\\Controllers\\HasMiddleware;\nclass Base implements HasMiddleware { public static function middleware(): array { return ['auth']; } }\nclass C extends Base {}";
        self::assertSame([['auth'], []], $this->read($body));
    }

    public function testUnresolvableOptionsSkipAndWarn(): void
    {
        foreach (['$this->middleware(\'a\', $opts);', '$this->middleware(\'a\', [...$o]);', '$this->middleware(\'a\', [$k => [\'show\']]);'] as $call) {
            [$mw, $w] = $this->read('class C { public function __construct() { '.$call.' } }');
            self::assertSame([], $mw, $call);
            self::assertCount(1, $w, $call);
            self::assertStringContainsString(':3: controller middleware options could not be resolved', $w[0]);
        }
    }

    public function testPipedNameStaysSingleEntry(): void
    {
        self::assertSame([['role:admin|editor'], []], $this->read("class C { public function __construct() { \$this->middleware('role:admin|editor'); } }"));
    }
}
