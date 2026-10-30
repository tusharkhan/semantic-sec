<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Integration\Console;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Tester\CommandTester;
use TusharKhan\SemanticSec\Console\Application;
use TusharKhan\SemanticSec\Framework\Laravel\AuthCheckKind;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;

final class MapCommandTest extends TestCase
{
    /** @var list<string> */
    private array $tmp = [];

    protected function tearDown(): void
    {
        foreach ($this->tmp as $dir) {
            exec('rm -rf '.escapeshellarg($dir));
        }
    }

    private function tester(): CommandTester
    {
        return new CommandTester((new Application())->find('map'));
    }

    private function tempDir(): string
    {
        $dir = sys_get_temp_dir().'/semsec-map-'.bin2hex(random_bytes(4));
        mkdir($dir, 0777, true);

        return $this->tmp[] = $dir;
    }

    public function testConsoleOutputOnBenchmark(): void
    {
        $t = $this->tester();
        $code = $t->execute(['--project-root' => BenchmarkCorpus::root().'/laravel11-app']);

        $this->assertSame(0, $code);
        $this->assertStringContainsString('/vuln/invoices/{id}', $t->getDisplay());
        $this->assertMatchesRegularExpression('/\d+ routes: \d+ with authorization, \d+ authentication only, \d+ unprotected/', $t->getDisplay());
    }

    public function testJsonOutputShape(): void
    {
        $t = $this->tester();
        $code = $t->execute(['--project-root' => BenchmarkCorpus::root().'/laravel11-app', '--format' => 'json']);
        $data = json_decode($t->getDisplay(), true, 512, JSON_THROW_ON_ERROR);

        $this->assertSame(0, $code);
        $this->assertSame(11, $data['framework']['major']);
        $this->assertNotEmpty($data['routes']);
        $valid = array_map(static fn (AuthCheckKind $k): string => $k->value, AuthCheckKind::cases());
        foreach ($data['routes'] as $route) {
            $this->assertArrayHasKey('closure', $route['action']);
            foreach ($route['checks'] as $check) {
                $this->assertContains($check['kind'], $valid);
                $this->assertArrayHasKey('covers', $check);
            }
        }
    }

    public function testNoFrameworkExitsTwo(): void
    {
        $t = $this->tester();
        $code = $t->execute(['--project-root' => $this->tempDir()], ['capture_stderr_separately' => true]);

        $this->assertSame(2, $code);
        $this->assertStringContainsString('--framework', $t->getErrorOutput());
    }

    public function testBadFormatAndMissingRootExitTwo(): void
    {
        $t = $this->tester();
        $this->assertSame(2, $t->execute(['--format' => 'xml']));
        $this->assertStringContainsString('--format must be console or json', $t->getDisplay());
        $this->assertSame(2, $this->tester()->execute(['--project-root' => '/no/such/dir']));
    }

    public function testDuplicateChecksCollapsedInConsole(): void
    {
        $dir = $this->tempDir();
        mkdir($dir.'/routes');
        mkdir($dir.'/app/Http/Controllers', 0777, true);
        file_put_contents($dir.'/composer.json', '{"require":{"laravel/framework":"^10.0"}}');
        file_put_contents($dir.'/routes/web.php', "<?php\nuse App\\Http\\Controllers\\ThingController;\nuse Illuminate\\Support\\Facades\\Route;\nRoute::middleware('auth')->group(function () {\n    Route::get('/things', [ThingController::class, 'index']);\n});\n");
        file_put_contents($dir.'/app/Http/Controllers/ThingController.php', "<?php\nnamespace App\\Http\\Controllers;\nclass ThingController\n{\n    public function __construct()\n    {\n        \$this->middleware('auth');\n    }\n\n    public function index()\n    {\n    }\n}\n");

        $t = $this->tester();
        $t->execute(['--project-root' => $dir]);

        $this->assertSame(1, substr_count($t->getDisplay(), 'authentication (auth only)'), $t->getDisplay());
    }

    /** @param array<string, string> $files */
    private function project(array $files): string
    {
        $dir = $this->tempDir();
        foreach ($files + ['composer.json' => '{"require":{"laravel/framework":"^11.0"}}'] as $path => $code) {
            @mkdir(dirname($dir.'/'.$path), 0777, true);
            file_put_contents($dir.'/'.$path, $code);
        }

        return $dir;
    }

    private function fixture(): string
    {
        return $this->project([
            'bootstrap/app.php' => "<?php\nreturn Application::configure()->withRouting(web: __DIR__.'/../routes/web.php')->create();",
            'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\nuse App\\Http\\Controllers\\C;\n"
                ."Route::get('/a/{post}', [C::class, 'show'])->middleware(['auth', 'can:view,post'])->scopeBindings();\n"
                ."Route::get('/b', [C::class, 'index'])->middleware('auth')->withoutMiddleware('verified');\n"
                ."Route::get('/c', [C::class, 'open']);\n"
                ."Route::get('/d', [C::class, 'gone']);\n"
                ."Route::get('/caf\xE9', [C::class, 'open']);\n",
            'app/Http/Controllers/C.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Post;\nclass C\n{\n    public function show(Post \$post) { \$this->authorize('view', \$post); }\n    public function index() {}\n    public function open() { return Post::where('user_id', \$id)->get(); }\n}\n",
            'app/Models/Post.php' => "<?php\nnamespace App\\Models;\nclass Post extends \\Illuminate\\Database\\Eloquent\\Model {}\n",
        ]);
    }

    public function testConsoleShowsEverySourceAndCounts(): void
    {
        $t = $this->tester();
        $t->execute(['--project-root' => $this->fixture()]);
        $display = $t->getDisplay();

        $this->assertStringContainsString('authentication (auth only): middleware auth', $display);
        $this->assertStringContainsString('route_ability: middleware can:view,post', $display);
        $this->assertStringContainsString("controller_ability: \$this->authorize('view', \$post)", $display);
        $this->assertStringContainsString('5 routes: 1 with authorization, 1 authentication only, 3 unprotected', $display);
        $this->assertMatchesRegularExpression('/\n\nWarnings\n  routes\/web\.php:7: action App\\\\Http\\\\Controllers\\\\C::gone not found\n/', $display);
    }

    public function testConsoleCollapsesIdenticalLinesAndShowsNoneSources(): void
    {
        $dir = $this->project([
            'bootstrap/app.php' => "<?php\nreturn Application::configure()->withRouting(web: __DIR__.'/../routes/web.php')->create();",
            'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::middleware('auth')->group(function () {\n    Route::get('/x', [\\App\\C::class, 'x'])->middleware('auth');\n});\n",
            'app/C.php' => "<?php\nnamespace App;\nclass C { public function x(\\App\\R \$r) {} }\nclass R extends \\Illuminate\\Foundation\\Http\\FormRequest { public function authorize(): bool { return true; } }\n",
        ]);
        $t = $this->tester();
        $t->execute(['--project-root' => $dir]);
        $display = $t->getDisplay();

        $this->assertSame(1, substr_count($display, 'authentication (auth only): middleware auth'), $display);
        $this->assertStringContainsString('form_request (none): FormRequest R::authorize returns true', $display);
        $this->assertStringContainsString('1 routes: 0 with authorization, 1 authentication only, 0 unprotected', $display);
        $this->assertStringNotContainsString('Warnings', $display);
    }

    public function testJsonCarriesRouteDetailsAndSurvivesBadUtf8(): void
    {
        $t = $this->tester();
        $code = $t->execute(['--project-root' => $this->fixture(), '--format' => 'json']);
        $data = json_decode($t->getDisplay(), true, 512, JSON_THROW_ON_ERROR);

        $this->assertSame(0, $code);
        $this->assertCount(5, $data['routes']);
        $a = $data['routes'][0];
        $this->assertSame('routes/web.php', $a['file']);
        $this->assertSame(4, $a['line']);
        $this->assertTrue($a['scopeBindings']);
        $this->assertSame([], $a['withoutMiddleware']);
        $this->assertSame(['verified'], $data['routes'][1]['withoutMiddleware']);
        $this->assertNull($data['routes'][1]['scopeBindings']);
        $this->assertSame("/caf\u{FFFD}", $data['routes'][4]['uri']);
    }
}
