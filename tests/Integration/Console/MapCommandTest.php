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
}
