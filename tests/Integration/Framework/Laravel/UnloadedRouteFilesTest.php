<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Integration\Framework\Laravel;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Console\MapBuilder;

final class UnloadedRouteFilesTest extends TestCase
{
    private string $dir = '';

    protected function tearDown(): void
    {
        if ($this->dir !== '') {
            exec('rm -rf '.escapeshellarg($this->dir));
        }
    }

    public function testRouteFileNobodyLoadsWarns(): void
    {
        $this->dir = sys_get_temp_dir().'/ss-unloaded-'.bin2hex(random_bytes(4));
        $files = [
            'composer.json' => '{"require":{"laravel/framework":"^11.0"}}',
            'bootstrap/app.php' => "<?php\nreturn Application::configure()->withRouting(web: __DIR__.'/../routes/web.php')->create();",
            'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::get('/', fn () => 1);\nrequire __DIR__.'/auth.php';",
            'routes/auth.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::get('/login', fn () => 1);",
            'routes/orphan.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::get('/hidden', fn () => 1);",
            'routes/console.php' => "<?php\nuse Illuminate\\Support\\Facades\\Artisan;\nArtisan::command('x', fn () => 1);",
        ];
        foreach ($files as $path => $code) {
            @mkdir(dirname($this->dir.'/'.$path), 0777, true);
            file_put_contents($this->dir.'/'.$path, $code);
        }

        [$map, , $warnings] = (new MapBuilder())->build($this->dir, null, null);

        self::assertCount(2, $map->routes);
        self::assertSame(['routes/orphan.php defines routes but is not loaded by any analysed source'], $warnings);
    }
}
