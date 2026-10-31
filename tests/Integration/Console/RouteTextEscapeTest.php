<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Integration\Console;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Tester\CommandTester;
use TusharKhan\SemanticSec\Console\Application;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;

// Route strings come from the scanned project, so console output must not let them drive the terminal.
final class RouteTextEscapeTest extends TestCase
{
    private string $base;

    private string $root;

    protected function setUp(): void
    {
        $this->base = sys_get_temp_dir().'/semsec-escape-'.bin2hex(random_bytes(4));
        mkdir($this->base, 0777, true);
        exec('cp -R '.escapeshellarg(BenchmarkCorpus::root().'/laravel11-app').' '.escapeshellarg($this->base.'/app'), $out, $code);
        self::assertSame(0, $code);
        $this->root = $this->base.'/app';
        file_put_contents($this->root.'/routes/web.php', <<<'PHP'

            Route::post("/evil\x1b]0;PWNED\x07\x1b[2J/{id}", [\App\Http\Controllers\Vuln\InvoiceController::class, 'update'])->name("n\x1b[31m");
            Route::post('/evil2/{id}/<error>tag</error>', [\App\Http\Controllers\Vuln\InvoiceController::class, 'nonexistent']);
            PHP, FILE_APPEND);
    }

    protected function tearDown(): void
    {
        exec('rm -rf '.escapeshellarg($this->base));
    }

    public function testMapTableAndWarningsAreEscaped(): void
    {
        $out = $this->display('map', []);

        self::assertStringContainsString('/evil ]0;PWNED [2J/{id}', $out);
        self::assertStringContainsString('/evil2/{id}/<error>tag</error>', $out, 'tags are printed, not interpreted');
        self::assertNoControls($out);
    }

    public function testDryRunTableAndWarningsAreEscaped(): void
    {
        $out = $this->display('analyze', ['--dry-run' => true]);

        self::assertStringContainsString('POST /evil ]0;PWNED [2J/{id}', $out);
        self::assertStringContainsString('<error>tag</error>', $out);
        self::assertNoControls($out);
    }

    /** @param array<string, bool> $args */
    private function display(string $command, array $args): string
    {
        $t = new CommandTester((new Application())->find($command));
        self::assertSame(0, $t->execute(['--project-root' => $this->root, ...$args], ['capture_stderr_separately' => true]), $t->getErrorOutput());

        return $t->getDisplay().$t->getErrorOutput();
    }

    private static function assertNoControls(string $out): void
    {
        self::assertSame(0, preg_match('/[\x00-\x09\x0B-\x1F\x7F]/', $out), 'no control characters but newlines');
    }
}
