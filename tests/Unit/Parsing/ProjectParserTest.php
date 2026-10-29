<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Parsing;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Parsing\AstGenerator;
use TusharKhan\SemanticSec\Parsing\FileFinder;
use TusharKhan\SemanticSec\Parsing\ProjectParser;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;
use TusharKhan\SemanticSec\Tests\Support\ExplodingStream;

final class ProjectParserTest extends TestCase
{
    private string $root;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir().'/ss-pp-'.bin2hex(random_bytes(6));
        mkdir($this->root.'/app', 0777, true);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->root.'/app/*') ?: [] as $f) {
            is_link($f) || is_file($f) ? unlink($f) : null;
        }
        rmdir($this->root.'/app');
        rmdir($this->root);
    }

    public function testSyntaxErrorIsCollectedAndOtherFilesStillParse(): void
    {
        file_put_contents($this->root.'/app/Good.php', '<?php class Good {}');
        file_put_contents($this->root.'/app/Bad.php', '<?php class {');

        $result = $this->parser()->parse($this->root);

        self::assertCount(1, $result->files);
        self::assertNotNull($result->file('app/Good.php'));
        self::assertNull($result->file('app/Bad.php'));
        self::assertCount(1, $result->failures);
        self::assertSame('app/Bad.php', $result->failures[0]->path);
        self::assertNotNull($result->failures[0]->sourceLine);
    }

    public function testNameConflictIsCollectedAndOtherFilesStillParse(): void
    {
        file_put_contents($this->root.'/app/Good.php', '<?php class Good {}');
        file_put_contents($this->root.'/app/Conflict.php', '<?php use A\B; use C\B;');

        $result = $this->parser()->parse($this->root);

        self::assertNotNull($result->file('app/Good.php'));
        self::assertCount(1, $result->failures);
        self::assertSame('app/Conflict.php', $result->failures[0]->path);
    }

    public function testUnreadableFileIsAFailureWithNullLine(): void
    {
        if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
            self::markTestSkipped('root can read everything');
        }
        file_put_contents($this->root.'/app/Locked.php', '<?php class L {}');
        chmod($this->root.'/app/Locked.php', 0000);

        $result = $this->parser()->parse($this->root);

        self::assertSame([], $result->files);
        self::assertSame('app/Locked.php', $result->failures[0]->path);
        self::assertNull($result->failures[0]->sourceLine);
    }

    public function testOversizedFileIsSkippedAndOthersStillParse(): void
    {
        file_put_contents($this->root.'/app/Good.php', '<?php class Good {}');
        file_put_contents($this->root.'/app/Big.php', "<?php\n".str_repeat("// padding padding padding padding\n", 36_000));

        $result = $this->parser()->parse($this->root);

        self::assertNotNull($result->file('app/Good.php'));
        self::assertNull($result->file('app/Big.php'));
        self::assertCount(1, $result->failures);
        self::assertSame('app/Big.php', $result->failures[0]->path);
        self::assertSame('skipped: 1.2 MB exceeds the 1.0 MB limit', $result->failures[0]->getMessage());
        self::assertNull($result->failures[0]->sourceLine);
    }

    public function testUnexpectedThrowableIsContainedPerFile(): void
    {
        ExplodingStream::register();
        ExplodingStream::$files = ['proj/app/Good.php' => '<?php class Good {}', 'proj/app/Boom.php' => null];

        $result = $this->parser()->parse('ssboom://proj');

        self::assertNotNull($result->file('app/Good.php'));
        self::assertCount(1, $result->failures);
        self::assertSame('app/Boom.php', $result->failures[0]->path);
        self::assertSame('internal error: LogicException: stream exploded', $result->failures[0]->getMessage());
        self::assertNull($result->failures[0]->sourceLine);
    }

    public function testFileLookupFindsEveryParsedFileByPath(): void
    {
        file_put_contents($this->root.'/app/A.php', '<?php class A {}');
        file_put_contents($this->root.'/app/B.php', '<?php class B {}');

        $result = $this->parser()->parse($this->root);

        self::assertSame('app/B.php', $result->file('app/B.php')?->file->path);
        self::assertSame('app/A.php', $result->file('app/A.php')?->file->path);
        self::assertNull($result->file('app/C.php'));
    }

    public function testParsesWholeBenchmarkAppWithoutFailures(): void
    {
        $result = $this->parser()->parse(BenchmarkCorpus::root().'/laravel11-app');

        self::assertSame([], $result->failures);
        self::assertNotNull($result->file('app/Http/Controllers/Vuln/InvoiceController.php'));
    }

    private function parser(): ProjectParser
    {
        return new ProjectParser(new FileFinder(), new AstGenerator());
    }
}
