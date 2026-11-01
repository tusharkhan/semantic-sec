<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Integration\Since;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Since\ChangedFiles;
use TusharKhan\SemanticSec\Tests\Support\GitRepo;

final class ChangedFilesTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir().'/semsec-changed-'.bin2hex(random_bytes(4));
        mkdir($this->dir, 0777, true);
    }

    protected function tearDown(): void
    {
        exec('rm -rf '.escapeshellarg($this->dir));
    }

    public function testCommittedChangesSinceRef(): void
    {
        GitRepo::init($this->dir);
        GitRepo::write($this->dir, 'app/A.php', "<?php\n");
        GitRepo::write($this->dir, 'app/Keep.php', "<?php\n");
        GitRepo::commitAll($this->dir, 'one');
        GitRepo::write($this->dir, 'app/A.php', "<?php\n// changed\n");
        GitRepo::write($this->dir, 'app/B.php', "<?php\n");
        GitRepo::commitAll($this->dir, 'two');

        self::assertSame(['app/A.php', 'app/B.php'], ChangedFiles::between($this->dir, 'HEAD~1'));
    }

    public function testUncommittedChangesIgnored(): void
    {
        GitRepo::init($this->dir);
        GitRepo::write($this->dir, 'a.php', "<?php\n");
        GitRepo::commitAll($this->dir, 'one');
        GitRepo::write($this->dir, 'b.php', "<?php\n");
        GitRepo::commitAll($this->dir, 'two');
        GitRepo::write($this->dir, 'a.php', "<?php\n// dirty\n");
        GitRepo::write($this->dir, 'c.php', "<?php\n");

        self::assertSame(['b.php'], ChangedFiles::between($this->dir, 'HEAD~1'));
    }

    public function testDeletedFileReported(): void
    {
        GitRepo::init($this->dir);
        GitRepo::write($this->dir, 'gone.php', "<?php\n");
        GitRepo::commitAll($this->dir, 'one');
        unlink($this->dir.'/gone.php');
        GitRepo::commitAll($this->dir, 'two');

        self::assertSame(['gone.php'], ChangedFiles::between($this->dir, 'HEAD~1'));
    }

    public function testRenameReportsBothSides(): void
    {
        GitRepo::init($this->dir);
        GitRepo::write($this->dir, 'app/Policies/OldPolicy.php', "<?php\nclass OldPolicy\n{\n    public function view(): bool\n    {\n        return false;\n    }\n}\n");
        GitRepo::commitAll($this->dir, 'one');
        GitRepo::git($this->dir, 'mv', 'app/Policies/OldPolicy.php', 'app/Policies/NewPolicy.php');
        GitRepo::commitAll($this->dir, 'two');
        GitRepo::git($this->dir, 'config', 'diff.renames', 'copies');

        self::assertSame(['app/Policies/NewPolicy.php', 'app/Policies/OldPolicy.php'], ChangedFiles::between($this->dir, 'HEAD~1'));
    }

    public function testThreeDotUsesMergeBase(): void
    {
        GitRepo::init($this->dir);
        GitRepo::write($this->dir, 'base.php', "<?php\n");
        GitRepo::commitAll($this->dir, 'base');
        GitRepo::git($this->dir, 'checkout', '-q', '-b', 'feature');
        GitRepo::write($this->dir, 'feature.php', "<?php\n");
        GitRepo::commitAll($this->dir, 'feature');
        GitRepo::git($this->dir, 'checkout', '-q', 'main');
        GitRepo::write($this->dir, 'main-only.php', "<?php\n");
        GitRepo::commitAll($this->dir, 'main moves on');
        GitRepo::git($this->dir, 'checkout', '-q', 'feature');

        self::assertSame(['feature.php'], ChangedFiles::between($this->dir, 'main'));
    }

    public function testProjectRootAsSubdirectory(): void
    {
        GitRepo::init($this->dir);
        GitRepo::write($this->dir, 'api/app/A.php', "<?php\n");
        GitRepo::write($this->dir, 'web/x.php', "<?php\n");
        GitRepo::commitAll($this->dir, 'one');
        GitRepo::write($this->dir, 'api/app/A.php', "<?php\n// changed\n");
        GitRepo::write($this->dir, 'api/routes/api.php', "<?php\n");
        GitRepo::write($this->dir, 'web/x.php', "<?php\n// changed\n");
        GitRepo::write($this->dir, 'api-other/y.php', "<?php\n");
        GitRepo::commitAll($this->dir, 'two');

        self::assertSame(['app/A.php', 'routes/api.php'], ChangedFiles::between($this->dir.'/api', 'HEAD~1'));
    }

    public function testPathsWithSpacesAndUnicode(): void
    {
        GitRepo::init($this->dir);
        GitRepo::write($this->dir, 'keep.php', "<?php\n");
        GitRepo::commitAll($this->dir, 'one');
        GitRepo::write($this->dir, 'dir with space/Fïlé ü.php', "<?php\n");
        GitRepo::write($this->dir, "tab\there.php", "<?php\n");
        GitRepo::commitAll($this->dir, 'two');

        self::assertSame(['dir with space/Fïlé ü.php', "tab\there.php"], ChangedFiles::between($this->dir, 'HEAD~1'));
    }

    public function testUnknownRefThrows(): void
    {
        GitRepo::init($this->dir);
        GitRepo::write($this->dir, 'a.php', "<?php\n");
        GitRepo::commitAll($this->dir, 'one');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('unknown git ref: no-such-branch');

        ChangedFiles::between($this->dir, 'no-such-branch');
    }

    public function testNotARepoThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('is not a git repository');

        ChangedFiles::between($this->dir, 'HEAD');
    }

    public function testGitMissingThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('git could not be run');

        ChangedFiles::between($this->dir, 'HEAD', '/nonexistent/git');
    }

    #[DataProvider('badRefs')]
    public function testRefStartingWithDashRejected(string $ref): void
    {
        GitRepo::init($this->dir);
        GitRepo::commitAll($this->dir, 'one');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('--since');

        ChangedFiles::between($this->dir, $ref);
    }

    /** @return array<string, array{string}> */
    public static function badRefs(): array
    {
        return [
            'empty' => [''],
            'dash' => ['-p'],
            'option' => ['--output=/tmp/x'],
            'space' => ['main other'],
            'tab' => ["main\tother"],
            'newline' => ["main\nother"],
            'nul' => ["main\0"],
            'leading dots' => ['..main'],
            'too long' => [str_repeat('a', 256)],
        ];
    }

    public function testValidateAcceptsCommonRefs(): void
    {
        foreach (['main', 'origin/main', 'HEAD~1', 'v1.2.3', 'abc123', 'feature/x-y_z', 'HEAD^', 'main@{1}', str_repeat('a', 255)] as $ref) {
            ChangedFiles::validate($ref);
        }
        $this->addToAssertionCount(1);
    }
}
