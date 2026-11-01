<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support;

use Symfony\Component\Process\Process;

/** Builds throwaway git repositories for the --since tests. */
final class GitRepo
{
    public static function init(string $dir): void
    {
        if (! is_dir($dir)) {
            mkdir($dir, 0777, true);
        }
        self::git($dir, 'init', '-q', '-b', 'main');
        self::git($dir, 'config', 'user.name', 'Test User');
        self::git($dir, 'config', 'user.email', 'test@example.com');
        self::git($dir, 'config', 'commit.gpgsign', 'false');
    }

    public static function commitAll(string $dir, string $message): void
    {
        self::git($dir, 'add', '-A');
        self::git($dir, 'commit', '-q', '--allow-empty', '-m', $message);
    }

    public static function write(string $dir, string $path, string $content): void
    {
        $file = $dir.'/'.$path;
        if (! is_dir(dirname($file))) {
            mkdir(dirname($file), 0777, true);
        }
        file_put_contents($file, $content);
    }

    public static function git(string $dir, string ...$args): string
    {
        $process = new Process(['git', '-C', $dir, ...$args], null, ['GIT_CONFIG_NOSYSTEM' => '1', 'HOME' => $dir]);
        $process->mustRun();

        return $process->getOutput();
    }
}
