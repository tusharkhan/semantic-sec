<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Since;

use Symfony\Component\Process\Exception\ExceptionInterface;
use Symfony\Component\Process\Process;

/** The files committed since a git ref (`<ref>...HEAD`), relative to the project root (SPEC §12). */
final class ChangedFiles
{
    public const MAX_REF = 255;

    private const TIMEOUT = 60.0;

    public const SHALLOW_HINT = ' (in CI, fetch full history, e.g. actions/checkout with fetch-depth: 0)';

    // Environment that would redirect git or inject config; `false` unsets it for the child.
    private const UNSET_ENV = ['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_COMMON_DIR', 'GIT_NAMESPACE', 'GIT_EXTERNAL_DIFF', 'GIT_DIFF_OPTS', 'GIT_CONFIG_PARAMETERS', 'GIT_CONFIG_COUNT'];

    // Config that could change the diff's paths, pinned on the command line.
    private const PINNED = ['-c', 'diff.relative=false', '-c', 'diff.noprefix=false', '-c', 'core.quotePath=false', '-c', 'diff.renames=false', '-c', 'diff.external='];

    // Rejects anything git could read as an option, and whitespace or control characters.
    public static function validate(string $ref): void
    {
        if ($ref === '' || strlen($ref) > self::MAX_REF || str_starts_with($ref, '-') || str_starts_with($ref, '..') || preg_match('~[\x00-\x20\x7F]~', $ref) === 1) {
            throw new \RuntimeException(sprintf('--since must be a git ref of 1-%d characters, without whitespace, a leading "-" or a leading ".."', self::MAX_REF));
        }
    }

    /**
     * @param  string  $git  the git executable; a test seam
     * @return list<string> sorted, root-relative paths; renames list both sides, deleted files are included
     */
    public static function between(string $root, string $ref, string $git = 'git'): array
    {
        self::validate($ref);
        $prefix = self::run($git, $root, ['rev-parse', '--show-prefix'], fn (): string => sprintf('%s is not a git repository, or git refused it (see safe.directory)', $root));
        $prefix = rtrim($prefix, "\n");
        self::run($git, $root, ['rev-parse', '--verify', '--quiet', $ref.'^{commit}'], fn (): string => 'unknown git ref: '.$ref.(self::shallow($git, $root) ? self::SHALLOW_HINT : ''));
        $out = self::run($git, $root, ['diff', '--name-only', '--no-relative', '--no-renames', '--no-ext-diff', '--no-textconv', '-z', $ref.'...HEAD', '--'], fn (): string => sprintf('git diff %s...HEAD failed; a shallow clone needs the full history (fetch-depth: 0)', $ref));

        $paths = [];
        foreach (explode("\0", $out) as $path) {
            if ($path === '' || ! str_starts_with($path, $prefix)) {
                continue;
            }
            $paths[substr($path, strlen($prefix))] = true;
        }
        $paths = array_map('strval', array_keys($paths));
        sort($paths, SORT_STRING);

        return $paths;
    }

    /**
     * @param  list<string>  $args
     * @param  \Closure(): string  $error  the message when git exits non-zero; git's own stderr is never shown
     */
    private static function run(string $git, string $root, array $args, \Closure $error): string
    {
        $env = ['GIT_TERMINAL_PROMPT' => '0', 'GIT_OPTIONAL_LOCKS' => '0', 'LC_ALL' => 'C'];
        foreach (self::UNSET_ENV as $name) {
            $env[$name] = false;
        }
        foreach (array_keys([...$_SERVER, ...$_ENV]) as $name) {
            if (is_string($name) && preg_match('~^GIT_CONFIG_(KEY|VALUE)_\d+$~', $name) === 1) {
                $env[$name] = false;
            }
        }
        $process = new Process([$git, ...self::PINNED, '-C', $root, ...$args], null, $env, null, self::TIMEOUT);
        try {
            $process->run();
        } catch (ExceptionInterface $e) {
            throw new \RuntimeException('git could not be run ('.self::short($e->getMessage()).')');
        }
        if ($process->getExitCode() === 127 || $process->getExitCode() === 126) {
            throw new \RuntimeException('git could not be run; install git or run without --since');
        }
        if (! $process->isSuccessful()) {
            throw new \RuntimeException($error());
        }

        return $process->getOutput();
    }

    private static function shallow(string $git, string $root): bool
    {
        try {
            return trim(self::run($git, $root, ['rev-parse', '--is-shallow-repository'], fn (): string => '')) === 'true';
        } catch (\RuntimeException) {
            return false;
        }
    }

    private static function short(string $message): string
    {
        return substr((string) preg_replace('~[\x00-\x1F\x7F]+~', ' ', $message), 0, 200);
    }
}
