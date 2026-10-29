<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support;

/** Read-only stream wrapper whose files can raise a \Throwable on read. */
final class ExplodingStream
{
    /** @var array<string, string|null> path => contents, null means reading throws */
    public static array $files = [];

    /** @var resource|null */
    public $context;

    private string $buffer = '';

    private int $pos = 0;

    /** @var list<string> */
    private array $entries = [];

    public static function register(): void
    {
        if (! in_array('ssboom', stream_get_wrappers(), true)) {
            stream_wrapper_register('ssboom', self::class);
        }
    }

    private string $dirPath = '';

    public function dir_opendir(string $path, int $options): bool
    {
        $this->dirPath = $path;
        $prefix = rtrim($path, '/').'/';
        $names = [];
        foreach (array_keys(self::$files) as $file) {
            $full = 'ssboom://'.$file;
            if (str_starts_with($full, $prefix)) {
                $names[explode('/', substr($full, strlen($prefix)))[0]] = true;
            }
        }
        $this->entries = array_map('strval', array_keys($names));

        return true;
    }

    public function dir_readdir(): string|false
    {
        $next = array_shift($this->entries);

        return $next ?? false;
    }

    public function dir_closedir(): bool
    {
        return true;
    }

    public function dir_rewinddir(): bool
    {
        return $this->dir_opendir($this->dirPath, 0);
    }

    /** @return array<string, int>|false */
    public function url_stat(string $path, int $flags): array|false
    {
        $key = substr($path, strlen('ssboom://'));
        if (array_key_exists($key, self::$files)) {
            return ['mode' => 0100644, 'size' => strlen(self::$files[$key] ?? '')];
        }
        foreach (array_keys(self::$files) as $file) {
            if ($key === '' || str_starts_with($file, rtrim($key, '/').'/')) {
                return ['mode' => 040755, 'size' => 0];
            }
        }

        return false;
    }

    public function stream_open(string $path, string $mode, int $options, ?string &$opened): bool
    {
        $key = substr($path, strlen('ssboom://'));
        if (! array_key_exists($key, self::$files)) {
            return false;
        }
        $this->buffer = self::$files[$key] ?? throw new \LogicException('stream exploded');

        return true;
    }

    public function stream_read(int $count): string
    {
        $chunk = substr($this->buffer, $this->pos, $count);
        $this->pos += strlen($chunk);

        return $chunk;
    }

    public function stream_eof(): bool
    {
        return $this->pos >= strlen($this->buffer);
    }

    /** @return array<string, int> */
    public function stream_stat(): array
    {
        return ['size' => strlen($this->buffer)];
    }

    public function stream_set_option(int $option, int $arg1, ?int $arg2): bool
    {
        return false;
    }
}
