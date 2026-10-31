<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support;

/** Replaces the http/https stream wrappers with one that records and refuses every open. */
final class NetworkTrap
{
    /** @var list<string> */
    private static array $opened = [];

    /** @var resource|null */
    public $context;

    public static function install(): void
    {
        self::$opened = [];
        foreach (['http', 'https'] as $scheme) {
            if (in_array($scheme, stream_get_wrappers(), true)) {
                stream_wrapper_unregister($scheme);
            }
            stream_wrapper_register($scheme, self::class);
        }
    }

    /** @return list<string> the URLs that were opened while installed */
    public static function uninstall(): array
    {
        foreach (['http', 'https'] as $scheme) {
            stream_wrapper_unregister($scheme);
            stream_wrapper_restore($scheme);
        }

        return self::$opened;
    }

    public function stream_open(string $path, string $mode, int $options, ?string &$openedPath): bool
    {
        self::$opened[] = $path;

        return false;
    }

    public function url_stat(string $path, int $flags): false
    {
        self::$opened[] = $path;

        return false;
    }
}
