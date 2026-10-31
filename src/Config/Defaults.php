<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Config;

final class Defaults
{
    /** @var array{models: array<string, ?string>}|null */
    private static ?array $data = null;

    public static function model(string $provider): ?string
    {
        return self::data()['models'][$provider] ?? null;
    }

    /** @return array{models: array<string, ?string>} */
    private static function data(): array
    {
        return self::$data ??= require dirname(__DIR__, 2).'/config/defaults.php';
    }
}
