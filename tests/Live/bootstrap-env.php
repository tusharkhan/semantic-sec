<?php

declare(strict_types=1);

// Loads KEY=value lines from the git-ignored .env.live into the env; never prints a value, and real env wins.
(static function (string $path): void {
    if (!is_file($path) || !is_readable($path)) {
        return;
    }
    $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#')) {
            continue;
        }
        if (str_starts_with($line, 'export ')) {
            $line = ltrim(substr($line, 7));
        }
        $eq = strpos($line, '=');
        if ($eq === false) {
            continue;
        }
        $name = trim(substr($line, 0, $eq));
        if (preg_match('/\A[A-Za-z_][A-Za-z0-9_]*\z/', $name) !== 1) {
            continue;
        }
        $value = trim(substr($line, $eq + 1));
        if (strlen($value) >= 2 && ($value[0] === '"' || $value[0] === "'") && $value[-1] === $value[0]) {
            $value = substr($value, 1, -1);
        }
        $current = getenv($name);
        if ($current !== false && $current !== '') {
            continue;
        }
        putenv($name.'='.$value);
        $_ENV[$name] = $value;
    }
})(dirname(__DIR__, 2).'/.env.live');
