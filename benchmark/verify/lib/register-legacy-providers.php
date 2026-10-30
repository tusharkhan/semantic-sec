<?php

// Usage: php register-legacy-providers.php <project-dir>
$dir = $argv[1] ?? '';
$file = rtrim($dir, '/').'/config/app.php';

if ($dir === '' || ! is_file($file)) {
    fwrite(STDERR, "register-legacy-providers: config/app.php not found in '{$dir}'\n");
    exit(1);
}

$src = file_get_contents($file);

if (str_contains($src, 'RouteServiceProvider::class')) {
    echo "providers already registered\n";
    exit(0);
}

$needle = 'return [';
$pos = strpos($src, $needle);

if ($pos === false) {
    fwrite(STDERR, "register-legacy-providers: 'return [' not found in {$file}\n");
    exit(1);
}

$line = "\n\n    'providers' => Illuminate\\Support\\ServiceProvider::defaultProviders()->merge([\n"
    ."        App\\Providers\\RouteServiceProvider::class,\n"
    ."        App\\Providers\\AuthServiceProvider::class,\n"
    ."    ])->toArray(),";

file_put_contents($file, substr_replace($src, $line, $pos + strlen($needle), 0));
echo "providers registered\n";
