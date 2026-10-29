<?php

declare(strict_types=1);

// Usage: php check-routes.php <expected.yaml> <app> <route-list.json> | --self-test

use Symfony\Component\Yaml\Yaml;

function normalizeUri(string $uri): string
{
    return preg_replace('/\{([^}:]+):[^}]+\}/', '{$1}', ltrim($uri, '/')) ?? $uri;
}

/** @return array{0: string, 1: string} */
function splitKey(string $key): array
{
    [$method, $uri] = array_pad(explode(' ', trim($key), 2), 2, '');

    return [strtoupper($method), normalizeUri($uri)];
}

/**
 * @param  list<array<string, mixed>>  $routes
 * @return list<array<string, mixed>>
 */
function matchRoutes(array $routes, string $key): array
{
    [$method, $uri] = splitKey($key);
    $found = [];
    foreach ($routes as $route) {
        $methods = explode('|', (string) ($route['method'] ?? ''));
        if (in_array($method, $methods, true) && normalizeUri((string) ($route['uri'] ?? '')) === $uri) {
            $found[] = $route;
        }
    }

    return $found;
}

function isAuth(string $middleware): bool
{
    return $middleware === 'auth'
        || str_starts_with($middleware, 'auth:')
        || str_starts_with($middleware, 'Illuminate\\Auth\\Middleware\\Authenticate');
}

function isAbility(string $middleware): bool
{
    // Laravel 11+ route:list expands the can alias to its class.
    return str_starts_with($middleware, 'can:') || str_starts_with($middleware, 'Illuminate\\Auth\\Middleware\\Authorize');
}

/**
 * @param  list<string>  $middleware
 * @param  list<string>  $map
 * @return list<string>
 */
function middlewareProblems(array $middleware, array $map): array
{
    $problems = [];
    $hasAuth = array_filter($middleware, isAuth(...)) !== [];
    $hasCan = array_filter($middleware, isAbility(...)) !== [];
    if (in_array('authentication', $map, true) && ! $hasAuth) {
        $problems[] = 'map has authentication but no auth middleware';
    }
    if (in_array('route_ability', $map, true) && ! $hasCan) {
        $problems[] = 'map has route_ability but no can: middleware';
    }
    if (! in_array('route_ability', $map, true) && ! in_array('controller_ability', $map, true) && $hasCan) {
        $problems[] = 'map has no ability check but route has can: middleware';
    }

    return $problems;
}

/**
 * @param  list<array<string, mixed>>  $routes
 * @param  list<string>  $map
 * @return list<string>
 */
function checkRoute(array $routes, string $label, string $key, ?array $map): array
{
    $found = matchRoutes($routes, $key);
    if (count($found) !== 1) {
        return ["$label $key: ".(count($found) === 0 ? 'not found in route:list' : 'matched '.count($found).' route:list entries')];
    }
    $middleware = array_map('strval', (array) ($found[0]['middleware'] ?? []));
    if ($map === null) {
        $problems = array_filter($middleware, isAuth(...)) !== [] ? ['public route has auth middleware'] : [];
    } else {
        $problems = middlewareProblems($middleware, $map);
    }

    return array_map(static fn (string $p): string => "$label $key: $p", $problems);
}

/**
 * @param  array<string, mixed>  $expected
 * @param  list<array<string, mixed>>  $routes
 * @return array{0: int, 1: list<string>}
 */
function checkAll(array $expected, string $app, array $routes): array
{
    $checked = 0;
    $failures = [];
    foreach ($expected['cases'] ?? [] as $case) {
        if (($case['app'] ?? null) !== $app) {
            continue;
        }
        foreach (['vulnerable', 'safe'] as $variant) {
            $entry = $case[$variant];
            $checked++;
            $map = array_map('strval', $entry['map'] ?? []);
            array_push($failures, ...checkRoute($routes, $case['id'].".$variant", (string) $entry['route'], $map));
        }
    }
    foreach ($expected['public_routes'] ?? [] as $public) {
        if (($public['app'] ?? null) !== $app) {
            continue;
        }
        $checked++;
        array_push($failures, ...checkRoute($routes, 'public.route', (string) $public['route'], null));
    }

    return [$checked, $failures];
}

function selfTest(): int
{
    $routes = [
        ['method' => 'GET|HEAD', 'uri' => 'posts/{post}', 'middleware' => ['web']],
        ['method' => 'GET|HEAD', 'uri' => 'a/{x}', 'middleware' => ['web', 'auth']],
        ['method' => 'GET|HEAD', 'uri' => 'b/{x}', 'middleware' => ['web', 'auth:api']],
        ['method' => 'GET|HEAD', 'uri' => 'c/{x}', 'middleware' => ['web', 'auth', 'can:view,x']],
        ['method' => 'GET|HEAD', 'uri' => 'd/{x}', 'middleware' => ['web', 'auth', 'can:view,x']],
        ['method' => 'GET|HEAD', 'uri' => 'f/{x}', 'middleware' => ['web', 'Illuminate\\Auth\\Middleware\\Authenticate', 'Illuminate\\Auth\\Middleware\\Authorize:view,x']],
        ['method' => 'GET|HEAD', 'uri' => 'e', 'middleware' => ['web', 'Illuminate\\Auth\\Middleware\\Authenticate:web']],
    ];
    $case = static fn (string $id, string $route, array $map): array => [
        'id' => $id, 'app' => 't', 'vulnerable' => ['route' => $route, 'map' => $map], 'safe' => ['route' => $route, 'map' => $map],
    ];
    $expected = [
        'cases' => [
            $case('ok', 'GET /a/{x:slug}', ['authentication']),
            $case('guard', 'HEAD /b/{x}', ['authentication']),
            $case('class', 'GET /e', ['authentication']),
            $case('missing', 'GET /nope', ['authentication']),
            $case('noCan', 'GET /a/{x}', ['authentication', 'route_ability']),
            $case('wrongCan', 'GET /d/{x}', ['authentication']),
            $case('okCan', 'GET /c/{x}', ['authentication', 'route_ability']),
            $case('okClassCan', 'GET /f/{x}', ['authentication', 'route_ability']),
        ],
        'public_routes' => [
            ['app' => 't', 'route' => 'GET /posts/{post:slug}'],
            ['app' => 't', 'route' => 'GET /a/{x}'],
        ],
    ];
    [$checked, $failures] = checkAll($expected, 't', $routes);
    $want = [
        'missing.vulnerable GET /nope: not found in route:list',
        'missing.safe GET /nope: not found in route:list',
        'noCan.vulnerable GET /a/{x}: map has route_ability but no can: middleware',
        'noCan.safe GET /a/{x}: map has route_ability but no can: middleware',
        'wrongCan.vulnerable GET /d/{x}: map has no ability check but route has can: middleware',
        'wrongCan.safe GET /d/{x}: map has no ability check but route has can: middleware',
        'public.route GET /a/{x}: public route has auth middleware',
    ];
    if ($checked !== 18 || $failures !== $want) {
        fwrite(STDERR, "self-test FAILED\n".implode("\n", $failures)."\n");

        return 1;
    }
    echo "self-test OK\n";

    return 0;
}

function main(array $argv): int
{
    if (($argv[1] ?? '') === '--self-test') {
        return selfTest();
    }
    if (count($argv) !== 4) {
        fwrite(STDERR, "usage: php check-routes.php <expected.yaml> <app> <route-list.json> | --self-test\n");

        return 2;
    }
    $autoload = dirname(__DIR__, 3).'/vendor/autoload.php';
    if (! is_file($autoload)) {
        fwrite(STDERR, "run composer install in the repository first\n");

        return 2;
    }
    require $autoload;
    [, $file, $app, $json] = $argv;
    $routes = json_decode((string) file_get_contents($json), true);
    if (! is_array($routes)) {
        fwrite(STDERR, "invalid route list JSON: $json\n");

        return 2;
    }
    [$checked, $failures] = checkAll(Yaml::parseFile($file), $app, $routes);
    if ($failures !== []) {
        fwrite(STDERR, implode("\n", $failures)."\n");

        return 1;
    }
    echo "OK $checked routes checked ($app)\n";

    return 0;
}

exit(main($argv));
