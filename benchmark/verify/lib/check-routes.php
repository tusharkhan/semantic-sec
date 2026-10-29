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
 * @param  list<string>|null  $map
 * @return list<string>
 */
function checkRoute(array $routes, string $label, string $key, ?array $map, string $symbol): array
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
    $expectedAction = str_replace('::', '@', $symbol);
    $actualAction = (string) ($found[0]['action'] ?? '');
    if ($actualAction !== $expectedAction) {
        $problems[] = "action is $actualAction, expected $expectedAction";
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
            array_push($failures, ...checkRoute($routes, $case['id'].".$variant", (string) $entry['route'], $map, (string) ($entry['symbol'] ?? '')));
        }
    }
    foreach ($expected['public_routes'] ?? [] as $public) {
        if (($public['app'] ?? null) !== $app) {
            continue;
        }
        $checked++;
        array_push($failures, ...checkRoute($routes, 'public.route', (string) $public['route'], null, (string) ($public['symbol'] ?? '')));
    }

    return [$checked, $failures];
}

/** @param array<string, mixed> $expected */
function expectedCount(array $expected, string $app): int
{
    $cases = count(array_filter($expected['cases'] ?? [], static fn (array $c): bool => ($c['app'] ?? null) === $app));
    $public = count(array_filter($expected['public_routes'] ?? [], static fn (array $p): bool => ($p['app'] ?? null) === $app));

    return $cases * 2 + $public;
}

/**
 * @param  array<string, mixed>  $expected
 * @param  list<array<string, mixed>>  $routes
 * @return array{0: int, 1: list<string>}
 */
function evaluate(array $expected, string $app, array $routes): array
{
    [$checked, $failures] = checkAll($expected, $app, $routes);
    $want = expectedCount($expected, $app);
    if ($checked === 0) {
        $failures[] = "no expected routes for app \"$app\"";
    } elseif ($checked !== $want) {
        $failures[] = "checked $checked routes but expected $want for app \"$app\"";
    }

    return [$checked, $failures];
}

function selfTest(): int
{
    $auth = 'Illuminate\\Auth\\Middleware\\Authenticate';
    $authz = 'Illuminate\\Auth\\Middleware\\Authorize';
    $routes = [
        ['method' => 'GET|HEAD', 'uri' => 'posts/{post}', 'middleware' => ['web'], 'action' => 'T\\C@m'],
        ['method' => 'GET|HEAD', 'uri' => 'a/{x}', 'middleware' => ['web', 'auth'], 'action' => 'T\\C@m'],
        ['method' => 'GET|HEAD', 'uri' => 'b/{x}', 'middleware' => ['web', 'auth:api'], 'action' => 'T\\C@m'],
        ['method' => 'GET|HEAD', 'uri' => 'c/{x}', 'middleware' => ['web', 'auth', 'can:view,x'], 'action' => 'T\\C@m'],
        ['method' => 'GET|HEAD', 'uri' => 'd/{x}', 'middleware' => ['web', 'auth', 'can:view,x'], 'action' => 'T\\C@m'],
        ['method' => 'GET|HEAD', 'uri' => 'f/{x}', 'middleware' => ['web', $auth, "$authz:view,x"], 'action' => 'T\\C@m'],
        ['method' => 'GET|HEAD', 'uri' => 'e', 'middleware' => ['web', "$auth:web"], 'action' => 'T\\C@m'],
        ['method' => 'GET|HEAD', 'uri' => 'noauth', 'middleware' => ['web'], 'action' => 'T\\C@m'],
        ['method' => 'GET|HEAD', 'uri' => 'dup', 'middleware' => ['web', 'auth'], 'action' => 'T\\C@m'],
        ['method' => 'POST', 'uri' => 'dup', 'middleware' => ['web', 'auth'], 'action' => 'T\\C@m'],
        ['method' => 'GET|POST', 'uri' => 'dup', 'middleware' => ['web', 'auth'], 'action' => 'T\\C@m'],
        ['method' => 'GET|HEAD', 'uri' => 'g/{x:slug}', 'middleware' => ['web', 'auth'], 'action' => 'T\\C@m'],
        ['method' => 'GET|HEAD', 'uri' => 'h/{x}', 'middleware' => ['web', 'auth', 'can:update,x'], 'action' => 'T\\C@m'],
        ['method' => 'GET|HEAD', 'uri' => 'i/{x}', 'middleware' => ['web', 'auth', "$authz:view,x"], 'action' => 'T\\C@m'],
        ['method' => 'GET|HEAD', 'uri' => 'w/{x}', 'middleware' => ['web', 'auth'], 'action' => 'T\\Other@m'],
        ['method' => 'GET|HEAD', 'uri' => 'pw/{x}', 'middleware' => ['web'], 'action' => 'T\\Other@m'],
    ];
    $case = static fn (string $id, string $route, array $map): array => [
        'id' => $id, 'app' => 't', 'vulnerable' => ['route' => $route, 'map' => $map, 'symbol' => 'T\\C::m'], 'safe' => ['route' => $route, 'map' => $map, 'symbol' => 'T\\C::m'],
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
            $case('noAuth', 'GET /noauth', ['authentication']),
            $case('dup', 'GET /dup', ['authentication']),
            $case('ctrlAbility', 'GET /h/{x}', ['authentication', 'controller_ability']),
            $case('routeSlug', 'GET /g/{x}', ['authentication']),
            $case('routeSlug2', 'GET /g/{x:slug}', ['authentication']),
            $case('wrongClassCan', 'GET /i/{x}', ['authentication']),
            $case('wrongAction', 'GET /w/{x}', ['authentication']),
        ],
        'public_routes' => [
            ['app' => 't', 'route' => 'GET /posts/{post:slug}', 'symbol' => 'T\\C::m'],
            ['app' => 't', 'route' => 'GET /a/{x}', 'symbol' => 'T\\C::m'],
            ['app' => 't', 'route' => 'GET /pw/{x}', 'symbol' => 'T\\C::m'],
            ['app' => 'other', 'route' => 'GET /ignored', 'symbol' => 'T\\C::m'],
        ],
    ];
    [$checked, $failures] = evaluate($expected, 't', $routes);
    $both = static fn (string $id, string $route, string $why): array => ["$id.vulnerable $route: $why", "$id.safe $route: $why"];
    $want = [
        ...$both('missing', 'GET /nope', 'not found in route:list'),
        ...$both('noCan', 'GET /a/{x}', 'map has route_ability but no can: middleware'),
        ...$both('wrongCan', 'GET /d/{x}', 'map has no ability check but route has can: middleware'),
        ...$both('noAuth', 'GET /noauth', 'map has authentication but no auth middleware'),
        ...$both('dup', 'GET /dup', 'matched 2 route:list entries'),
        ...$both('wrongClassCan', 'GET /i/{x}', 'map has no ability check but route has can: middleware'),
        ...$both('wrongAction', 'GET /w/{x}', 'action is T\\Other@m, expected T\\C@m'),
        'public.route GET /a/{x}: public route has auth middleware',
        'public.route GET /pw/{x}: action is T\\Other@m, expected T\\C@m',
    ];
    $zero = evaluate($expected, 'nothing', $routes);
    $ok = $checked === 33 && $failures === $want
        && $zero === [0, ['no expected routes for app "nothing"']];
    if (! $ok) {
        fwrite(STDERR, "self-test FAILED ($checked)\n".implode("\n", $failures)."\n".json_encode($zero)."\n");

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
    [$checked, $failures] = evaluate(Yaml::parseFile($file), $app, $routes);
    if ($failures !== []) {
        fwrite(STDERR, implode("\n", $failures)."\n");

        return 1;
    }
    echo "OK $checked routes checked ($app)\n";

    return 0;
}

exit(main($argv));
