<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support;

use PhpParser\Node;
use PhpParser\Node\Stmt;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\NodeFinder;
use TusharKhan\SemanticSec\Analysis\Category;
use TusharKhan\SemanticSec\Framework\Laravel\AuthCheckKind;

// Pure checks over expected.yaml entries; every message starts with "<case id>[.<variant>]: ".
final class CorpusValidator
{
    public const VARIANTS = ['vulnerable', 'safe'];

    public const SETS = ['existing', 'blind'];

    private const CASE_KEYS = ['id', 'app', 'set', 'category', 'description', 'vulnerable', 'safe'];

    private const VARIANT_KEYS = ['route', 'symbol', 'line', 'map', 'suppressed', 'candidate', 'accept', 'posthoc'];

    private const PUBLIC_ROUTE_KEYS = ['app', 'set', 'route', 'symbol'];

    private const SYMBOL_PATTERN = '/^App\\\\[\w\\\\]+::\w+$/';

    private const REQUIRED_VARIANT_KEYS = ['route', 'symbol', 'map'];

    private const ROUTE_PATTERN = '#^(GET|POST|PUT|PATCH|DELETE) /\S*$#';

    private const SUPPRESSION_MARKER = '@semantic-sec-ignore';

    /** @param array<mixed> $case */
    public static function caseId(array $case): string
    {
        return is_string($case['id'] ?? null) && $case['id'] !== '' ? $case['id'] : '?';
    }

    /**
     * @param array<mixed> $case
     *
     * @return list<string>
     */
    public static function caseErrors(array $case, string $root): array
    {
        $id = self::caseId($case);
        $errors = [];

        foreach (self::CASE_KEYS as $key) {
            if (! array_key_exists($key, $case)) {
                $errors[] = "$id: missing key \"$key\"";
            }
        }

        foreach (array_keys($case) as $key) {
            if (! in_array($key, self::CASE_KEYS, true)) {
                $errors[] = "$id: unknown key \"$key\"";
            }
        }

        if (array_key_exists('app', $case) && ! self::isApp($case['app'], $root)) {
            $errors[] = "$id: app " . json_encode($case['app']) . ' is not a benchmark app';
        }

        if (array_key_exists('set', $case) && ! in_array($case['set'], self::SETS, true)) {
            $errors[] = "$id: set must be existing or blind";
        }

        if (array_key_exists('category', $case) && Category::tryFrom(is_string($case['category']) ? $case['category'] : '') === null) {
            $errors[] = "$id: bad category " . json_encode($case['category']);
        }

        if (array_key_exists('description', $case) && (! is_string($case['description']) || $case['description'] === '')) {
            $errors[] = "$id: description must be a non-empty string";
        }

        foreach (self::VARIANTS as $variant) {
            if (array_key_exists($variant, $case)) {
                $errors = [...$errors, ...self::variantErrors("$id.$variant", $variant, $case[$variant])];
            }
        }

        return $errors;
    }

    /**
     * @param array<mixed> $route
     *
     * @return list<string>
     */
    public static function publicRouteErrors(string $label, array $route, string $root): array
    {
        $errors = [];
        foreach (['app', 'route', 'symbol'] as $key) {
            if (! is_string($route[$key] ?? null) || $route[$key] === '') {
                $errors[] = "$label: $key must be a non-empty string";
            }
        }
        foreach (array_keys($route) as $key) {
            if (! in_array($key, self::PUBLIC_ROUTE_KEYS, true)) {
                $errors[] = "$label: unknown key \"$key\"";
            }
        }
        if (array_key_exists('set', $route) && ! in_array($route['set'], self::SETS, true)) {
            $errors[] = "$label: set must be existing or blind";
        }
        if (is_string($route['app'] ?? null) && ! self::isApp($route['app'], $root)) {
            $errors[] = "$label: app \"{$route['app']}\" is not a benchmark app";
        }

        return $errors;
    }

    /** @return list<string> */
    public static function lineErrors(string $label, ClassMethod $method, int $line): array
    {
        $statement = (new NodeFinder())->findFirst(
            $method->stmts ?? [],
            static fn (Node $node): bool => $node instanceof Stmt && $node->getStartLine() === $line,
        );

        return $statement === null ? ["$label: no statement starts on line $line"] : [];
    }

    /** @return list<string> */
    public static function suppressionErrors(string $label, ClassMethod $method, bool $suppressed): array
    {
        $annotated = false;
        foreach ($method->getComments() as $comment) {
            $annotated = $annotated || str_contains($comment->getText(), self::SUPPRESSION_MARKER);
        }

        if ($suppressed && ! $annotated) {
            return ["$label: suppressed: true but the method has no " . self::SUPPRESSION_MARKER . ' comment'];
        }

        if (! $suppressed && $annotated) {
            return ["$label: " . self::SUPPRESSION_MARKER . ' on a variant without suppressed: true'];
        }

        return [];
    }

    /**
     * @param list<array{owner: string, app: string, route: string}> $routes
     *
     * @return list<string>
     */
    public static function routeErrors(array $routes): array
    {
        $errors = [];
        $seen = [];

        foreach ($routes as $route) {
            if (preg_match(self::ROUTE_PATTERN, $route['route']) !== 1) {
                $errors[] = "{$route['owner']}: bad route " . json_encode($route['route'], JSON_UNESCAPED_SLASHES);

                continue;
            }

            $key = $route['app'] . ' ' . $route['route'];
            if (isset($seen[$key])) {
                $errors[] = "{$route['owner']}: route \"{$route['route']}\" in {$route['app']} already used by {$seen[$key]}";

                continue;
            }

            $seen[$key] = $route['owner'];
        }

        return $errors;
    }

    public static function isApp(mixed $app, string $root): bool
    {
        return is_string($app) && preg_match('/^[a-z0-9-]+$/', $app) === 1 && is_dir("$root/$app");
    }

    /** @return list<string> */
    private static function variantErrors(string $label, string $variant, mixed $data): array
    {
        if (! is_array($data)) {
            return ["$label: must be a mapping"];
        }

        $errors = [];

        foreach (self::REQUIRED_VARIANT_KEYS as $key) {
            if (! array_key_exists($key, $data)) {
                $errors[] = "$label: missing key \"$key\"";
            }
        }

        foreach (array_keys($data) as $key) {
            if (! in_array($key, self::VARIANT_KEYS, true)) {
                $errors[] = "$label: unknown key \"$key\"";
            }
        }

        foreach (['route', 'symbol'] as $key) {
            if (array_key_exists($key, $data) && (! is_string($data[$key]) || $data[$key] === '')) {
                $errors[] = "$label: $key must be a non-empty string";
            }
        }

        if (is_string($data['symbol'] ?? null) && preg_match(self::SYMBOL_PATTERN, $data['symbol']) !== 1) {
            $errors[] = "$label: symbol must look like App\\Class::method";
        }

        foreach (['suppressed', 'candidate', 'posthoc'] as $key) {
            if (array_key_exists($key, $data) && ! is_bool($data[$key])) {
                $errors[] = "$label: $key must be a bool";
            }
        }

        if ($variant === 'vulnerable' && ! is_int($data['line'] ?? null)) {
            $errors[] = "$label: line must be an int";
        }

        if ($variant !== 'vulnerable' && array_key_exists('line', $data)) {
            $errors[] = "$label: line is only allowed on vulnerable";
        }

        if (array_key_exists('accept', $data)) {
            $errors = [...$errors, ...self::acceptErrors($label, $data['accept'], $data['symbol'] ?? null)];
        }

        if (array_key_exists('posthoc', $data) && ! array_key_exists('accept', $data)) {
            $errors[] = "$label: posthoc needs an accept list";
        }

        if (array_key_exists('map', $data)) {
            $errors = [...$errors, ...self::mapErrors($label, $data['map'])];
        }

        return $errors;
    }

    /** @return list<string> */
    private static function acceptErrors(string $label, mixed $accept, mixed $symbol): array
    {
        $valid = is_array($accept) && $accept !== [] && array_is_list($accept);
        foreach ($valid ? $accept : [] as $item) {
            $valid = $valid && is_string($item) && preg_match(self::SYMBOL_PATTERN, $item) === 1;
        }
        if (! $valid) {
            return ["$label: accept must be a non-empty list of App\\Class::method symbols"];
        }

        return in_array($symbol, $accept, true) ? ["$label: accept repeats the case symbol"] : [];
    }

    /** @return list<string> */
    private static function mapErrors(string $label, mixed $map): array
    {
        if (! is_array($map) || ! array_is_list($map)) {
            return ["$label: map must be a list"];
        }

        $errors = [];
        $seen = [];

        foreach ($map as $kind) {
            $name = is_string($kind) ? $kind : json_encode($kind);
            if (! is_string($kind) || AuthCheckKind::tryFrom($kind) === null) {
                $errors[] = "$label: bad map kind \"$name\"";

                continue;
            }

            if (isset($seen[$kind])) {
                $errors[] = "$label: duplicate map kind \"$kind\"";
            }

            $seen[$kind] = true;
        }

        return $errors;
    }
}
