<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support\Benchmark;

/** disguise-map.json from Disguise: per app, disguised class, file and route back to the original; unknown names map to themselves. */
final class DisguiseMap
{
    /**
     * @param string $root absolute path of the disguised corpus
     * @param array<string, array{classes: array<string, string>, files: array<string, string>, routes: array<string, string>}> $byApp
     */
    private function __construct(public readonly string $root, private readonly array $byApp)
    {
    }

    public static function load(string $path): self
    {
        $json = is_file($path) ? file_get_contents($path) : false;
        $data = $json === false ? null : json_decode($json, true);
        if (! is_array($data)) {
            throw new \RuntimeException("cannot read disguise map {$path}");
        }

        return self::fromArray($data, dirname($path));
    }

    // A relative root resolves against $base, the map file's directory.
    /** @param array<mixed> $data */
    public static function fromArray(array $data, string $base): self
    {
        $root = is_string($data['root'] ?? null) ? $data['root'] : 'bench';
        $root = str_starts_with($root, '/') ? $root : rtrim($base, '/').'/'.$root;
        $resolved = realpath($root);
        $byApp = [];
        foreach (is_array($data['apps'] ?? null) ? $data['apps'] : [] as $app => $entry) {
            if (! is_string($app) || ! is_array($entry)) {
                continue;
            }
            $byApp[$app] = [
                'classes' => self::strings($entry['classes'] ?? null),
                'files' => self::strings($entry['files'] ?? null),
                'routes' => self::strings($entry['routes'] ?? null),
            ];
        }

        return new self($resolved === false ? $root : $resolved, $byApp);
    }

    /** @return list<string> */
    public function apps(): array
    {
        return array_keys($this->byApp);
    }

    public function originalClass(string $app, string $class): string
    {
        $class = ltrim($class, '\\');
        foreach ($this->byApp[$app]['classes'] ?? [] as $disguised => $original) {
            if (strcasecmp($disguised, $class) === 0) {
                return $original;
            }
        }

        return $class;
    }

    // Class::member or Class; the member part is kept as is.
    public function originalSymbol(string $app, string $symbol): string
    {
        if ($symbol === '') {
            return '';
        }
        $parts = explode('::', ExpectedCases::symbol($symbol), 2);

        return $this->originalClass($app, $parts[0]).(isset($parts[1]) ? '::'.$parts[1] : '');
    }

    public function disguisedSymbol(string $app, string $symbol): string
    {
        $parts = explode('::', ExpectedCases::symbol($symbol), 2);
        foreach ($this->byApp[$app]['classes'] ?? [] as $disguised => $original) {
            if (strcasecmp($original, $parts[0]) === 0) {
                $parts[0] = $disguised;
                break;
            }
        }

        return implode('::', $parts);
    }

    public function originalFile(string $app, string $file): string
    {
        $file = ExpectedCases::canonicalFile($file);

        return $this->byApp[$app]['files'][$file] ?? $file;
    }

    public function disguisedRoute(string $app, string $route): string
    {
        $found = array_search($route, $this->byApp[$app]['routes'] ?? [], true);

        return is_string($found) ? $found : $route;
    }

    public function originalRoute(string $app, string $route): string
    {
        return $this->byApp[$app]['routes'][$route] ?? $route;
    }

    /** @return array<string, string> */
    private static function strings(mixed $value): array
    {
        $out = [];
        foreach (is_array($value) ? $value : [] as $key => $item) {
            if (is_string($key) && is_string($item)) {
                $out[$key] = $item;
            }
        }

        return $out;
    }
}
