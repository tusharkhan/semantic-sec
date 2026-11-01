<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support\Benchmark;

use TusharKhan\SemanticSec\Console\MapBuilder;
use TusharKhan\SemanticSec\Framework\Laravel\RouteEntry;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;

/**
 * Maps claude-code-security-review findings to original-corpus symbols via our SymbolTable and the disguise map.
 *
 * @phpstan-import-type Trace from CompetitorRun
 */
final class CompetitorConverter
{
    // A finding this many lines below a route's first line still belongs to it (chained ->middleware() lines).
    public const ROUTE_SPAN = 2;

    /** @param array<string, array{symbols: SymbolTable, routes: list<RouteEntry>}> $projects */
    private function __construct(private readonly DisguiseMap $map, private readonly array $projects)
    {
    }

    public static function fromMap(DisguiseMap $map): self
    {
        $projects = [];
        foreach ($map->apps() as $app) {
            $root = $map->root.'/'.$app;
            if (! is_dir($root)) {
                throw new \RuntimeException("disguised app missing: {$root}");
            }
            $project = (new MapBuilder())->project($root, null, null);
            $projects[$app] = ['symbols' => $project->symbols, 'routes' => $project->map->routes];
        }

        return new self($map, $projects);
    }

    // Takes EvalResult.to_dict() (full_findings), raw github_action_audit.py output (findings) or a claude-call-N.json.
    /** @param array<mixed> $eval */
    public function convert(array $eval): CompetitorRun
    {
        if (($eval['success'] ?? true) === false) {
            throw new \RuntimeException('competitor run failed: '.(is_string($eval['error_message'] ?? null) ? $eval['error_message'] : 'no error message'));
        }
        if (($eval['type'] ?? null) === 'result' && is_string($eval['result'] ?? null)) {
            $eval = self::unwrap($eval['result']);
        }
        $findings = is_array($eval['full_findings'] ?? null) ? $eval['full_findings'] : (is_array($eval['findings'] ?? null) ? $eval['findings'] : []);
        $analyze = array_fill_keys(array_keys($this->projects), ['findings' => []]);
        $traces = [];
        foreach ($findings as $finding) {
            if (! is_array($finding)) {
                continue;
            }
            $trace = $this->trace($finding);
            $traces[] = $trace;
            if ($trace['app'] !== null) {
                $analyze[$trace['app']]['findings'][] = [
                    'category' => $trace['category'],
                    'confidence' => $trace['confidence'],
                    'file' => $trace['file'],
                    'line' => $trace['line'],
                    'symbol' => $trace['symbol'],
                    'title' => self::title($finding),
                ];
            }
        }

        return new CompetitorRun($analyze, $traces, [
            'success' => true,
            'runtime' => is_numeric($eval['runtime_seconds'] ?? null) ? (float) $eval['runtime_seconds'] : 0.0,
            'findings_count' => is_int($eval['findings_count'] ?? null) ? $eval['findings_count'] : count($traces),
        ]);
    }

    /**
     * @param array<mixed> $finding
     *
     * @return Trace
     */
    private function trace(array $finding): array
    {
        [$category, $rule] = CategoryInference::infer($finding);
        $reported = is_string($finding['file'] ?? null) ? $finding['file'] : (is_string($finding['path'] ?? null) ? $finding['path'] : '');
        $line = is_numeric($finding['line'] ?? null) ? (int) $finding['line'] : 0;
        $trace = [
            'app' => null,
            'file' => ExpectedCases::canonicalFile($reported),
            'line' => $line,
            'rawCategory' => is_scalar($finding['category'] ?? null) ? (string) $finding['category'] : '',
            'category' => $category,
            'rule' => $rule,
            'confidence' => self::confidence($finding),
            'disguisedSymbol' => '',
            'symbol' => '',
            'location' => 'outside the benchmark apps',
        ];
        [$app, $relative] = $this->split($trace['file']);
        if ($app === null) {
            return $trace;
        }
        [$symbol, $file, $location] = $this->locate($app, $relative, $line);

        return [...$trace, 'app' => $app, 'file' => $this->map->originalFile($app, $file), 'disguisedSymbol' => $symbol, 'symbol' => $this->map->originalSymbol($app, $symbol), 'location' => $location];
    }

    /** @return array{0: string|null, 1: string} the app whose directory appears in the path, and the path inside it */
    private function split(string $path): array
    {
        $segments = explode('/', $path);
        foreach ($segments as $i => $segment) {
            if (isset($this->projects[$segment])) {
                return [$segment, implode('/', array_slice($segments, $i + 1))];
            }
        }

        return [null, $path];
    }

    /** @return array{0: string, 1: string, 2: string} disguised symbol, disguised file and how it was found */
    private function locate(string $app, string $file, int $line): array
    {
        $symbols = $this->projects[$app]['symbols'];
        $classes = $symbols->classesInFile($file);
        foreach ($classes as $class) {
            if ($line < $class->startLine || $line > $class->endLine) {
                continue;
            }
            foreach ($class->methods as $method) {
                if ($line >= $method->startLine && $line <= $method->endLine) {
                    return [$class->name.'::'.$method->name, $file, 'method'];
                }
            }
            foreach ($class->properties as $property) {
                if ($property->line === $line) {
                    return [$class->name.'::$'.$property->name, $file, 'property'];
                }
            }

            return [$class->name, $file, 'class'];
        }
        if (count($classes) === 1) {
            return [$classes[0]->name, $file, 'file'];
        }
        $best = null;
        foreach ($this->projects[$app]['routes'] as $route) {
            if ($route->file === $file && $route->line <= $line && $line - $route->line <= self::ROUTE_SPAN && ($best === null || $route->line > $best->line)) {
                $best = $route;
            }
        }
        if ($best !== null && $best->action->symbol() !== null) {
            $class = $symbols->getClass((string) $best->action->class);

            return [(string) $best->action->symbol(), $class === null ? $file : $class->file, 'route'];
        }
        $isRoutes = array_filter($this->projects[$app]['routes'], static fn (RouteEntry $r): bool => $r->file === $file) !== [];

        return ['', $file, $isRoutes ? 'no route at that line' : 'no symbol at that line'];
    }

    // A claude-call-N.json from the cost guard: the model's reply text, with the findings JSON somewhere inside.
    /** @return array<mixed> */
    private static function unwrap(string $text): array
    {
        $start = strpos($text, '{');
        $end = strrpos($text, '}');
        $data = $start === false || $end === false ? null : json_decode(substr($text, $start, $end - $start + 1), true);

        return is_array($data) ? $data : [];
    }

    // Their confidence is 0..1 (the prompt drops < 0.7); severity stands in when it is missing.
    /** @param array<mixed> $finding */
    private static function confidence(array $finding): string
    {
        if (is_numeric($finding['confidence'] ?? null)) {
            $c = (float) $finding['confidence'];

            return $c >= 0.9 ? 'high' : ($c >= 0.7 ? 'medium' : 'low');
        }

        return match (strtoupper(is_string($finding['severity'] ?? null) ? $finding['severity'] : '')) {
            'HIGH' => 'high',
            'LOW' => 'low',
            default => 'medium',
        };
    }

    /** @param array<mixed> $finding */
    private static function title(array $finding): string
    {
        $category = is_scalar($finding['category'] ?? null) ? (string) $finding['category'] : '';
        $description = is_scalar($finding['description'] ?? null) ? (string) $finding['description'] : '';
        $title = trim($category.': '.$description, ': ');

        return mb_strlen($title) > 160 ? mb_substr($title, 0, 157).'...' : $title;
    }
}
