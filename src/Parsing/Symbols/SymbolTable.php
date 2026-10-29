<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Parsing\Symbols;

final class SymbolTable
{
    /** @var array<string, ClassSymbol> */
    private array $classes = [];

    /** @var array<string, list<ClassSymbol>> */
    private array $byFile = [];

    /** @var list<string> */
    private array $duplicates = [];

    /**
     * @param  list<ClassSymbol>  $classes
     * @param  list<string>  $failures
     */
    public function __construct(array $classes, private array $failures = [])
    {
        foreach ($classes as $class) {
            if (isset($this->classes[$class->name])) {
                $this->duplicates[] = sprintf('%s declared in %s and %s', $class->name, $this->classes[$class->name]->file, $class->file);

                continue;
            }
            $this->classes[$class->name] = $class;
            $this->byFile[$class->file][] = $class;
        }
    }

    /** @return list<string> */
    public function duplicates(): array
    {
        return $this->duplicates;
    }

    /** @return list<string> */
    public function failures(): array
    {
        return $this->failures;
    }

    public function getClass(string $fqn): ?ClassSymbol
    {
        return $this->classes[ltrim($fqn, '\\')] ?? null;
    }

    // Own methods, then traits, then the parent chain; case-insensitive.
    public function findMethod(string $class, string $method): ?MethodSymbol
    {
        $visited = [];

        return $this->lookup(ltrim($class, '\\'), strtolower($method), $visited);
    }

    /** @return list<ClassSymbol> */
    public function classesInFile(string $path): array
    {
        return $this->byFile[$path] ?? [];
    }

    /** @return list<ClassSymbol> */
    public function all(): array
    {
        return array_values($this->classes);
    }

    /** @param array<string, true> $visited */
    private function lookup(string $fqn, string $method, array &$visited): ?MethodSymbol
    {
        $symbol = $this->classes[$fqn] ?? null;
        if ($symbol === null || isset($visited[$fqn])) {
            return null;
        }
        $visited[$fqn] = true;

        if (isset($symbol->methods[$method])) {
            return $symbol->methods[$method];
        }
        foreach ($symbol->traits as $trait) {
            $found = $this->lookup($trait, $method, $visited);
            if ($found !== null) {
                return $found;
            }
        }

        return $symbol->parent !== null ? $this->lookup($symbol->parent, $method, $visited) : null;
    }
}
