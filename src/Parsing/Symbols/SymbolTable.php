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

    /** @var array<string, array<string, true>> */
    private array $ancestorCache = [];

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
        $method = strtolower($method);
        foreach ($this->lineage($class) as $symbol) {
            if (isset($symbol->methods[$method])) {
                return $symbol->methods[$method];
            }
        }

        return null;
    }

    // Own properties, then traits, then the parent chain.
    public function findProperty(string $class, string $name): ?PropertySymbol
    {
        foreach ($this->lineage($class) as $symbol) {
            if (isset($symbol->properties[$name])) {
                return $symbol->properties[$name];
            }
        }

        return null;
    }

    /**
     * The class, its traits (recursively) and then its parent chain, in lookup order; cycle-safe.
     *
     * @return list<ClassSymbol>
     */
    public function lineage(string $class): array
    {
        $out = [];
        $visited = [];
        $this->collectLineage(ltrim($class, '\\'), $visited, $out);

        return $out;
    }

    // Parents and interfaces (including interface `extends`), transitively; names outside the table still count.
    public function isSubclassOf(string $class, string $ancestor): bool
    {
        return isset($this->ancestors(ltrim($class, '\\'))[ltrim($ancestor, '\\')]);
    }

    /** @return list<string> concrete classes and enums in the table that implement or extend the interface */
    public function implementations(string $interface): array
    {
        $out = [];
        foreach ($this->classes as $name => $symbol) {
            $abstract = $symbol->node instanceof \PhpParser\Node\Stmt\Class_ && $symbol->node->isAbstract();
            if (($symbol->kind === 'class' || $symbol->kind === 'enum') && ! $abstract && $this->isSubclassOf($name, $interface)) {
                $out[] = $name;
            }
        }

        return $out;
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

    /**
     * @param  array<string, true>  $visited
     * @param  list<ClassSymbol>  $out
     */
    private function collectLineage(string $fqn, array &$visited, array &$out): void
    {
        $symbol = $this->classes[$fqn] ?? null;
        if ($symbol === null || isset($visited[$fqn])) {
            return;
        }
        $visited[$fqn] = true;
        $out[] = $symbol;
        foreach ($symbol->traits as $trait) {
            $this->collectLineage(ltrim($trait, '\\'), $visited, $out);
        }
        if ($symbol->parent !== null) {
            $this->collectLineage(ltrim($symbol->parent, '\\'), $visited, $out);
        }
    }

    /** @return array<string, true> every ancestor name of the class, excluding itself */
    private function ancestors(string $class): array
    {
        if (isset($this->ancestorCache[$class])) {
            return $this->ancestorCache[$class];
        }
        $seen = [];
        $queue = [$class];
        while ($queue !== []) {
            $symbol = $this->classes[array_shift($queue)] ?? null;
            if ($symbol === null) {
                continue;
            }
            foreach ([$symbol->parent, ...$symbol->interfaces] as $next) {
                $next = $next === null ? null : ltrim($next, '\\');
                if ($next !== null && ! isset($seen[$next])) {
                    $seen[$next] = true;
                    $queue[] = $next;
                }
            }
        }
        unset($seen[$class]);

        return $this->ancestorCache[$class] = $seen;
    }
}
