<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Framework\Laravel;

use PhpParser\Node\Expr;
use PhpParser\Node\Name;
use PhpParser\Node\Stmt\Return_;
use PhpParser\NodeFinder;
use TusharKhan\SemanticSec\Parsing\Symbols\ClassSymbol;
use TusharKhan\SemanticSec\Parsing\Symbols\MethodSymbol;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;

/** Maps models to policy classes (registered or auto-discovered) and spots trivial `return true;` abilities. */
final class PolicyRegistry
{
    private const SERVICE_PROVIDER = 'Illuminate\\Support\\ServiceProvider';

    private const AUTH_PROVIDER = 'Illuminate\\Foundation\\Support\\Providers\\AuthServiceProvider';

    private const GATE = 'Illuminate\\Support\\Facades\\Gate';

    /** @param array<string, string> $registered model => policy */
    private function __construct(private readonly SymbolTable $symbols, private readonly array $registered)
    {
    }

    /** @return array{0: self, 1: list<string>} */
    public static function fromProject(SymbolTable $symbols, ConstantEvaluator $eval): array
    {
        $registered = [];
        $warnings = [];
        $add = static function (string $model, string $policy, string $file, int $line) use (&$registered, &$warnings): void {
            $model = ltrim($model, '\\');
            $policy = ltrim($policy, '\\');
            if (! isset($registered[$model])) {
                $registered[$model] = $policy;
            } elseif ($registered[$model] !== $policy) {
                $warnings[] = sprintf('%s:%d: model %s has multiple policies', $file, $line, $model);
            }
        };

        foreach ($symbols->all() as $class) {
            $ancestors = self::ancestors($symbols, $class);
            if (in_array(self::AUTH_PROVIDER, $ancestors, true)) {
                self::readPoliciesProperty($class, $eval, $add, $warnings);
            }
            if (in_array(self::SERVICE_PROVIDER, $ancestors, true) || in_array(self::AUTH_PROVIDER, $ancestors, true)) {
                self::readGateCalls($class, $eval, $add, $warnings);
            }
        }

        return [new self($symbols, $registered), $warnings];
    }

    public function policyFor(string $model): ?string
    {
        $model = ltrim($model, '\\');
        if (isset($this->registered[$model])) {
            return $this->registered[$model];
        }
        foreach ($this->candidates($model) as $candidate) {
            if ($this->symbols->getClass($candidate) !== null) {
                return $candidate;
            }
        }

        return null;
    }

    public function isTrivial(string $policy, string $ability): bool
    {
        $stmts = $this->abilityHolder($policy, $ability)?->node->stmts;
        if ($stmts === null || count($stmts) !== 1 || ! $stmts[0] instanceof Return_) {
            return false;
        }
        $expr = $stmts[0]->expr;

        return $expr instanceof Expr\ConstFetch && strtolower($expr->name->toString()) === 'true';
    }

    public function abilityHolder(string $policy, string $ability): ?MethodSymbol
    {
        return $this->symbols->findMethod($policy, $ability);
    }

    /** @return list<string> */
    private function candidates(string $model): array
    {
        $pos = strrpos($model, '\\');
        $ns = $pos === false ? '' : substr($model, 0, $pos);
        $short = $pos === false ? $model : substr($model, $pos + 1);
        $root = explode('\\', $ns)[0];
        $primary = str_ends_with($ns, '\\Models') ? substr($ns, 0, -7) : $ns;
        $out = [];
        foreach ([$primary, $root] as $base) {
            $out[] = ($base === '' ? '' : $base.'\\').'Policies\\'.$short.'Policy';
        }

        return array_values(array_unique($out));
    }

    /**
     * Ancestor names in the table plus the first out-of-table parent; Laravel's own providers extend ServiceProvider.
     *
     * @return list<string>
     */
    private static function ancestors(SymbolTable $symbols, ClassSymbol $class): array
    {
        $names = [];
        $parent = $class->parent;
        while ($parent !== null && ! in_array($parent, $names, true)) {
            $parent = ltrim($parent, '\\');
            $names[] = $parent;
            if (str_starts_with($parent, 'Illuminate\\Foundation\\Support\\Providers\\')) {
                $names[] = self::SERVICE_PROVIDER;
            }
            $parent = $symbols->getClass($parent)?->parent;
        }

        return $names;
    }

    /**
     * @param  \Closure(string, string, string, int): void  $add
     * @param  list<string>  $warnings
     */
    private static function readPoliciesProperty(ClassSymbol $class, ConstantEvaluator $eval, \Closure $add, array &$warnings): void
    {
        $default = ($class->properties['policies'] ?? null)?->default;
        if (! $default instanceof Expr\Array_) {
            return;
        }
        foreach ($default->items as $item) {
            $key = $item->key === null ? null : $eval->string($item->key, $class->file, $class);
            $value = $eval->string($item->value, $class->file, $class);
            if ($key === null || $value === null) {
                $warnings[] = sprintf('%s:%d: policy mapping could not be resolved', $class->file, $item->getStartLine());

                continue;
            }
            $add($key, $value, $class->file, $item->getStartLine());
        }
    }

    /**
     * @param  \Closure(string, string, string, int): void  $add
     * @param  list<string>  $warnings
     */
    private static function readGateCalls(ClassSymbol $class, ConstantEvaluator $eval, \Closure $add, array &$warnings): void
    {
        foreach ((new NodeFinder())->findInstanceOf($class->node->getMethods(), Expr\StaticCall::class) as $call) {
            if (! $call->class instanceof Name || ! in_array($call->class->toString(), [self::GATE, 'Gate'], true)
                || ! $call->name instanceof \PhpParser\Node\Identifier || strtolower($call->name->toString()) !== 'policy') {
                continue;
            }
            $args = array_map(static fn ($a) => $a instanceof \PhpParser\Node\Arg ? $a->value : null, array_slice($call->args, 0, 2));
            $model = ($args[0] ?? null) === null ? null : $eval->string($args[0], $class->file, $class);
            $policy = ($args[1] ?? null) === null ? null : $eval->string($args[1], $class->file, $class);
            if ($model === null || $policy === null) {
                $warnings[] = sprintf('%s:%d: Gate::policy could not be resolved', $class->file, $call->getStartLine());

                continue;
            }
            $add($model, $policy, $class->file, $call->getStartLine());
        }
    }
}
