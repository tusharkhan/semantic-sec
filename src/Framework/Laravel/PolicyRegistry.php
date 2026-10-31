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

    private const USE_POLICY = 'Illuminate\\Database\\Eloquent\\Attributes\\UsePolicy';

    private const RESPONSE = 'Illuminate\\Auth\\Access\\Response';

    /**
     * @param  array<string, string>  $registered  model => policy
     * @param  array<string, string>  $attributed  model => policy from #[UsePolicy]
     * @param  array<string, list<GateDefinition>>  $defines  ability => Gate::define calls
     */
    private function __construct(private readonly SymbolTable $symbols, private readonly array $registered, private readonly array $attributed, private readonly array $defines = [])
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

        $attributed = [];
        $defines = [];
        foreach ($symbols->all() as $class) {
            foreach ($class->node->attrGroups as $group) {
                foreach ($group->attrs as $attr) {
                    if ($attr->name->toString() !== self::USE_POLICY) {
                        continue;
                    }
                    $arg = $attr->args[0]->value ?? null;
                    $policy = $arg === null ? null : $eval->string($arg, $class->file, $class);
                    if ($policy === null) {
                        $warnings[] = sprintf('%s:%d: #[UsePolicy] could not be resolved', $class->file, $attr->getStartLine());
                    } else {
                        $attributed[$class->name] = ltrim($policy, '\\');
                    }
                }
            }
            $ancestors = self::ancestors($symbols, $class);
            if (in_array(self::AUTH_PROVIDER, $ancestors, true)) {
                self::readPoliciesProperty($class, $eval, $add, $warnings);
            }
            if (in_array(self::SERVICE_PROVIDER, $ancestors, true) || in_array(self::AUTH_PROVIDER, $ancestors, true)) {
                self::readGateCalls($class, $eval, $add, $warnings);
                foreach (self::readGateDefines($class, $eval, $symbols) as $define) {
                    $defines[$define->ability][] = $define;
                }
            }
        }

        return [new self($symbols, $registered, $attributed, $defines), $warnings];
    }

    public function policyFor(string $model): ?string
    {
        $model = ltrim($model, '\\');
        if (isset($this->registered[$model])) {
            return $this->registered[$model];
        }
        if (isset($this->attributed[$model])) {
            return $this->attributed[$model];
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
        $before = $this->symbols->findMethod($policy, 'before');
        if ($before !== null && self::allowsAll($before)) {
            return true;
        }
        $method = $this->abilityHolder($policy, $ability);

        return $method !== null && self::allowsAll($method);
    }

    // Body is exactly `return true;` or `return Response::allow();`.
    public static function allowsAll(MethodSymbol $method): bool
    {
        $stmts = $method->node->stmts;
        if ($stmts === null || count($stmts) !== 1 || ! $stmts[0] instanceof Return_) {
            return false;
        }
        $expr = $stmts[0]->expr;
        if ($expr instanceof Expr\ConstFetch) {
            return strtolower($expr->name->toString()) === 'true';
        }

        return $expr instanceof Expr\StaticCall && $expr->class instanceof Name && $expr->class->toString() === self::RESPONSE
            && $expr->name instanceof \PhpParser\Node\Identifier && strtolower($expr->name->toString()) === 'allow';
    }

    /** @return list<GateDefinition> the Gate::define calls for an ability, in source order */
    public function gateDefinitions(string $ability): array
    {
        return $this->defines[$ability] ?? [];
    }

    // Gate turns kebab-case abilities into camelCase policy methods.
    public static function abilityMethod(string $ability): string
    {
        return str_contains($ability, '-') ? lcfirst(str_replace(' ', '', ucwords(str_replace('-', ' ', $ability)))) : $ability;
    }

    public function abilityHolder(string $policy, string $ability): ?MethodSymbol
    {
        return $this->symbols->findMethod($policy, $ability);
    }

    /**
     * Mirrors Gate::guessPolicyName: prefixes + \Policies\XPolicy, plus the \Models\ variants, longest first.
     *
     * @return list<string>
     */
    private function candidates(string $model): array
    {
        $pos = strrpos($model, '\\');
        if ($pos === false) {
            return [];
        }
        $dir = substr($model, 0, $pos);
        $base = substr($model, $pos + 1).'Policy';
        $segments = explode('\\', $dir);
        $out = [];
        foreach (range(1, count($segments)) as $n) {
            $out[] = implode('\\', array_slice($segments, 0, $n)).'\\Policies\\'.$base;
        }
        if (str_contains($dir, '\\Models\\')) {
            $out[] = str_replace('\\Models\\', '\\Policies\\', $dir).'\\'.$base;
            $out[] = str_replace('\\Models\\', '\\Models\\Policies\\', $dir).'\\'.$base;
        }

        return array_reverse($out);
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

    /** @return list<GateDefinition> */
    private static function readGateDefines(ClassSymbol $class, ConstantEvaluator $eval, SymbolTable $symbols): array
    {
        $out = [];
        foreach ((new NodeFinder())->findInstanceOf($class->node->getMethods(), Expr\StaticCall::class) as $call) {
            if (! $call->class instanceof Name || ! in_array($call->class->toString(), [self::GATE, 'Gate'], true)
                || ! $call->name instanceof \PhpParser\Node\Identifier || strtolower($call->name->toString()) !== 'define') {
                continue;
            }
            $args = array_map(static fn ($a) => $a instanceof \PhpParser\Node\Arg ? $a->value : null, array_slice($call->args, 0, 2));
            $ability = ($args[0] ?? null) === null ? null : $eval->string($args[0], $class->file, $class);
            $callback = $args[1] ?? null;
            if ($ability === null) {
                continue;
            }
            [$method, $closure, $why] = self::callback($callback, $class, $eval, $symbols);
            $out[] = new GateDefinition($ability, $class->file, $call->getStartLine(), $method, $closure, $why);
        }

        return $out;
    }

    /** @return array{?MethodSymbol, Expr\Closure|Expr\ArrowFunction|null, ?string} method, closure, or why neither resolved */
    private static function callback(?Expr $callback, ClassSymbol $class, ConstantEvaluator $eval, SymbolTable $symbols): array
    {
        if ($callback instanceof Expr\Closure || $callback instanceof Expr\ArrowFunction) {
            return [null, $callback, null];
        }
        $target = null;
        if ($callback instanceof Expr\Array_ && count($callback->items) === 2) {
            $owner = $eval->string($callback->items[0]->value, $class->file, $class);
            $name = $eval->string($callback->items[1]->value, $class->file, $class);
            $target = $owner === null || $name === null ? null : [$owner, $name];
        } elseif ($callback !== null) {
            $string = $eval->string($callback, $class->file, $class);
            $target = $string === null ? null : (str_contains($string, '@') ? explode('@', $string, 2) : [$string, '__invoke']);
        }
        if ($target === null) {
            return [null, null, 'callback not statically resolvable'];
        }
        $method = $symbols->findMethod(ltrim($target[0], '\\'), $target[1]);

        return $method === null ? [null, null, ltrim($target[0], '\\').'::'.$target[1].' not in the project'] : [$method, null, null];
    }
}
