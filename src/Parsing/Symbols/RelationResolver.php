<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Parsing\Symbols;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;

/** Resolves an Eloquent relation name on a model to the related model class (SPEC §8); never guesses. */
final class RelationResolver
{
    private const ELOQUENT_MODEL = 'Illuminate\\Database\\Eloquent\\Model';

    private const RELATIONS = [
        'hasone', 'hasmany', 'belongsto', 'belongstomany', 'hasonethrough', 'hasmanythrough',
        'morphone', 'morphmany', 'morphtomany', 'morphedbymany',
    ];

    /** @var array<string, ?string> */
    private array $cache = [];

    public function __construct(private readonly SymbolTable $symbols)
    {
    }

    public function relatedClass(string $model, string $relation): ?string
    {
        $model = ltrim($model, '\\');
        $key = $model."\0".$relation;
        if (! array_key_exists($key, $this->cache)) {
            $this->cache[$key] = $this->resolve($model, $relation);
        }

        return $this->cache[$key];
    }

    /** @param list<string> $relations resolved hop by hop; any unknown hop gives null */
    public function followChain(string $model, array $relations): ?string
    {
        $current = ltrim($model, '\\');
        foreach ($relations as $relation) {
            $current = $this->relatedClass($current, $relation);
            if ($current === null) {
                return null;
            }
        }

        return $current;
    }

    private function resolve(string $model, string $relation): ?string
    {
        $method = $this->symbols->findMethod($model, $relation);
        if ($method !== null) {
            $fromBody = $this->fromBody($method, $model);
            if ($fromBody !== null) {
                return $fromBody;
            }
            if ($method->returnGeneric !== null) {
                return $method->returnGeneric;
            }
        }
        foreach ($this->symbols->lineage($model) as $symbol) {
            $type = $symbol->docProperties[$relation] ?? $symbol->docMethods[strtolower($relation)] ?? null;
            if ($type !== null) {
                // A doc tag may name a collection or builder; only a model class is an answer.
                return $this->symbols->isSubclassOf($type, self::ELOQUENT_MODEL) ? $type : null;
            }
        }

        return null;
    }

    // The class every return of `$this->hasMany(X::class, …)…` names, or null if any return differs.
    private function fromBody(MethodSymbol $method, string $model): ?string
    {
        $returns = $this->returns($method->node->stmts ?? []);
        $found = null;
        foreach ($returns as $return) {
            $class = $return->expr === null ? null : $this->relationTarget($return->expr, $method, $model);
            if ($class === null || ($found !== null && $found !== $class)) {
                return null;
            }
            $found = $class;
        }

        return $found;
    }

    private function relationTarget(Expr $expr, MethodSymbol $method, string $model): ?string
    {
        while (($expr instanceof Expr\MethodCall || $expr instanceof Expr\NullsafeMethodCall)
            && ! ($expr->var instanceof Expr\Variable && $expr->var->name === 'this')) {
            $expr = $expr->var;
        }
        if (! $expr instanceof Expr\MethodCall || ! $expr->name instanceof Node\Identifier
            || ! in_array($expr->name->toLowerString(), self::RELATIONS, true) || $expr->isFirstClassCallable()) {
            return null;
        }
        $first = $expr->getArgs()[0] ?? null;
        if ($first === null || $first->unpack || ($first->name !== null && $first->name->toString() !== 'related')) {
            return null;
        }
        $value = $first->value;
        if ($value instanceof Node\Scalar\String_) {
            return $value->value === '' ? null : ltrim($value->value, '\\');
        }
        if (! $value instanceof Expr\ClassConstFetch || ! $value->class instanceof Node\Name
            || ! $value->name instanceof Node\Identifier || $value->name->toLowerString() !== 'class') {
            return null;
        }

        return match ($value->class->toLowerString()) {
            'self' => $method->class,
            'static' => $model,
            'parent' => $this->symbols->getClass($method->class)?->parent,
            default => ltrim($value->class->toString(), '\\'),
        };
    }

    /**
     * Return statements of the body, not those of nested closures or classes.
     *
     * @param  array<Node>  $nodes
     * @return list<Stmt\Return_>
     */
    private function returns(array $nodes): array
    {
        $out = [];
        foreach ($nodes as $node) {
            if ($node instanceof Node\FunctionLike || $node instanceof Stmt\ClassLike) {
                continue;
            }
            if ($node instanceof Stmt\Return_) {
                $out[] = $node;
            }
            foreach ($node->getSubNodeNames() as $name) {
                $child = $node->$name;
                $children = is_array($child) ? $child : [$child];
                $out = [...$out, ...$this->returns(array_values(array_filter($children, static fn ($c): bool => $c instanceof Node)))];
            }
        }

        return $out;
    }
}
