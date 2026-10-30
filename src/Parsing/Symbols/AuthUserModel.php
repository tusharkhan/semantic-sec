<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Parsing\Symbols;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use TusharKhan\SemanticSec\Framework\Laravel\ConstantEvaluator;
use TusharKhan\SemanticSec\Parsing\ParseResult;

/** The authenticated user's model class, read from `config/auth.php` without running it. */
final class AuthUserModel
{
    private const CONFIG = 'config/auth.php';

    private const FALLBACKS = ['App\\Models\\User', 'App\\User'];

    public static function resolve(ParseResult $parsed, SymbolTable $symbols, ConstantEvaluator $eval): ?string
    {
        $config = $parsed->file(self::CONFIG);
        if ($config !== null) {
            return self::fromConfig($config->ast, $eval);
        }
        foreach ($parsed->failures as $failure) {
            // The file exists but can't be read; the model could be anything.
            if ($failure->path === self::CONFIG) {
                return null;
            }
        }
        foreach (self::FALLBACKS as $class) {
            if ($symbols->getClass($class) !== null) {
                return $class;
            }
        }

        return null;
    }

    /** @param array<Stmt> $ast */
    private static function fromConfig(array $ast, ConstantEvaluator $eval): ?string
    {
        foreach ($ast as $stmt) {
            if (! $stmt instanceof Stmt\Return_) {
                continue;
            }
            $value = $stmt->expr;
            foreach (['providers', 'users', 'model'] as $key) {
                $value = $value instanceof Expr\Array_ ? self::item($value, $key) : null;
            }
            if ($value instanceof Expr\FuncCall && $value->name instanceof Node\Name && $value->name->toLowerString() === 'env') {
                $args = $value->getArgs();
                $value = count($args) === 2 && $args[1]->name === null && ! $args[1]->unpack && $args[1]->value instanceof Expr\ClassConstFetch ? $args[1]->value : null;
            }
            $class = $value === null ? null : $eval->string($value, self::CONFIG);

            return $class === null || $class === '' ? null : ltrim($class, '\\');
        }

        return null;
    }

    private static function item(Expr\Array_ $array, string $key): ?Expr
    {
        $found = null;
        foreach ($array->items as $item) {
            if ($item->unpack) {
                return null;
            }
            if ($item->key instanceof Node\Scalar\String_ && $item->key->value === $key) {
                $found = $item->value;
            }
        }

        return $found;
    }
}
