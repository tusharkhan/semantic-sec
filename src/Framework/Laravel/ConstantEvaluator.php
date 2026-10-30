<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Framework\Laravel;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Scalar;
use PhpParser\Node\Stmt\ClassConst;
use TusharKhan\SemanticSec\Parsing\Symbols\ClassSymbol;

/** Statically evaluates string and project-relative path expressions; never runs code. */
final class ConstantEvaluator
{
    private const MAX_DEPTH = 8;

    public function string(Expr $expr, string $file, ?ClassSymbol $class = null): ?string
    {
        return $this->eval($expr, $file, $class, false, 0);
    }

    public function path(Expr $expr, string $file, ?ClassSymbol $class = null): ?string
    {
        $value = $this->eval($expr, $file, $class, true, 0);

        return $value === null ? null : self::normalisePath($value);
    }

    /** Normalises to a project-relative path ('' is the root); null if it escapes the root. */
    public static function normalisePath(string $path): ?string
    {
        $parts = [];
        foreach (explode('/', str_replace('\\', '/', $path)) as $segment) {
            if ($segment === '' || $segment === '.') {
                continue;
            }
            if ($segment === '..') {
                if ($parts === []) {
                    return null;
                }
                array_pop($parts);

                continue;
            }
            $parts[] = $segment;
        }

        return implode('/', $parts);
    }

    private function eval(Expr $expr, string $file, ?ClassSymbol $class, bool $path, int $depth): ?string
    {
        if ($depth > self::MAX_DEPTH) {
            return null;
        }
        $depth++;

        if ($expr instanceof Scalar\String_) {
            return $expr->value;
        }
        if ($expr instanceof Scalar\InterpolatedString) {
            $out = '';
            foreach ($expr->parts as $part) {
                if (! $part instanceof Node\InterpolatedStringPart) {
                    return null;
                }
                $out .= $part->value;
            }

            return $out;
        }
        if ($expr instanceof Expr\BinaryOp\Concat) {
            $l = $this->eval($expr->left, $file, $class, $path, $depth);
            $r = $l === null ? null : $this->eval($expr->right, $file, $class, $path, $depth);

            return $r === null ? null : $l.$r;
        }
        if ($expr instanceof Scalar\MagicConst\Dir) {
            $dir = dirname($file);

            return $dir === '' ? '.' : $dir;
        }
        if ($expr instanceof Expr\ClassConstFetch) {
            return $this->classConst($expr, $file, $class, $path, $depth);
        }
        if ($expr instanceof Expr\PropertyFetch) {
            return $this->thisProperty($expr, $file, $class, $path, $depth);
        }
        if ($path && $expr instanceof Expr\FuncCall) {
            return $this->pathFunction($expr, $file, $class, $depth);
        }

        return null;
    }

    private function classConst(Expr\ClassConstFetch $expr, string $file, ?ClassSymbol $class, bool $path, int $depth): ?string
    {
        if (! $expr->name instanceof Node\Identifier || ! $expr->class instanceof Node\Name) {
            return null;
        }
        $const = $expr->name->toString();
        $target = $expr->class->toString();
        $isSelf = in_array(strtolower($target), ['self', 'static'], true);

        if (strtolower($const) === 'class') {
            if ($isSelf) {
                return $class?->name;
            }

            return ltrim($target, '\\');
        }
        if (! $isSelf || $class === null) {
            return null;
        }
        foreach ($class->node->stmts as $stmt) {
            if (! $stmt instanceof ClassConst) {
                continue;
            }
            foreach ($stmt->consts as $c) {
                if ($c->name->toString() === $const) {
                    return $this->eval($c->value, $file, $class, $path, $depth);
                }
            }
        }

        return null;
    }

    private function thisProperty(Expr\PropertyFetch $expr, string $file, ?ClassSymbol $class, bool $path, int $depth): ?string
    {
        if ($class === null
            || ! $expr->var instanceof Expr\Variable || $expr->var->name !== 'this'
            || ! $expr->name instanceof Node\Identifier) {
            return null;
        }
        $default = ($class->properties[$expr->name->toString()] ?? null)?->default;

        return $default === null ? null : $this->eval($default, $class->file, $class, $path, $depth);
    }

    private function pathFunction(Expr\FuncCall $call, string $file, ?ClassSymbol $class, int $depth): ?string
    {
        if (! $call->name instanceof Node\Name) {
            return null;
        }
        $fn = strtolower($call->name->getLast());
        $args = $call->getArgs();
        if (array_filter($args, fn (Node\Arg $a): bool => $a->unpack || $a->name !== null) !== []) {
            return null;
        }

        if ($fn === 'base_path' || $fn === 'app_path') {
            if (count($args) > 1) {
                return null;
            }
            $base = $fn === 'app_path' ? 'app' : '';
            $sub = '';
            if ($args !== []) {
                $sub = $this->eval($args[0]->value, $file, $class, true, $depth);
                if ($sub === null) {
                    return null;
                }
            }
            $joined = self::normalisePath($base.'/'.$sub);

            return $joined === null ? null : ($joined === '' ? '.' : $joined);
        }

        if ($fn === 'dirname' && count($args) >= 1 && count($args) <= 2) {
            $levels = 1;
            if (isset($args[1])) {
                if (! $args[1]->value instanceof Scalar\Int_ || $args[1]->value->value < 1) {
                    return null;
                }
                $levels = $args[1]->value->value;
            }
            $inner = $this->eval($args[0]->value, $file, $class, true, $depth);
            $p = $inner === null ? null : self::normalisePath($inner);
            for ($i = 0; $p !== null && $i < $levels; $i++) {
                if ($p === '') {
                    return null;
                }
                $d = dirname($p);
                $p = $d === '.' ? '' : $d;
            }

            return $p === null ? null : ($p === '' ? '.' : $p);
        }

        return null;
    }
}
