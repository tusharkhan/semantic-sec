<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Payload;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use PhpParser\NodeFinder;
use TusharKhan\SemanticSec\Parsing\CallGraph\PathNode;
use TusharKhan\SemanticSec\Parsing\ParseResult;

/** Turns one call-graph node into compact source lines that keep their original line numbers. */
final class Pruner
{
    private const FUNCS = ['auth', 'abort_if', 'abort_unless', 'abort', 'throw_if', 'throw_unless', 'policy'];

    private const METHODS = ['authorize', 'authorizeresource', 'authorizeforuser', 'can', 'cannot', 'cant', 'user', 'denyaccessunlessgranted', 'isgranted'];

    private const FACADES = ['gate', 'auth'];

    private const DEBUG_FUNCS = ['dd', 'dump', 'var_dump', 'print_r', 'ray', 'logger', 'info'];

    /** @var array<string, array{lines: list<string>, code: array<int, true>, docs: list<array{int, int}>}> */
    private array $files = [];

    private NodeFinder $finder;

    public function __construct(private readonly ParseResult $parsed)
    {
        $this->finder = new NodeFinder();
    }

    /** @param list<string> $authHelpers method names or `Class::method` FQNs, matched case-insensitively */
    public function prune(PathNode $node, array $authHelpers): PrunedMethod
    {
        $fn = $node->method->node ?? $node->closure;
        $info = $this->file($node->file);
        if ($fn === null || $info === null) {
            return new PrunedMethod($node->id, $node->file, $node->startLine, $node->endLine, []);
        }

        $helpers = $this->helperSet($authHelpers);
        $stmts = $fn instanceof Expr\ArrowFunction ? [$fn->expr] : ($fn->getStmts() ?? []);

        if ($node->method !== null && $this->isTrivial($node->method->node)) {
            return new PrunedMethod($node->id, $node->file, $node->startLine, $node->endLine, [['line' => $node->startLine, 'text' => '// '.$node->id.': trivial accessor omitted']]);
        }

        $keep = [];
        $drop = [];
        foreach ($stmts as $stmt) {
            if ($this->isProtected($stmt, $helpers)) {
                $this->mark($keep, $stmt->getStartLine(), $stmt->getEndLine());
            } else {
                $this->collectDebug($stmt, $fn, $drop);
            }
        }

        $first = $node->startLine;
        $doc = $fn instanceof Stmt\ClassMethod ? $fn->getDocComment() : null;
        if ($doc !== null) {
            $first = min($first, $doc->getStartLine());
        }

        $docKeep = $this->docLines($info, $first, $node->endLine);
        $lines = [];
        for ($n = $first; $n <= $node->endLine && $n <= count($info['lines']); $n++) {
            if (isset($keep[$n]) || $n === $node->startLine || $n === $node->endLine) {
                $lines[] = ['line' => $n, 'text' => $info['lines'][$n - 1]];
            } elseif (isset($drop[$n])) {
                continue;
            } elseif (isset($docKeep[$n])) {
                if ($docKeep[$n]) {
                    $lines[] = ['line' => $n, 'text' => $info['lines'][$n - 1]];
                }
            } elseif (isset($info['code'][$n])) {
                $lines[] = ['line' => $n, 'text' => $info['lines'][$n - 1]];
            }
        }

        return new PrunedMethod($node->id, $node->file, $node->startLine, $node->endLine, $lines);
    }

    /** @return ?array{lines: list<string>, code: array<int, true>, docs: list<array{int, int}>} */
    private function file(string $path): ?array
    {
        if (isset($this->files[$path])) {
            return $this->files[$path];
        }
        $parsed = $this->parsed->file($path);
        if ($parsed === null) {
            return null;
        }
        // Same line model as AstGenerator: a lone CR is a line break; the BOM is not a character.
        $code = (string) preg_replace('/\r(?!\n)/', "\n", $parsed->file->code);
        if (str_starts_with($code, "\xEF\xBB\xBF")) {
            $code = substr($code, 3);
        }
        $lines = array_map(static fn (string $l): string => rtrim($l), explode("\n", $code));

        $codeLines = [];
        $docs = [];
        $line = 1;
        foreach (token_get_all($code) as $token) {
            $text = is_array($token) ? $token[1] : $token;
            $span = substr_count($text, "\n");
            $id = is_array($token) ? $token[0] : null;
            if ($id === T_DOC_COMMENT) {
                $docs[] = [$line, $line + $span];
            } elseif ($id !== T_WHITESPACE && $id !== T_COMMENT && $id !== T_OPEN_TAG) {
                // A trailing newline belongs to the line it ends, not the next one.
                $last = $line + $span - (str_ends_with($text, "\n") ? 1 : 0);
                for ($n = $line; $n <= max($line, $last); $n++) {
                    $codeLines[$n] = true;
                }
            }
            $line += $span;
        }

        return $this->files[$path] = ['lines' => $lines, 'code' => $codeLines, 'docs' => $docs];
    }

    /**
     * Docblock lines in the range: true = keep, false = drop. Lines that also hold code are left to the caller.
     *
     * @param  array{lines: list<string>, code: array<int, true>, docs: list<array{int, int}>}  $info
     * @return array<int, bool>
     */
    private function docLines(array $info, int $from, int $to): array
    {
        $result = [];
        foreach ($info['docs'] as [$a, $b]) {
            if ($b < $from || $a > $to) {
                continue;
            }
            $kept = false;
            $verdict = [];
            for ($n = $a; $n <= $b; $n++) {
                $text = trim($info['lines'][$n - 1] ?? '');
                if (isset($info['code'][$n])) {
                    continue;
                }
                $delimiter = $a !== $b && ($text === '/**' || $text === '*/');
                $has = ! $delimiter && preg_match('/@(?:param|return|var)\b/', $text) === 1;
                $verdict[$n] = $has;
                $kept = $kept || $has;
            }
            foreach ($verdict as $n => $has) {
                $text = trim($info['lines'][$n - 1] ?? '');
                $result[$n] = $has || ($kept && $a !== $b && ($text === '/**' || $text === '*/'));
            }
        }

        return $result;
    }

    /** @param array<int, true> $set */
    private function mark(array &$set, int $from, int $to): void
    {
        for ($n = $from; $n <= $to; $n++) {
            $set[$n] = true;
        }
    }

    /**
     * Lines of debug statements that sit alone on their lines.
     *
     * @param  array<int, true>  $drop
     */
    private function collectDebug(Node $root, Node $fn, array &$drop): void
    {
        $nodes = $this->finder->findInstanceOf($root, Stmt::class);
        $stmts = $root instanceof Stmt ? array_merge([$root], $nodes) : $nodes;
        foreach ($stmts as $stmt) {
            if (! $stmt instanceof Stmt\Expression || ! $this->isDebug($stmt->expr)) {
                continue;
            }
            $s = $stmt->getStartLine();
            $e = $stmt->getEndLine();
            $shared = $this->touches($fn, $s, $e);
            foreach ($stmts as $other) {
                $shared = $shared || ($other !== $stmt && $this->touches($other, $s, $e));
            }
            if (! $shared) {
                $this->mark($drop, $s, $e);
            }
        }
    }

    // True when another construct starts or ends on those lines, so they hold more than the debug call.
    private function touches(Node $other, int $s, int $e): bool
    {
        foreach ([$other->getStartLine(), $other->getEndLine()] as $l) {
            if ($l >= $s && $l <= $e) {
                return true;
            }
        }

        return false;
    }

    private function isDebug(Expr $expr): bool
    {
        while ($expr instanceof Expr\MethodCall || $expr instanceof Expr\NullsafeMethodCall) {
            $expr = $expr->var;
        }
        if ($expr instanceof Expr\FuncCall && $expr->name instanceof Node\Name) {
            return in_array(strtolower($expr->name->getLast()), self::DEBUG_FUNCS, true);
        }

        return $expr instanceof Expr\StaticCall && $expr->class instanceof Node\Name && strtolower($expr->class->getLast()) === 'log';
    }

    /**
     * @param  array{names: array<string, true>, statics: array<string, true>}  $helpers
     */
    private function isProtected(Node $stmt, array $helpers): bool
    {
        $found = $this->finder->findFirst($stmt, function (Node $n) use ($helpers): bool {
            if ($n instanceof Expr\FuncCall && $n->name instanceof Node\Name) {
                $name = strtolower($n->name->getLast());

                return in_array($name, self::FUNCS, true) || isset($helpers['names'][$name]);
            }
            if ($n instanceof Expr\MethodCall || $n instanceof Expr\NullsafeMethodCall || $n instanceof Expr\StaticCall) {
                $name = $n->name instanceof Node\Identifier ? strtolower($n->name->toString()) : null;
                if ($n instanceof Expr\StaticCall && $n->class instanceof Node\Name) {
                    if (in_array(strtolower($n->class->getLast()), self::FACADES, true)) {
                        return true;
                    }
                    if ($name !== null && isset($helpers['statics'][strtolower(ltrim($n->class->toString(), '\\')).'::'.$name])) {
                        return true;
                    }
                }

                return $name !== null && (in_array($name, self::METHODS, true) || isset($helpers['names'][$name]));
            }

            return false;
        });

        return $found !== null;
    }

    /**
     * A `Class::method` entry also protects a same-named method call on any receiver, since receiver types are not known here.
     *
     * @param  list<string>  $authHelpers
     * @return array{names: array<string, true>, statics: array<string, true>}
     */
    private function helperSet(array $authHelpers): array
    {
        $names = [];
        $statics = [];
        foreach ($authHelpers as $helper) {
            $helper = strtolower(ltrim(trim($helper), '\\'));
            if ($helper === '') {
                continue;
            }
            if (str_contains($helper, '::')) {
                $statics[$helper] = true;
                $helper = substr($helper, (int) strrpos($helper, '::') + 2);
            }
            $names[$helper] = true;
        }

        return ['names' => $names, 'statics' => $statics];
    }

    private function isTrivial(Stmt\ClassMethod $m): bool
    {
        if ($m->stmts === null) {
            return false;
        }
        // A comment-only body parses to a Nop.
        $stmts = array_values(array_filter($m->stmts, static fn (Stmt $s): bool => ! $s instanceof Stmt\Nop));
        if ($m->name->toLowerString() === '__construct') {
            return $stmts === [];
        }
        $first = $stmts[0] ?? null;
        if (count($stmts) === 1 && $first instanceof Stmt\Return_) {
            return $first->expr !== null && $this->isThisProp($first->expr);
        }
        $second = $stmts[1] ?? null;
        if ($first instanceof Stmt\Expression && $first->expr instanceof Expr\Assign
            && $this->isThisProp($first->expr->var) && $first->expr->expr instanceof Expr\Variable
            && is_string($first->expr->expr->name)) {
            $isParam = false;
            foreach ($m->params as $p) {
                $isParam = $isParam || ($p->var instanceof Expr\Variable && $p->var->name === $first->expr->expr->name);
            }

            return $isParam && (count($stmts) === 1
                || (count($stmts) === 2 && $second instanceof Stmt\Return_ && $second->expr instanceof Expr\Variable && $second->expr->name === 'this'));
        }

        return false;
    }

    private function isThisProp(Node $e): bool
    {
        return $e instanceof Expr\PropertyFetch && $e->var instanceof Expr\Variable && $e->var->name === 'this' && $e->name instanceof Node\Identifier;
    }
}
