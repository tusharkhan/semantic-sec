<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Engine;

use PhpParser\Node;
use PhpParser\NodeFinder;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor;
use PhpParser\NodeVisitor\CloningVisitor;
use PhpParser\NodeVisitorAbstract;
use PhpParser\PrettyPrinter\Standard;
use TusharKhan\SemanticSec\Analysis\Category;
use TusharKhan\SemanticSec\Parsing\ParseResult;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;
use TusharKhan\SemanticSec\Payload\Payload;

/** sha256(file | symbol | CWE | normalisedHash), stable across whitespace, comments and edits elsewhere (SPEC §11.2). */
final class Fingerprinter
{
    private const CLOSURE = '~^closure@(.+):(\d+)$~';

    private const HEADER = '~^// FILE: (.+) :: (.+?) \(L\d+-L\d+\)$~';

    private const TAG = '~^L\d+\| ?~';

    private readonly Standard $printer;

    /** @var array<string, array{string, ?string}> symbol => [canonical symbol, node hash or null] */
    private array $resolved = [];

    public function __construct(private readonly ParseResult $parsed, private readonly SymbolTable $symbols)
    {
        $this->printer = new Standard();
    }

    public function fingerprint(string $file, string $symbol, Category $c, Payload $p): string
    {
        [$canonical, $hash] = $this->resolved[$symbol] ??= $this->resolve($symbol);

        return hash('sha256', implode('|', [$file, $canonical, $c->cweId(), $hash ?? self::fallback($file, $symbol, $p)]));
    }

    // The symbol as written in one canonical way, and the hash of its node when one is found.
    /** @return array{string, ?string} */
    private function resolve(string $symbol): array
    {
        $name = ltrim(trim($symbol), '\\');
        if (preg_match(self::CLOSURE, $name, $m) === 1) {
            $node = $this->closure($m[1], (int) $m[2]);

            return $node === null ? [$name, null] : ['closure@'.$m[1], $this->hash($node)];
        }
        if (str_ends_with($name, '()') && !str_contains($name, '::')) {
            $function = $this->symbols->getFunction(substr($name, 0, -2));

            return $function === null ? [$name, null] : [$function->name.'()', $this->hash($function->node)];
        }
        $at = strpos($name, '::');
        if ($at === false) {
            $class = $this->symbols->getClass($name);

            return $class === null ? [$name, null] : [$class->name, $this->hash($class->node)];
        }
        $class = substr($name, 0, $at);
        $member = substr($name, $at + 2);
        if (str_starts_with($member, '$')) {
            $node = $this->property($class, substr($member, 1));

            return [$name, $node === null ? null : $this->hash($node)];
        }
        $method = $this->symbols->findMethod($class, (string) preg_replace('~\(\)$~', '', $member));

        return $method === null ? [$name, null] : [$class.'::'.$method->name, $this->hash($method->node)];
    }

    // The property statement that declares it, along the class lineage; a promoted parameter has none.
    private function property(string $class, string $name): ?Node\Stmt\Property
    {
        foreach ($this->symbols->lineage($class) as $owner) {
            foreach ($owner->node->getProperties() as $stmt) {
                foreach ($stmt->props as $item) {
                    if ($item->name->toString() === $name) {
                        return $stmt;
                    }
                }
            }
        }

        return null;
    }

    // The first closure or arrow function starting on that line of a parsed file.
    private function closure(string $file, int $line): ?Node\FunctionLike
    {
        $parsed = $this->parsed->file($file);
        if ($parsed === null) {
            return null;
        }
        $found = (new NodeFinder())->findFirst($parsed->ast, static fn (Node $n): bool => ($n instanceof Node\Expr\Closure || $n instanceof Node\Expr\ArrowFunction) && $n->getStartLine() === $line);

        return $found instanceof Node\FunctionLike ? $found : null;
    }

    // Prints a comment-free deep clone, so the shared AST keeps its comments.
    private function hash(Node $node): string
    {
        $clone = (new NodeTraverser(new CloningVisitor()))->traverse([$node]);
        $clone = (new NodeTraverser(new class () extends NodeVisitorAbstract {
            public function enterNode(Node $node): null
            {
                $node->setAttribute('comments', []);

                return null;
            }

            // A trailing comment parses as a Nop statement.
            public function leaveNode(Node $node): ?int
            {
                return $node instanceof Node\Stmt\Nop ? NodeVisitor::REMOVE_NODE : null;
            }
        }))->traverse($clone);
        $copy = $clone[0];

        return hash('sha256', $copy instanceof Node\Expr ? $this->printer->prettyPrintExpr($copy) : $this->printer->prettyPrint([$copy]));
    }

    // The header's tagged code without line tags, comments or layout, for ids with no node (gate:…, unknown).
    private static function fallback(string $file, string $symbol, Payload $p): string
    {
        $lines = [];
        $mine = false;
        foreach (explode("\n", $p->code) as $text) {
            if (preg_match(self::HEADER, $text, $m) === 1) {
                $mine = $m[1] === $file && $m[2] === $symbol;
            } elseif ($mine && preg_match(self::TAG, $text) === 1) {
                $lines[] = (string) preg_replace(self::TAG, '', $text);
            }
        }
        $code = '';
        foreach (token_get_all("<?php\n".implode("\n", $lines)) as $token) {
            if (is_array($token) && in_array($token[0], [T_OPEN_TAG, T_COMMENT, T_DOC_COMMENT], true)) {
                $code .= ' ';
            } else {
                $code .= is_array($token) ? $token[1] : $token;
            }
        }

        return hash('sha256', trim((string) preg_replace('~\s+~', ' ', $code)));
    }
}
