<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Parsing;

use PhpParser\Node;
use PhpParser\Node\Stmt;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use TusharKhan\SemanticSec\Analysis\Category;

final class SuppressionCollector
{
    public const PATTERN = '/@semantic-sec-ignore\s+([A-Za-z0-9_-]+)(?:\s*:\s*(.+?))?\s*(?:\*\/)?$/m';

    /** @param array<\PhpParser\Node\Stmt> $ast */
    public function collect(string $file, array $ast): SuppressionSet
    {
        $visitor = new class ($file) extends NodeVisitorAbstract {
            /** @var array<string, Suppression> */
            public array $found = [];

            /** @var array<string, string> */
            public array $invalid = [];

            public function __construct(private string $file)
            {
            }

            public function enterNode(Node $node): null
            {
                // Comments on expressions are ignored; only statements and members scope code.
                if (! $node instanceof Stmt || $node->getComments() === []) {
                    return null;
                }

                foreach ($node->getComments() as $comment) {
                    if (preg_match_all(SuppressionCollector::PATTERN, $comment->getText(), $matches, PREG_SET_ORDER) === false) {
                        continue;
                    }
                    foreach ($matches as $m) {
                        $this->record($node, $comment->getStartLine(), $m[1], trim($m[2] ?? ''));
                    }
                }

                return null;
            }

            private function record(Node $node, int $commentLine, string $token, string $reason): void
            {
                $category = strtolower($token) === 'all' ? null : Category::fromToken($token);
                if ($category === null && strtolower($token) !== 'all') {
                    $message = sprintf('%s:%d: unknown category "%s"', $this->file, $commentLine, $token);
                    $this->invalid[$message] = $message;

                    return;
                }

                $start = $node->getStartLine();
                $end = $node->getEndLine();
                $key = $commentLine.'|'.($category->value ?? 'all').'|'.$start.'-'.$end;
                $this->found[$key] ??= new Suppression($this->file, $category, $start, $end, $commentLine, $reason === '' ? null : $reason);
            }
        };

        (new NodeTraverser($visitor))->traverse($ast);

        return new SuppressionSet(array_values($visitor->found), array_values($visitor->invalid));
    }
}
