<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Parsing;

use PhpParser\Node;
use PhpParser\Node\Stmt;
use PhpParser\Node\Stmt\ClassLike;
use PhpParser\Node\Stmt\Namespace_;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use TusharKhan\SemanticSec\Analysis\Category;

final class SuppressionCollector
{
    public const MARKER = '@semantic-sec-ignore';

    public const PATTERN = '/@semantic-sec-ignore[ \t]+([A-Za-z0-9_-]+)(?:[ \t]*:[ \t]*(.*?))?[ \t\r]*(?:\*\/)?[ \t\r]*$/';

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
                    foreach (preg_split('/\R/', $comment->getText()) ?: [] as $line) {
                        if (! str_contains($line, SuppressionCollector::MARKER)) {
                            continue;
                        }
                        if (preg_match(SuppressionCollector::PATTERN, $line, $m) === 1) {
                            $this->record($node, $comment->getStartLine(), $m[1], trim($m[2] ?? ''));
                        } else {
                            $this->reject(sprintf('%s:%d: malformed directive; expected "@semantic-sec-ignore <category>[: reason]"', $this->file, $comment->getStartLine()));
                        }
                    }
                }

                return null;
            }

            private function reject(string $message): void
            {
                $this->invalid[$message] = $message;
            }

            private function record(Node $node, int $commentLine, string $token, string $reason): void
            {
                if ($node instanceof Namespace_ || $node instanceof ClassLike) {
                    $scope = $node instanceof Namespace_ ? 'file' : 'class';
                    $this->reject(sprintf('%s:%d: %s-level suppression is not supported; put it above the method or statement', $this->file, $commentLine, $scope));

                    return;
                }

                $category = strtolower($token) === 'all' ? null : Category::fromToken($token);
                if ($category === null && strtolower($token) !== 'all') {
                    $this->reject(sprintf('%s:%d: unknown category "%s"', $this->file, $commentLine, $token));

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
