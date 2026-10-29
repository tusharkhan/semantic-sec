<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Parsing;

final readonly class ParsedFile
{
    /** @param array<\PhpParser\Node\Stmt> $ast */
    public function __construct(public SourceFile $file, public array $ast, public SuppressionSet $suppressions)
    {
    }
}
