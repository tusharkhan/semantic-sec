<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Payload;

final readonly class PrunedMethod
{
    /** @param list<array{line:int, text:string}> $lines kept source lines with their original line numbers */
    public function __construct(
        public string $id,
        public string $file,
        public int $startLine,
        public int $endLine,
        public array $lines,
    ) {
    }
}
