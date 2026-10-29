<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Parsing;

final class ParseFailure extends \RuntimeException
{
    public function __construct(public readonly string $path, string $message, public readonly ?int $sourceLine)
    {
        parent::__construct($message);
    }
}
