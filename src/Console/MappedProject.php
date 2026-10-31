<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Console;

use TusharKhan\SemanticSec\Config\Config;
use TusharKhan\SemanticSec\Framework\DetectedFramework;
use TusharKhan\SemanticSec\Framework\Laravel\AuthorizationMap;
use TusharKhan\SemanticSec\Parsing\ParseResult;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;

/** A parsed project with its authorization map: the shared first stage of `map` and `analyze`. */
final readonly class MappedProject
{
    /** @param list<string> $warnings */
    public function __construct(
        public Config $config,
        public DetectedFramework $framework,
        public ParseResult $parsed,
        public SymbolTable $symbols,
        public AuthorizationMap $map,
        public array $warnings,
    ) {
    }
}
