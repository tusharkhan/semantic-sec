<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Framework;

use TusharKhan\SemanticSec\Config\Config;
use TusharKhan\SemanticSec\Framework\Laravel\AuthorizationMap;
use TusharKhan\SemanticSec\Parsing\ParseResult;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;

interface FrameworkContext
{
    public function name(): string;

    public function buildAuthorizationMap(ParseResult $parsed, SymbolTable $symbols, Config $config, DetectedFramework $framework): AuthorizationMap;

    /** @return array<string, string> facade FQN and short alias (bare and with a leading backslash) => stable facade id */
    public function facadeMap(): array;

    // Short fixed framework notes, appended once to the system prompt.
    public function promptContext(): string;
}
