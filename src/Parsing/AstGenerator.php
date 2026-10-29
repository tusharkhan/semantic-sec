<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Parsing;

use PhpParser\Error;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;
use PhpParser\Parser;
use PhpParser\ParserFactory;

final class AstGenerator
{
    private Parser $parser;

    public function __construct()
    {
        $this->parser = (new ParserFactory())->createForNewestSupportedVersion();
    }

    public function parse(SourceFile $file): ParsedFile
    {
        // Lone CR is not counted as a line by the parser; CRLF already is.
        $code = (string) preg_replace('/\r(?!\n)/', "\n", $file->code);

        try {
            $ast = $this->parser->parse($code) ?? [];
            $traverser = new NodeTraverser(new NameResolver(null, ['replaceNodes' => true]));
            /** @var array<\PhpParser\Node\Stmt> $ast */
            $ast = $traverser->traverse($ast);
        } catch (Error $e) {
            $line = $e->getStartLine();

            throw new ParseFailure($file->path, $e->getRawMessage(), $line > 0 ? $line : null);
        }

        return new ParsedFile($file, $ast, (new SuppressionCollector())->collect($file->path, $ast));
    }
}
