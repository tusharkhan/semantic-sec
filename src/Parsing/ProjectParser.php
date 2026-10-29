<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Parsing;

final class ProjectParser
{
    public function __construct(private FileFinder $finder, private AstGenerator $generator)
    {
    }

    /** @param  list<string>  $excludeGlobs */
    public function parse(string $root, array $excludeGlobs = []): ParseResult
    {
        $files = [];
        $failures = [];
        foreach ($this->finder->find($root, $excludeGlobs) as $relative) {
            try {
                $files[] = $this->generator->parse(SourceFile::fromPath($root, $relative));
            } catch (ParseFailure $failure) {
                $failures[] = $failure;
            }
        }

        return new ParseResult($files, $failures);
    }
}
