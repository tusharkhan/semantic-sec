<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Parsing;

final class ProjectParser
{
    public function __construct(private FileFinder $finder, private AstGenerator $generator, private int $maxFileBytes = SourceFile::DEFAULT_MAX_BYTES)
    {
    }

    /** @param  list<string>  $excludeGlobs */
    public function parse(string $root, array $excludeGlobs = []): ParseResult
    {
        $files = [];
        $failures = [];
        foreach ($this->finder->find($root, $excludeGlobs) as $relative) {
            try {
                $files[] = $this->generator->parse(SourceFile::fromPath($root, $relative, $this->maxFileBytes));
            } catch (ParseFailure $failure) {
                $failures[] = $failure;
            } catch (\Throwable $e) {
                $failures[] = new ParseFailure($relative, sprintf('internal error: %s: %s', $e::class, $e->getMessage()), null);
            }
        }

        return new ParseResult($files, $failures);
    }
}
