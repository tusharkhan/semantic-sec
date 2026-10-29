<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Parsing;

final readonly class ParseResult
{
    /**
     * @param  list<ParsedFile>  $files
     * @param  list<ParseFailure>  $failures
     */
    public function __construct(public array $files, public array $failures)
    {
    }

    public function file(string $path): ?ParsedFile
    {
        foreach ($this->files as $file) {
            if ($file->file->path === $path) {
                return $file;
            }
        }

        return null;
    }
}
