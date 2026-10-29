<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Parsing;

final readonly class ParseResult
{
    /** @var array<string, ParsedFile> */
    private array $byPath;

    /**
     * @param  list<ParsedFile>  $files
     * @param  list<ParseFailure>  $failures
     */
    public function __construct(public array $files, public array $failures)
    {
        $index = [];
        foreach ($files as $file) {
            $index[$file->file->path] ??= $file;
        }
        $this->byPath = $index;
    }

    public function file(string $path): ?ParsedFile
    {
        return $this->byPath[$path] ?? null;
    }
}
