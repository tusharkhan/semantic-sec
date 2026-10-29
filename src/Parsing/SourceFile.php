<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Parsing;

final readonly class SourceFile
{
    public function __construct(public string $path, public string $absolutePath, public string $code)
    {
    }

    public static function fromPath(string $root, string $relativePath): self
    {
        $absolute = rtrim($root, '/').'/'.$relativePath;
        $code = is_file($absolute) && is_readable($absolute) ? @file_get_contents($absolute) : false;
        if ($code === false) {
            throw new ParseFailure($relativePath, 'Cannot read file', null);
        }
        if (str_starts_with($code, "\xEF\xBB\xBF")) {
            $code = substr($code, 3);
        }

        return new self($relativePath, $absolute, $code);
    }
}
