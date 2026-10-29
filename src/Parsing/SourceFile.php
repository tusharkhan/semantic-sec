<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Parsing;

final readonly class SourceFile
{
    public function __construct(public string $path, public string $absolutePath, public string $code)
    {
    }

    public const DEFAULT_MAX_BYTES = 1_048_576;

    public static function fromPath(string $root, string $relativePath, int $maxBytes = self::DEFAULT_MAX_BYTES): self
    {
        $absolute = rtrim($root, '/').'/'.$relativePath;
        $size = is_file($absolute) ? @filesize($absolute) : false;
        if ($size !== false && $size > $maxBytes) {
            throw new ParseFailure($relativePath, sprintf('skipped: %.1f MB exceeds the %.1f MB limit', $size / 1048576, $maxBytes / 1048576), null);
        }
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
