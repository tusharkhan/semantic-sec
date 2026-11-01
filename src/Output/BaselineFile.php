<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Output;

use TusharKhan\SemanticSec\Console\Application;
use TusharKhan\SemanticSec\Console\Terminal;
use TusharKhan\SemanticSec\Engine\AnalysisResult;
use TusharKhan\SemanticSec\Engine\Baseline;
use TusharKhan\SemanticSec\Engine\Vulnerability;

/** Reads and writes `semantic-sec-baseline.json` (plan decision 3); only the fingerprints are read back. */
final class BaselineFile
{
    public const DEFAULT = 'semantic-sec-baseline.json';

    public const VERSION = 1;

    public const MAX_BYTES = 16 * 1024 * 1024;

    private const FINGERPRINT = '~^[0-9a-f]{64}$~D';

    private const FLAGS = JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR;

    // A missing file is an empty baseline unless $required; anything unreadable or malformed throws, naming the file.
    public static function load(string $path, bool $required): Baseline
    {
        clearstatcache();
        if (! file_exists($path)) {
            if ($required) {
                throw new \RuntimeException("Baseline file not found: {$path}");
            }

            return Baseline::empty();
        }
        if (! is_file($path)) {
            throw new \RuntimeException("Baseline {$path} is not a regular file");
        }
        $size = @filesize($path);
        if ($size === false || $size > self::MAX_BYTES) {
            throw new \RuntimeException(sprintf('Baseline %s is larger than %d MB', $path, self::MAX_BYTES / 1024 / 1024));
        }
        $text = @file_get_contents($path, false, null, 0, self::MAX_BYTES + 1);
        if ($text === false || strlen($text) > self::MAX_BYTES) {
            throw new \RuntimeException("Cannot read baseline {$path}");
        }
        if (str_starts_with($text, "\xEF\xBB\xBF")) {
            throw new \RuntimeException("Baseline {$path} starts with a byte-order mark; save it without BOM");
        }
        try {
            $doc = json_decode($text, true, 16, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new \RuntimeException("Baseline {$path} is not valid JSON");
        }
        if (! is_array($doc) || ($doc['version'] ?? null) !== self::VERSION) {
            throw new \RuntimeException(sprintf('Baseline %s must be an object with "version": %d', $path, self::VERSION));
        }
        $entries = $doc['fingerprints'] ?? null;
        if (! is_array($entries) || ! array_is_list($entries)) {
            throw new \RuntimeException("Baseline {$path} must have a \"fingerprints\" list");
        }
        $fingerprints = [];
        foreach ($entries as $i => $entry) {
            $fingerprint = is_array($entry) ? ($entry['fingerprint'] ?? null) : null;
            if (! is_string($fingerprint) || preg_match(self::FINGERPRINT, $fingerprint) !== 1) {
                throw new \RuntimeException(sprintf('Baseline %s: entry %d has no 64-hex "fingerprint"', $path, $i));
            }
            $fingerprints[] = $fingerprint;
        }

        return Baseline::of($fingerprints);
    }

    // Every reported, filtered and baselined finding, never a suppressed one; sorted by fingerprint, so the bytes are stable.
    public static function write(string $path, AnalysisResult $r): int
    {
        [$text, $count] = self::encode($r);
        SafeWriter::write($path, $text);

        return $count;
    }

    /** @return array{string, int} the file's text and how many fingerprints it holds */
    private static function encode(AnalysisResult $r): array
    {
        $all = [...array_column($r->findings, 'vulnerability'), ...$r->filtered, ...$r->baselined];
        $entries = [];
        foreach ($all as $v) {
            /** @var Vulnerability $v */
            $entries[$v->fingerprint] ??= [
                'fingerprint' => $v->fingerprint,
                'category' => $v->category->value,
                'file' => Terminal::clean($v->file),
                'symbol' => Terminal::clean($v->symbol),
                'title' => Terminal::clean($v->title),
            ];
        }
        ksort($entries, SORT_STRING);

        return [json_encode(['version' => self::VERSION, 'tool' => Application::NAME, 'fingerprints' => array_values($entries)], self::FLAGS)."\n", count($entries)];
    }
}
