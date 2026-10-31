<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Engine;

use TusharKhan\SemanticSec\Config\CustomRuleset;
use TusharKhan\SemanticSec\Console\Application;
use TusharKhan\SemanticSec\Console\OutputDir;
use TusharKhan\SemanticSec\Llm\LlmOutcome;
use TusharKhan\SemanticSec\Llm\LlmResponse;
use TusharKhan\SemanticSec\Llm\ResponseValidator;
use TusharKhan\SemanticSec\Llm\SecurityPrompt;
use TusharKhan\SemanticSec\Payload\Payload;

/** Validated Ok answers on disk, keyed by everything that shapes the answer (SPEC §12). */
final class ResultCache
{
    public const DIR = '.semantic-sec/cache';

    private const FORMAT = 1;

    // Far deeper than any valid answer; deeper input is a miss, not a crash.
    private const MAX_DEPTH = 64;

    private readonly string $rulesetHash;

    private int $hits = 0;

    /** @var array<string, string> key => warning, one per entry */
    private array $warnings = [];

    /** @param list<CustomRuleset> $rulesets */
    public function __construct(
        private readonly string $dir,
        private readonly string $provider,
        private readonly string $model,
        array $rulesets,
        private readonly bool $readEnabled,
        private readonly string $toolVersion = Application::VERSION,
        private readonly string $promptVersion = SecurityPrompt::VERSION,
    ) {
        $pairs = array_map(static fn (CustomRuleset $r): array => [$r->name, $r->prompt], $rulesets);
        $this->rulesetHash = hash('sha256', json_encode($pairs, JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE));
    }

    /**
     * Creates <root>/.semantic-sec/cache behind the OutputDir guard; throws \RuntimeException on a symlink or escape.
     *
     * @param  list<CustomRuleset>  $rulesets
     */
    public static function inProject(string $root, string $provider, string $model, array $rulesets, bool $readEnabled): self
    {
        return new self(OutputDir::prepare($root, self::DIR), $provider, $model, $rulesets, $readEnabled);
    }

    // Components are JSON-encoded so no separator inside one can shift text into the next.
    public function key(Payload $p): string
    {
        $parts = [$this->toolVersion, $this->provider, $this->model, $this->promptVersion, $this->rulesetHash, $p->text()];

        return hash('sha256', json_encode($parts, JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE));
    }

    public function get(Payload $p): ?LlmResponse
    {
        if (! $this->readEnabled) {
            return null;
        }
        $key = $this->key($p);
        $file = $this->file($key);
        if (! is_link($file) && ! file_exists($file)) {
            return null;
        }
        $entry = $this->read($file);
        if ($entry === null) {
            $this->warnings[$key] = 'cache entry '.$key.' ignored';

            return null;
        }
        $this->hits++;

        return new LlmResponse($p->id, LlmOutcome::Ok, $entry['data'], 0, 0, $entry['model']);
    }

    public function put(Payload $p, LlmResponse $r): void
    {
        if ($r->outcome !== LlmOutcome::Ok || $r->data === null || ResponseValidator::errors($r->data) !== []) {
            return;
        }
        $key = $this->key($p);
        $temp = $this->dir.'/.'.$key.'.'.bin2hex(random_bytes(6)).'.tmp';
        try {
            $json = json_encode(['v' => self::FORMAT, 'model' => $r->model, 'data' => $r->data], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);
            $handle = @fopen($temp, 'x');
            if ($handle === false) {
                throw new \RuntimeException('open');
            }
            $written = @fwrite($handle, $json);
            fclose($handle);
            if ($written !== strlen($json) || ! @rename($temp, $this->file($key))) {
                throw new \RuntimeException('write');
            }
        } catch (\JsonException|\RuntimeException) {
            @unlink($temp);
            $this->warnings[$key] = 'cache entry '.$key.' not written';
        }
    }

    public function hits(): int
    {
        return $this->hits;
    }

    /** @return list<string> */
    public function warnings(): array
    {
        return array_values($this->warnings);
    }

    private function file(string $key): string
    {
        return $this->dir.'/'.$key.'.json';
    }

    // A symlinked, unreadable, malformed or invalid entry yields null; nothing here throws.
    /** @return array{model: string, data: array<string, mixed>}|null */
    private function read(string $file): ?array
    {
        if (is_link($file) || ! is_file($file)) {
            return null;
        }
        $raw = @file_get_contents($file);
        if ($raw === false || $raw === '') {
            return null;
        }
        try {
            $entry = json_decode($raw, true, self::MAX_DEPTH, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }
        if (! is_array($entry) || array_keys($entry) !== ['v', 'model', 'data'] || $entry['v'] !== self::FORMAT) {
            return null;
        }
        $model = $entry['model'];
        $data = $entry['data'];
        if (! is_string($model) || $model === '' || ! is_array($data) || ResponseValidator::errors($data) !== []) {
            return null;
        }

        /** @var array<string, mixed> $data */
        return ['model' => $model, 'data' => $data];
    }
}
