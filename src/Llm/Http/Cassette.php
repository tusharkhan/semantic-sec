<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Llm\Http;

/**
 * Recorded HTTP interactions stored as JSON.
 *
 * @phpstan-type Interaction array{request: array{method: string, uri: string, headers: array<string, string>, body: string}, response: array{status: int, headers: array<string, string>, body: string}}
 */
final class Cassette
{
    /** @param list<Interaction> $interactions */
    private function __construct(public readonly string $path, private array $interactions)
    {
    }

    // A missing file is an empty cassette, ready to record into.
    public static function load(string $path): self
    {
        if (!is_file($path)) {
            return new self($path, []);
        }

        try {
            $json = json_decode((string) file_get_contents($path), true, 64, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new \LogicException("cassette {$path}: invalid JSON ({$e->getMessage()})", 0, $e);
        }
        if (!is_array($json) || !isset($json['interactions']) || !is_array($json['interactions']) || !array_is_list($json['interactions'])) {
            throw new \LogicException("cassette {$path}: missing interactions list");
        }

        /** @var list<Interaction> $interactions */
        $interactions = $json['interactions'];

        return new self($path, $interactions);
    }

    /** @return list<Interaction> */
    public function interactions(): array
    {
        return $this->interactions;
    }

    /** @param Interaction $interaction */
    public function add(array $interaction): void
    {
        $this->interactions[] = $interaction;
    }

    public function save(): void
    {
        $dir = dirname($this->path);
        if (!is_dir($dir) && !mkdir($dir, 0o777, true) && !is_dir($dir)) {
            throw new \RuntimeException("cassette {$this->path}: cannot create {$dir}");
        }
        $json = json_encode(['interactions' => $this->interactions], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        if (file_put_contents($this->path, $json . "\n") === false) {
            throw new \RuntimeException("cassette {$this->path}: cannot write");
        }
    }
}
