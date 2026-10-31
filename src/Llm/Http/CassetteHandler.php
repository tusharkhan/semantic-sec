<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Llm\Http;

use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\Utils as Psr7Utils;
use GuzzleHttp\Utils;
use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use TusharKhan\SemanticSec\Payload\Redactor;

/**
 * Guzzle handler that replays a cassette in order or by request body, or records real traffic into one.
 *
 * @phpstan-import-type Interaction from Cassette
 */
final class CassetteHandler
{
    private const MARK = '<scrubbed>';

    private const SECRET_HEADER = '/key|token|auth|secret|cookie|session/i';

    private const SECRET_QUERY = '/key|token|auth|secret|sig|password/i';

    private const TRANSPORT_HEADERS = ['content-encoding', 'content-length', 'transfer-encoding'];

    /** @var (callable(RequestInterface, array<string, mixed>): PromiseInterface)|null */
    private $inner = null;

    private int $position = 0;

    /** @var array<int, true> interactions already replayed in body mode */
    private array $used = [];

    /** @var list<string> every encoded form of every secret, longest first */
    private readonly array $needles;

    /**
     * @param (callable(RequestInterface, array<string, mixed>): PromiseInterface)|null $inner real handler for record mode; defaults to cURL
     * @param list<string> $secrets key values scrubbed from recordings (raw, URL, JSON and base64 forms) and from replayed URIs
     * @param string $match 'order' replays in recorded order, 'body' matches method, URI and scrubbed body hash in any order
     */
    public function __construct(private readonly Cassette $cassette, private readonly string $mode, ?callable $inner = null, #[\SensitiveParameter] array $secrets = [], private readonly string $match = 'order')
    {
        if ($mode !== 'replay' && $mode !== 'record') {
            throw new \InvalidArgumentException("cassette mode must be replay or record, got {$mode}");
        }
        if ($match !== 'order' && $match !== 'body') {
            throw new \InvalidArgumentException("cassette match must be order or body, got {$match}");
        }
        if ($mode === 'replay' && !is_file($cassette->path)) {
            throw new \LogicException("cassette not found: {$cassette->path}");
        }
        if ($mode === 'record') {
            $this->inner = $inner ?? Utils::chooseHandler();
            $cassette->clear();
        }
        $this->needles = self::needles($secrets);
    }

    // print_r and var_dump show neither the secrets nor their encoded forms.
    /** @return array<string, mixed> */
    public function __debugInfo(): array
    {
        return ['cassette' => $this->cassette->path, 'mode' => $this->mode, 'match' => $this->match, 'position' => $this->position, 'secrets' => '<hidden>'];
    }

    /** @param array<string, mixed> $options */
    public function __invoke(RequestInterface $request, array $options): PromiseInterface
    {
        return match (true) {
            $this->mode === 'record' => $this->record($request, $options),
            $this->match === 'body' => $this->replayByBody($request),
            default => $this->replay($request),
        };
    }

    public function assertExhausted(): void
    {
        $unused = $this->mode === 'replay' ? count($this->cassette->interactions()) - ($this->match === 'body' ? count($this->used) : $this->position) : 0;
        if ($unused > 0) {
            throw new \LogicException("cassette {$this->cassette->path}: {$unused} unused interactions");
        }
    }

    private function replay(RequestInterface $request): PromiseInterface
    {
        $actualUri = $this->normalizeUri((string) $request->getUri());
        $actual = $request->getMethod() . ' ' . $actualUri;
        $interaction = $this->cassette->interactions()[$this->position] ?? null;
        if ($interaction === null) {
            throw new \LogicException("cassette {$this->cassette->path}: expected no more requests, got {$actual}");
        }
        $expectedUri = $this->normalizeUri($interaction['request']['uri']);
        $expected = $interaction['request']['method'] . ' ' . $expectedUri;
        if (strcasecmp($interaction['request']['method'], $request->getMethod()) !== 0 || $expectedUri !== $actualUri) {
            throw new \LogicException("cassette {$this->cassette->path}: expected {$expected}, got {$actual}");
        }
        $this->position++;
        $response = $interaction['response'];

        return Create::promiseFor(new Response($response['status'], $response['headers'], $response['body']));
    }

    // The first unused interaction with the same method, URI and scrubbed body; a miss names only those and the hash.
    private function replayByBody(RequestInterface $request): PromiseInterface
    {
        $uri = $this->normalizeUri((string) $request->getUri());
        $hash = hash('sha256', self::redactBody(new Redactor(), $this->replaceSecrets(self::readBody($request))));
        foreach ($this->cassette->interactions() as $i => $interaction) {
            if (isset($this->used[$i])
                || strcasecmp($interaction['request']['method'], $request->getMethod()) !== 0
                || $this->normalizeUri($interaction['request']['uri']) !== $uri
                || !hash_equals(hash('sha256', $interaction['request']['body']), $hash)) {
                continue;
            }
            $this->used[$i] = true;
            $response = $interaction['response'];

            return Create::promiseFor(new Response($response['status'], $response['headers'], $response['body']));
        }

        throw new \LogicException("cassette {$this->cassette->path}: no unused interaction for {$request->getMethod()} {$uri} with body sha256 {$hash}");
    }

    /** @param array<string, mixed> $options */
    private function record(RequestInterface $request, array $options): PromiseInterface
    {
        $inner = $this->inner ?? throw new \LogicException('record mode has no handler');
        $requestBody = self::readBody($request);

        return $inner($request, $options)->then(function (ResponseInterface $response) use ($request, $requestBody): ResponseInterface {
            $responseBody = self::readBody($response);
            $this->cassette->add($this->clean([
                'request' => ['method' => $request->getMethod(), 'uri' => (string) $request->getUri(), 'headers' => self::headers($request), 'body' => $requestBody],
                'response' => ['status' => $response->getStatusCode(), 'headers' => self::headers($response, self::TRANSPORT_HEADERS), 'body' => $responseBody],
            ]));
            $this->cassette->save();

            return $response->withBody(Psr7Utils::streamFor($responseBody));
        });
    }

    /**
     * Replaces every secret form in every string first, then runs the Redactor over header values and bodies.
     *
     * @param Interaction $interaction
     * @return Interaction
     */
    private function clean(array $interaction): array
    {
        $interaction['request']['uri'] = $this->normalizeUri($interaction['request']['uri']);
        foreach (['request', 'response'] as $side) {
            $headers = [];
            foreach ($interaction[$side]['headers'] as $name => $value) {
                $headers[$this->replaceSecrets($name)] = $this->replaceSecrets($value);
            }
            $interaction[$side]['headers'] = $headers;
            $interaction[$side]['body'] = $this->replaceSecrets($interaction[$side]['body']);
        }

        $redactor = new Redactor();
        foreach (['request', 'response'] as $side) {
            $interaction[$side]['headers'] = array_map($redactor->redact(...), $interaction[$side]['headers']);
            $interaction[$side]['body'] = self::redactBody($redactor, $interaction[$side]['body']);
        }
        $this->assertNoSecretLeft($interaction);

        return $interaction;
    }

    // Last net over the serialized form; never names the secret.
    /** @param Interaction $interaction */
    private function assertNoSecretLeft(array $interaction): void
    {
        foreach ([JSON_UNESCAPED_SLASHES, 0] as $flags) {
            $json = json_encode($interaction, $flags | JSON_THROW_ON_ERROR);
            foreach ($this->needles as $needle) {
                if (str_contains($json, $needle)) {
                    throw new \LogicException("cassette {$this->cassette->path}: a secret survived scrubbing; nothing was saved");
                }
            }
        }
    }

    private function normalizeUri(string $uri): string
    {
        return $this->replaceSecrets(self::scrubUri($uri));
    }

    private function replaceSecrets(string $text): string
    {
        return $this->needles === [] ? $text : str_replace($this->needles, self::MARK, $text);
    }

    /**
     * @param list<string> $secrets
     * @return list<string>
     */
    private static function needles(array $secrets): array
    {
        $needles = [];
        foreach ($secrets as $secret) {
            if ($secret === '') {
                continue;
            }
            $forms = [$secret, base64_encode($secret)];
            foreach ([0, JSON_UNESCAPED_SLASHES, JSON_UNESCAPED_UNICODE, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE] as $flags) {
                $json = json_encode($secret, $flags);
                if ($json !== false) {
                    $forms[] = substr($json, 1, -1);
                }
            }
            foreach ($forms as $form) {
                array_push($needles, $form, urlencode($form), rawurlencode($form), self::uriEncode($form));
            }
        }
        $needles = array_values(array_unique(array_filter($needles, static fn (string $n): bool => $n !== '')));
        usort($needles, static fn (string $a, string $b): int => strlen($b) <=> strlen($a));

        return $needles;
    }

    // JSON bodies are redacted per string leaf so the result stays valid JSON; untouched bodies keep their bytes.
    private static function redactBody(Redactor $redactor, string $body): string
    {
        try {
            $decoded = json_decode($body, false, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return $redactor->redact($body);
        }
        if (!is_array($decoded) && !$decoded instanceof \stdClass) {
            return $redactor->redact($body);
        }
        $changed = false;
        $redacted = self::redactLeaves($redactor, $decoded, $changed);

        return $changed ? json_encode($redacted, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR) : $body;
    }

    private static function redactLeaves(Redactor $redactor, mixed $value, bool &$changed): mixed
    {
        if (is_string($value)) {
            $clean = $redactor->redact($value);
            $changed = $changed || $clean !== $value;

            return $clean;
        }
        if (is_array($value)) {
            return array_map(static fn (mixed $v): mixed => self::redactLeaves($redactor, $v, $changed), $value);
        }
        if ($value instanceof \stdClass) {
            $copy = new \stdClass();
            foreach (get_object_vars($value) as $k => $v) {
                $copy->{$k} = self::redactLeaves($redactor, $v, $changed);
            }

            return $copy;
        }

        return $value;
    }

    // Percent-encodes the way Guzzle's Uri does for paths and queries.
    private static function uriEncode(string $text): string
    {
        return (string) preg_replace_callback(
            '/(?:[^a-zA-Z0-9_\-\.~!\$&\'\(\)\*\+,;=%:@\/\?]++|%(?![A-Fa-f0-9]{2}))/',
            static fn (array $m): string => rawurlencode($m[0]),
            $text,
        );
    }

    // Replaces the value of every query parameter whose name looks secret.
    private static function scrubUri(string $uri): string
    {
        $parts = explode('?', $uri, 2);
        if (count($parts) < 2) {
            return $uri;
        }
        [$query, $fragment] = array_pad(explode('#', $parts[1], 2), 2, null);
        $pairs = array_map(static function (string $pair): string {
            [$name] = explode('=', $pair, 2);

            return preg_match(self::SECRET_QUERY, rawurldecode($name)) === 1 ? $name . '=' . self::MARK : $pair;
        }, explode('&', (string) $query));

        return $parts[0] . '?' . implode('&', $pairs) . ($fragment === null ? '' : '#' . $fragment);
    }

    // Reads the whole body and rewinds it so the real handler can still send it.
    private static function readBody(MessageInterface $message): string
    {
        $body = $message->getBody();
        $contents = (string) $body;
        if ($body->isSeekable()) {
            $body->rewind();
        }

        return $contents;
    }

    /**
     * @param list<string> $drop lowercase header names left out entirely
     * @return array<string, string>
     */
    private static function headers(MessageInterface $message, array $drop = []): array
    {
        $headers = [];
        foreach ($message->getHeaders() as $name => $values) {
            $name = (string) $name;
            if (in_array(strtolower($name), $drop, true)) {
                continue;
            }
            $headers[$name] = preg_match(self::SECRET_HEADER, $name) === 1 ? self::MARK : implode(', ', $values);
        }

        return $headers;
    }
}
