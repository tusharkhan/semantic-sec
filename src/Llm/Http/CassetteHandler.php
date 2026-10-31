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
 * Guzzle handler that replays a cassette in order, or records real traffic into one.
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

    /** @var list<string> */
    private readonly array $secrets;

    /**
     * @param (callable(RequestInterface, array<string, mixed>): PromiseInterface)|null $inner real handler for record mode; defaults to cURL
     * @param list<string> $secrets literal key values replaced everywhere in recorded interactions
     */
    public function __construct(private readonly Cassette $cassette, private readonly string $mode, ?callable $inner = null, array $secrets = [])
    {
        if ($mode !== 'replay' && $mode !== 'record') {
            throw new \InvalidArgumentException("cassette mode must be replay or record, got {$mode}");
        }
        if ($mode === 'replay' && !is_file($cassette->path)) {
            throw new \LogicException("cassette not found: {$cassette->path}");
        }
        if ($mode === 'record') {
            $this->inner = $inner ?? Utils::chooseHandler();
            $cassette->clear();
        }
        $this->secrets = array_values(array_filter($secrets, static fn (string $s): bool => $s !== ''));
    }

    /** @param array<string, mixed> $options */
    public function __invoke(RequestInterface $request, array $options): PromiseInterface
    {
        return $this->mode === 'replay' ? $this->replay($request) : $this->record($request, $options);
    }

    public function assertExhausted(): void
    {
        $unused = $this->mode === 'replay' ? count($this->cassette->interactions()) - $this->position : 0;
        if ($unused > 0) {
            throw new \LogicException("cassette {$this->cassette->path}: {$unused} unused interactions");
        }
    }

    private function replay(RequestInterface $request): PromiseInterface
    {
        $actual = $request->getMethod() . ' ' . self::scrubUri((string) $request->getUri());
        $interaction = $this->cassette->interactions()[$this->position] ?? null;
        if ($interaction === null) {
            throw new \LogicException("cassette {$this->cassette->path}: expected no more requests, got {$actual}");
        }
        $expectedUri = self::scrubUri($interaction['request']['uri']);
        $expected = $interaction['request']['method'] . ' ' . $expectedUri;
        if (strcasecmp($interaction['request']['method'], $request->getMethod()) !== 0 || $expectedUri !== self::scrubUri((string) $request->getUri())) {
            throw new \LogicException("cassette {$this->cassette->path}: expected {$expected}, got {$actual}");
        }
        $this->position++;
        $response = $interaction['response'];

        return Create::promiseFor(new Response($response['status'], $response['headers'], $response['body']));
    }

    /** @param array<string, mixed> $options */
    private function record(RequestInterface $request, array $options): PromiseInterface
    {
        $inner = $this->inner ?? throw new \LogicException('record mode has no handler');
        $requestBody = self::readBody($request);

        return $inner($request, $options)->then(function (ResponseInterface $response) use ($request, $requestBody): ResponseInterface {
            $responseBody = self::readBody($response);
            $this->cassette->add($this->clean([
                'request' => ['method' => $request->getMethod(), 'uri' => self::scrubUri((string) $request->getUri()), 'headers' => self::headers($request), 'body' => $requestBody],
                'response' => ['status' => $response->getStatusCode(), 'headers' => self::headers($response, self::TRANSPORT_HEADERS), 'body' => $responseBody],
            ]));
            $this->cassette->save();

            return $response->withBody(Psr7Utils::streamFor($responseBody));
        });
    }

    /**
     * Replaces configured secrets in every string, then runs the Redactor over header values and bodies.
     *
     * @param Interaction $interaction
     * @return Interaction
     */
    private function clean(array $interaction): array
    {
        $redactor = new Redactor();
        foreach (['request', 'response'] as $side) {
            foreach ($interaction[$side]['headers'] as $name => $value) {
                $interaction[$side]['headers'][$name] = $redactor->redact($this->replaceSecrets($value));
            }
            $interaction[$side]['body'] = self::redactBody($redactor, $this->replaceSecrets($interaction[$side]['body']));
        }
        $interaction['request']['uri'] = $this->replaceSecrets($interaction['request']['uri']);

        return $interaction;
    }

    private function replaceSecrets(string $text): string
    {
        return $this->secrets === [] ? $text : str_replace($this->secrets, self::MARK, $text);
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
