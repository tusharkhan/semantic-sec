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

/** Guzzle handler that replays a cassette in order, or records real traffic into one. */
final class CassetteHandler
{
    private const SCRUBBED = ['x-api-key', 'authorization', 'api-key'];

    /** @var (callable(RequestInterface, array<string, mixed>): PromiseInterface)|null */
    private $inner = null;

    private int $position = 0;

    /** @param (callable(RequestInterface, array<string, mixed>): PromiseInterface)|null $inner real handler for record mode; defaults to cURL */
    public function __construct(private readonly Cassette $cassette, private readonly string $mode, ?callable $inner = null)
    {
        if ($mode !== 'replay' && $mode !== 'record') {
            throw new \InvalidArgumentException("cassette mode must be replay or record, got {$mode}");
        }
        if ($mode === 'record') {
            $this->inner = $inner ?? Utils::chooseHandler();
        }
    }

    /** @param array<string, mixed> $options */
    public function __invoke(RequestInterface $request, array $options): PromiseInterface
    {
        return $this->mode === 'replay' ? $this->replay($request) : $this->record($request, $options);
    }

    private function replay(RequestInterface $request): PromiseInterface
    {
        $actual = $request->getMethod() . ' ' . $request->getUri();
        $interaction = $this->cassette->interactions()[$this->position] ?? null;
        if ($interaction === null) {
            throw new \LogicException("cassette {$this->cassette->path}: expected no more requests, got {$actual}");
        }
        $expected = $interaction['request']['method'] . ' ' . $interaction['request']['uri'];
        if (strcasecmp($interaction['request']['method'], $request->getMethod()) !== 0 || $interaction['request']['uri'] !== (string) $request->getUri()) {
            throw new \LogicException("cassette {$this->cassette->path}: expected {$expected}, got {$actual}");
        }
        $this->position++;
        $response = $interaction['response'];

        return Create::promiseFor(new Response($response['status'], $response['headers'], $response['body']));
    }

    /** @param array<string, mixed> $options */
    private function record(RequestInterface $request, array $options): PromiseInterface
    {
        $requestBody = self::readBody($request);

        $inner = $this->inner ?? throw new \LogicException('record mode has no handler');

        return $inner($request, $options)->then(function (ResponseInterface $response) use ($request, $requestBody): ResponseInterface {
            $responseBody = self::readBody($response);
            $this->cassette->add([
                'request' => ['method' => $request->getMethod(), 'uri' => (string) $request->getUri(), 'headers' => self::headers($request), 'body' => $requestBody],
                'response' => ['status' => $response->getStatusCode(), 'headers' => self::headers($response), 'body' => $responseBody],
            ]);
            $this->cassette->save();

            return $response->withBody(Psr7Utils::streamFor($responseBody));
        });
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

    /** @return array<string, string> */
    private static function headers(MessageInterface $message): array
    {
        $headers = [];
        foreach ($message->getHeaders() as $name => $values) {
            $headers[(string) $name] = in_array(strtolower((string) $name), self::SCRUBBED, true) ? '<scrubbed>' : implode(', ', $values);
        }

        return $headers;
    }
}
