<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support\Benchmark;

use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Response;
use Psr\Http\Message\RequestInterface;

/** Guzzle handler that answers like Anthropic: one finding at the case's line for each vulnerable route, none elsewhere. No network. */
final class FakeAnthropicHandler
{
    public int $calls = 0;

    /** @param list<BenchmarkCase> $cases */
    public function __construct(private readonly array $cases, private readonly string $model = 'claude-opus-5-5')
    {
    }

    /** @param array<string, mixed> $options */
    public function __invoke(RequestInterface $request, array $options): PromiseInterface
    {
        $this->calls++;
        $body = json_decode((string) $request->getBody(), true);
        $user = is_array($body) && is_string($body['messages'][0]['content'] ?? null) ? $body['messages'][0]['content'] : '';
        $route = preg_match('~^Route:\n  (\S+ \S+)~m', $user, $m) === 1 ? $m[1] : '';
        $findings = [];
        foreach ($this->cases as $case) {
            $v = $case->vulnerable;
            if ($v->route === $route && $v->line !== null) {
                $findings[] = [
                    'title' => 'Fake finding for '.$case->id,
                    'category' => $case->category,
                    'severity' => 'high',
                    'confidence' => 'high',
                    'file' => $v->file,
                    'line' => $v->line,
                    'symbol' => $v->symbol,
                    'context' => $route,
                    'flaw' => 'fake',
                    'fix' => 'fake',
                    'patch' => '',
                    'path' => [['file' => $v->file, 'line' => $v->line, 'symbol' => $v->symbol]],
                ];
            }
        }
        $answer = [
            'id' => 'msg_fake_'.$this->calls,
            'type' => 'message',
            'role' => 'assistant',
            'model' => $this->model,
            'content' => [['type' => 'text', 'text' => json_encode(['findings' => $findings], JSON_THROW_ON_ERROR)]],
            'stop_reason' => 'end_turn',
            'stop_sequence' => null,
            'usage' => ['input_tokens' => 1000, 'output_tokens' => 200, 'cache_creation_input_tokens' => 0, 'cache_read_input_tokens' => 500],
        ];

        return Create::promiseFor(new Response(200, ['content-type' => 'application/json'], json_encode($answer, JSON_THROW_ON_ERROR)));
    }
}
