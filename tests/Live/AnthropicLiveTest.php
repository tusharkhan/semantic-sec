<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Live;

use GuzzleHttp\Middleware;
use Opis\JsonSchema\Validator;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use TusharKhan\SemanticSec\Config\Defaults;
use TusharKhan\SemanticSec\Framework\Laravel\LaravelContext;
use TusharKhan\SemanticSec\Llm\FindingSchema;
use TusharKhan\SemanticSec\Llm\Http\Cassette;
use TusharKhan\SemanticSec\Llm\Http\CassetteHandler;
use TusharKhan\SemanticSec\Llm\Http\HttpClientFactory;
use TusharKhan\SemanticSec\Llm\LlmOutcome;
use TusharKhan\SemanticSec\Llm\LlmRequest;
use TusharKhan\SemanticSec\Llm\LlmResponse;
use TusharKhan\SemanticSec\Llm\Provider\AnthropicClient;
use TusharKhan\SemanticSec\Llm\SecurityPrompt;
use TusharKhan\SemanticSec\Payload\Payload;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkMaps;

/** One real request; runs only with SEMANTIC_SEC_LIVE=1, records with SEMANTIC_SEC_RECORD=1. Prints no key. */
final class AnthropicLiveTest extends TestCase
{
    private const CASSETTE = __DIR__.'/../Fixtures/cassettes/anthropic/live-idor-find-by-id.json';

    private const ROUTE = 'GET /vuln/invoices/{id}';

    public function testIdorFindByIdPayload(): void
    {
        if (getenv('SEMANTIC_SEC_LIVE') !== '1') {
            self::markTestSkipped('live test; set SEMANTIC_SEC_LIVE=1 to run it');
        }
        require_once __DIR__.'/bootstrap-env.php';
        $key = getenv('ANTHROPIC_API_KEY');
        if (!is_string($key) || $key === '') {
            self::markTestSkipped('ANTHROPIC_API_KEY is not set');
        }

        /** @var \ArrayObject<int, array<mixed>> $history */
        $history = new \ArrayObject();
        $container = $history;
        $middleware = ['history' => Middleware::history($container)];
        $handler = getenv('SEMANTIC_SEC_RECORD') === '1'
            ? new CassetteHandler(Cassette::load(self::CASSETTE), 'record', secrets: [$key])
            : null;
        $client = new AnthropicClient(HttpClientFactory::create($handler, $middleware), $key);

        $model = Defaults::model('anthropic');
        self::assertNotNull($model);
        $payload = self::payload();
        $request = new LlmRequest($payload->id, SecurityPrompt::system((new LaravelContext())->promptContext(), []), $payload->text(), FindingSchema::schema(), $model, 16000, 'high');
        $response = $client->analyze($request)->wait();
        self::assertInstanceOf(LlmResponse::class, $response);

        $usage = self::usage($history);
        fwrite(STDOUT, sprintf(
            "\nanthropic live: outcome=%s model=%s input_tokens=%d output_tokens=%d cache_creation_input_tokens=%d cache_read_input_tokens=%d findings=%s\n",
            $response->outcome->value,
            $response->model,
            $usage['input_tokens'] ?? 0,
            $usage['output_tokens'] ?? 0,
            $usage['cache_creation_input_tokens'] ?? 0,
            $usage['cache_read_input_tokens'] ?? 0,
            is_array($response->data['findings'] ?? null) ? (string) count($response->data['findings']) : '-',
        ));

        self::assertSame(LlmOutcome::Ok, $response->outcome, 'detail: '.($response->detail ?? '-'));
        $schema = json_decode((string) json_encode(FindingSchema::schema()), false);
        $data = json_decode((string) json_encode((object) $response->data), false);
        self::assertTrue((new Validator())->validate($data, $schema)->isValid(), 'the answer matches FindingSchema');
    }

    private static function payload(): Payload
    {
        [$candidates] = BenchmarkMaps::selector('laravel11-app')->select(BenchmarkMaps::build('laravel11-app'), false);
        foreach ($candidates as $candidate) {
            if (in_array(self::ROUTE, $candidate->route->keys(), true)) {
                [$payloads] = BenchmarkMaps::payloadBuilder('laravel11-app')->build($candidate, 1);
                self::assertCount(1, $payloads);

                return $payloads[0];
            }
        }
        self::fail(self::ROUTE.' is not a candidate');
    }

    /**
     * @param  \ArrayObject<int, array<mixed>>  $history
     * @return array<string, int>
     */
    private static function usage(\ArrayObject $history): array
    {
        $response = $history[0]['response'] ?? null;
        if (!$response instanceof ResponseInterface) {
            return [];
        }
        $body = $response->getBody();
        if ($body->isSeekable()) {
            $body->rewind();
        }
        $json = json_decode((string) $body, true);
        $usage = is_array($json) && is_array($json['usage'] ?? null) ? $json['usage'] : [];

        return array_filter($usage, 'is_int');
    }
}
