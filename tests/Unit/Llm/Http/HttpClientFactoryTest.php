<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Llm\Http;

use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Llm\Http\HttpClientFactory;

final class HttpClientFactoryTest extends TestCase
{
    public function testRedirectsAreNeverFollowed(): void
    {
        $history = new \ArrayObject();
        $container = $history;
        $client = HttpClientFactory::create(
            new MockHandler([new Response(307, ['Location' => 'https://evil.example.test/x']), new Response(200)]),
            ['history' => Middleware::history($container)],
        );

        $response = $client->post('https://api.example.test/v1/one', ['headers' => ['x-api-key' => 'k'], 'http_errors' => false]);

        self::assertSame(307, $response->getStatusCode());
        self::assertCount(1, $history);
        self::assertFalse($client->getConfig('allow_redirects'));
    }
}
