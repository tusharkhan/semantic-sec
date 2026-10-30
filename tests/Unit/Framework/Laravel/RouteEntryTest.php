<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Framework\Laravel;

use PhpParser\Node\Expr\Closure;
use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Framework\Laravel\AuthCheck;
use TusharKhan\SemanticSec\Framework\Laravel\AuthCheckKind;
use TusharKhan\SemanticSec\Framework\Laravel\AuthorizationMap;
use TusharKhan\SemanticSec\Framework\Laravel\AuthStrength;
use TusharKhan\SemanticSec\Framework\Laravel\RouteAction;
use TusharKhan\SemanticSec\Framework\Laravel\RouteEntry;
use TusharKhan\SemanticSec\Framework\Laravel\RouteParameter;

final class RouteEntryTest extends TestCase
{
    /** @param list<string> $methods */
    private function entry(array $methods, string $uri): RouteEntry
    {
        return new RouteEntry($methods, $uri, null, new RouteAction('App\X', 'show'), [], [], [], false, 'routes/web.php', 3);
    }

    public function testKeysForSingleMethod(): void
    {
        self::assertSame(['GET /vuln/invoices/{id}'], $this->entry(['GET'], '/vuln/invoices/{id}')->keys());
    }

    public function testKeysForMultipleMethodsKeepDeclaredOrder(): void
    {
        self::assertSame(['PUT /a', 'PATCH /a'], $this->entry(['PUT', 'PATCH'], '/a')->keys());
    }

    public function testWithChecksReturnsNewInstance(): void
    {
        $entry = $this->entry(['GET'], '/a');
        $check = new AuthCheck(AuthCheckKind::Authentication, AuthStrength::Authentication, 'auth', 'routes/web.php', 3);

        $new = $entry->withChecks([$check]);

        self::assertNotSame($entry, $new);
        self::assertSame([], $entry->checks);
        self::assertSame([$check], $new->checks);
    }

    public function testWithParametersReturnsNewInstance(): void
    {
        $entry = $this->entry(['GET'], '/a/{id}');
        $new = $entry->withParameters([new RouteParameter('id', null, false)]);

        self::assertNotSame($entry, $new);
        self::assertSame([], $entry->parameters);
        self::assertCount(1, $new->parameters);
    }

    public function testMapFindHitAndMiss(): void
    {
        $a = $this->entry(['GET'], '/a');
        $b = $this->entry(['PUT', 'PATCH'], '/b');
        $map = new AuthorizationMap([$a, $b], []);

        self::assertSame($b, $map->find('PATCH /b'));
        self::assertNull($map->find('DELETE /b'));
    }

    public function testActionSymbol(): void
    {
        $class = new RouteAction('App\X', 'show');
        self::assertSame('App\X::show', $class->symbol());
        self::assertFalse($class->isClosure());

        $closure = new RouteAction(null, null, new Closure());
        self::assertNull($closure->symbol());
        self::assertTrue($closure->isClosure());
    }
}
