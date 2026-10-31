<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Integration\Payload;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Payload\Payload;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkMaps;

/** Pins the exact payload for the vulnerable idor-find-by-id route; regenerate with UPDATE_SNAPSHOTS=1. */
final class BenchmarkPayloadSnapshotTest extends TestCase
{
    private const SNAPSHOT = __DIR__.'/../../Fixtures/snapshots/idor-find-by-id.vuln.txt';

    public function testIdorFindByIdVulnerablePayloadMatchesSnapshot(): void
    {
        [$candidates] = BenchmarkMaps::selector('laravel11-app')->select(BenchmarkMaps::build('laravel11-app'), false);
        $candidate = null;
        foreach ($candidates as $c) {
            if (in_array('GET /vuln/invoices/{id}', $c->route->keys(), true)) {
                $candidate = $c;
            }
        }
        self::assertNotNull($candidate, 'GET /vuln/invoices/{id} is not a candidate');

        [$payloads, $warnings] = BenchmarkMaps::payloadBuilder('laravel11-app')->build($candidate, 1);
        self::assertSame([], $warnings);
        self::assertCount(1, $payloads);
        $actual = implode("\n\n", array_map(static fn (Payload $p): string => '=== '.$p->id.' ('.$p->part.'/'.$p->parts.($p->truncated ? ', truncated' : '').")\n".$p->text(), $payloads))."\n";

        if (getenv('UPDATE_SNAPSHOTS') === '1') {
            file_put_contents(self::SNAPSHOT, $actual);
        }
        self::assertFileExists(self::SNAPSHOT, 'run with UPDATE_SNAPSHOTS=1 to create it');
        self::assertSame(file_get_contents(self::SNAPSHOT), $actual);
    }
}
