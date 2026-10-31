<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Engine;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Analysis\Category;
use TusharKhan\SemanticSec\Analysis\Confidence;
use TusharKhan\SemanticSec\Analysis\Severity;
use TusharKhan\SemanticSec\Engine\Deduplicator;
use TusharKhan\SemanticSec\Engine\Vulnerability;

final class DeduplicatorTest extends TestCase
{
    public function testDedupKeepsHighestSeverityThenConfidenceAndMergesPaths(): void
    {
        $s1 = ['file' => 'a.php', 'line' => 1, 'symbol' => 'A::x'];
        $s2 = ['file' => 'a.php', 'line' => 2, 'symbol' => 'A::x'];
        $s3 = ['file' => 'b.php', 'line' => 9, 'symbol' => 'B::y'];
        $in = [
            self::v('one', 'f1', Severity::Medium, Confidence::High, [$s1]),
            self::v('other', 'f2', Severity::Low, Confidence::Low, [$s3]),
            self::v('two', 'f1', Severity::High, Confidence::Low, [$s2, $s1]),
            self::v('three', 'f1', Severity::High, Confidence::Medium, [$s3, $s2]),
            self::v('four', 'f1', Severity::High, Confidence::Medium, [$s1]),
        ];

        $out = (new Deduplicator())->merge($in);

        self::assertCount(2, $out);
        self::assertSame('three', $out[0]->title, 'highest severity, then confidence; first wins a tie');
        self::assertSame([$s3, $s2, $s1], $out[0]->path, 'winner first, then the rest in input order, unique');
        self::assertSame('other', $out[1]->title);
        self::assertSame([$s3], $out[1]->path);
    }

    public function testEmptyAndSingletons(): void
    {
        $d = new Deduplicator();
        $a = self::v('a', 'x', Severity::Low, Confidence::Low, []);

        self::assertSame([], $d->merge([]));
        self::assertSame([$a], $d->merge([$a]));
    }

    /** @param list<array{file:string,line:int,symbol:string}> $path */
    private static function v(string $title, string $fingerprint, Severity $severity, Confidence $confidence, array $path): Vulnerability
    {
        return new Vulnerability(Category::Idor, $severity, $confidence, $title, 'a.php', 1, 'A::x', '', '', '', '', $path, 'GET /a', 'p', 'm', $fingerprint);
    }
}
