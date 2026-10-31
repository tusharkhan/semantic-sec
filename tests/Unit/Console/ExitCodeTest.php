<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Console;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Analysis\Category;
use TusharKhan\SemanticSec\Analysis\Confidence;
use TusharKhan\SemanticSec\Analysis\Severity;
use TusharKhan\SemanticSec\Console\ExitCode;
use TusharKhan\SemanticSec\Engine\AnalysisResult;
use TusharKhan\SemanticSec\Engine\Vulnerability;

final class ExitCodeTest extends TestCase
{
    public function testCleanRunIsZero(): void
    {
        self::assertSame(0, ExitCode::for(self::analysis([], ['sent' => 3, 'ok' => 3]), false));
        self::assertSame(0, ExitCode::for(self::analysis([], []), false), 'nothing to send is clean');
    }

    public function testFailingFindingIsOne(): void
    {
        self::assertSame(1, ExitCode::for(self::analysis([true], ['sent' => 1, 'ok' => 1]), false));
    }

    public function testOneBeatsThreeAndTwo(): void
    {
        self::assertSame(1, ExitCode::for(self::analysis([false, true], ['sent' => 2, 'ok' => 1, 'failed' => 1, 'budgetExceeded' => true]), false));
    }

    public function testBudgetWithoutFailingFindingsIsThree(): void
    {
        self::assertSame(3, ExitCode::for(self::analysis([false], ['sent' => 1, 'ok' => 1, 'budgetExceeded' => true]), false));
        self::assertSame(3, ExitCode::for(self::analysis([], ['budgetExceeded' => true]), false), 'budget below one reservation');
        self::assertSame(3, ExitCode::for(self::analysis([], ['sent' => 2, 'failed' => 2, 'budgetExceeded' => true]), false), 'three beats all-failed');
    }

    public function testAllFailedIsTwo(): void
    {
        self::assertSame(2, ExitCode::for(self::analysis([], ['sent' => 3, 'refused' => 1, 'truncated' => 1, 'invalid' => 1]), false));
        self::assertSame(2, ExitCode::for(self::analysis([], ['sent' => 2, 'failed' => 2]), false));
    }

    public function testOneSuccessIsNotAllFailed(): void
    {
        self::assertSame(0, ExitCode::for(self::analysis([], ['sent' => 3, 'ok' => 1, 'failed' => 2]), false));
        self::assertSame(0, ExitCode::for(self::analysis([], ['sent' => 2, 'failed' => 2, 'cacheHits' => 1]), false), 'a cache hit is a success');
    }

    public function testLowConfidenceOnlyIsZero(): void
    {
        self::assertSame(0, ExitCode::for(self::analysis([false, false], ['sent' => 1, 'ok' => 1]), false));
    }

    public function testStrictFailsOnAnyFailure(): void
    {
        foreach (['failed', 'refused', 'invalid', 'truncated'] as $kind) {
            $r = self::analysis([], ['sent' => 3, 'ok' => 2, $kind => 1]);
            self::assertSame(2, ExitCode::for($r, true), $kind);
            self::assertSame("strict: 1 {$kind}", ExitCode::strictReason($r, true));
        }
    }

    public function testStrictUnsentFails(): void
    {
        $r = self::analysis([false], ['sent' => 1, 'ok' => 1, 'unsent' => 2]);

        self::assertSame(2, ExitCode::for($r, true));
        self::assertSame('strict: 2 unsent', ExitCode::strictReason($r, true));
        self::assertSame(0, ExitCode::for($r, false));
        self::assertNull(ExitCode::strictReason($r, false));
    }

    public function testStrictReasonListsEveryNonZeroCount(): void
    {
        $r = self::analysis([], ['sent' => 5, 'ok' => 1, 'failed' => 3, 'refused' => 1, 'unsent' => 2]);

        self::assertSame('strict: 3 failed, 1 refused, 2 unsent', ExitCode::strictReason($r, true));
        self::assertNull(ExitCode::strictReason(self::analysis([], ['sent' => 2, 'ok' => 2]), true), 'clean strict run has no reason');
    }

    public function testOneBeatsStrict(): void
    {
        $r = self::analysis([true], ['sent' => 3, 'ok' => 1, 'failed' => 2, 'unsent' => 1]);

        self::assertSame(1, ExitCode::for($r, true));
        self::assertNull(ExitCode::strictReason($r, true), 'strict is not the reason when 1 wins');
    }

    public function testStrictBeatsThree(): void
    {
        $r = self::analysis([false], ['sent' => 1, 'ok' => 1, 'unsent' => 4, 'budgetExceeded' => true]);

        self::assertSame(2, ExitCode::for($r, true));
        self::assertSame(3, ExitCode::for($r, false));
        self::assertSame(3, ExitCode::for(self::analysis([], ['sent' => 1, 'ok' => 1, 'budgetExceeded' => true]), true), 'nothing failed or unsent: still 3');
    }

    public function testNonStrictUnchanged(): void
    {
        self::assertSame(0, ExitCode::for(self::analysis([], ['sent' => 3, 'ok' => 1, 'failed' => 1, 'truncated' => 1, 'unsent' => 2]), false));
        self::assertSame(2, ExitCode::for(self::analysis([], ['sent' => 2, 'failed' => 2]), false));
        self::assertSame(2, ExitCode::for(self::analysis([], ['sent' => 2, 'failed' => 2]), true), 'all-failed is still 2 under strict');
        self::assertSame(0, ExitCode::for(self::analysis([], ['sent' => 2, 'ok' => 2]), true));
    }

    /**
     * @param  list<bool>  $failing
     * @param  array<string, int|bool>  $stats
     */
    private static function analysis(array $failing, array $stats): AnalysisResult
    {
        $base = ['candidates' => 0, 'payloads' => 0, 'skipped' => 0, 'unsent' => 0, 'sent' => 0, 'cacheHits' => 0, 'ok' => 0, 'refused' => 0, 'truncated' => 0, 'invalid' => 0, 'failed' => 0, 'dropped' => 0, 'filtered' => 0, 'tokens' => 0, 'budgetExceeded' => false];
        $findings = array_map(static fn (bool $f): array => ['vulnerability' => self::vulnerability(), 'failing' => $f], $failing);

        /** @phpstan-ignore argument.type (the spread keeps every Stats key) */
        return new AnalysisResult($findings, [], [], [], [...$base, ...$stats]);
    }

    private static function vulnerability(): Vulnerability
    {
        return new Vulnerability(Category::Idor, Severity::High, Confidence::High, 't', 'a.php', 1, 'A::b', '', '', '', '', [], 'GET /x', '001-x-1', 'm', str_repeat('a', 64));
    }
}
