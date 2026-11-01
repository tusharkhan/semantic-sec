<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Benchmark;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\CategoryInference;
use TusharKhan\SemanticSec\Tests\Support\Benchmark\Scorer;

final class CategoryInferenceTest extends TestCase
{
    /** @return iterable<string, array{array<string, mixed>, string, string}> */
    public static function findings(): iterable
    {
        yield 'cwe in the description wins' => [['category' => 'authorization_bypass', 'description' => 'Mass update (CWE-915) through fill()'], 'mass_assignment', 'cwe'];
        yield 'generic access-control cwe' => [['category' => 'security', 'description' => 'Improper authorization, CWE-285'], 'idor|missing_authorization', 'cwe'];
        yield 'our own token as category' => [['category' => 'IDOR', 'description' => 'x'], 'idor', 'category-field'];
        yield 'mass assignment keyword' => [['category' => 'input_validation', 'description' => 'request->all() is passed to update(), so is_admin can be set'], 'mass_assignment', 'keyword:mass_assignment'];
        yield 'deserialization keyword' => [['category' => 'rce', 'description' => 'unserialize() on cookie data'], 'insecure_deserialization', 'keyword:insecure_deserialization'];
        yield 'workflow keyword' => [['category' => 'business_logic', 'description' => 'An order can be cancelled after it shipped'], 'workflow_bypass', 'keyword:workflow_bypass'];
        yield 'ownership keyword' => [['category' => 'authorization_bypass', 'description' => 'Any user can read an invoice that belongs to another user'], 'idor', 'keyword:idor'];
        yield 'missing authorization keyword' => [['category' => 'privilege_escalation', 'description' => 'A non-merchant reaches the payout list'], 'missing_authorization', 'keyword:missing_authorization'];
        yield 'idor only in the exploit scenario' => [['category' => 'data_exposure', 'description' => 'Records are returned without checks', 'exploit_scenario' => "Attacker changes the id to read other users' receipts"], 'idor', 'exploit:idor'];
        yield 'generic access control' => [['category' => 'authorization_bypass', 'description' => 'The authorization check can be skipped'], 'idor|missing_authorization', 'access-control'];
        yield 'nothing to go on' => [['category' => 'sql_injection', 'description' => 'Raw query'], Scorer::ANY_CATEGORY, 'none'];
        yield 'empty finding' => [[], Scorer::ANY_CATEGORY, 'none'];
    }

    /** @param array<string, mixed> $finding */
    #[DataProvider('findings')]
    public function testInfersCategory(array $finding, string $category, string $rule): void
    {
        self::assertSame([$category, $rule], CategoryInference::infer($finding));
    }
}
