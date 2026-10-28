<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Analysis;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Analysis\Category;

final class CategoryTest extends TestCase
{
    public function testCweIds(): void
    {
        self::assertSame('CWE-639', Category::Idor->cweId());
        self::assertSame('CWE-862', Category::MissingAuthorization->cweId());
        self::assertSame('CWE-915', Category::MassAssignment->cweId());
        self::assertSame('CWE-502', Category::InsecureDeserialization->cweId());
        self::assertSame('CWE-841', Category::WorkflowBypass->cweId());
    }

    public function testLabels(): void
    {
        self::assertSame('Insecure Direct Object Reference (IDOR)', Category::Idor->label());
        self::assertSame('Missing Authorization', Category::MissingAuthorization->label());
        self::assertSame('Mass Assignment', Category::MassAssignment->label());
        self::assertSame('Insecure Deserialization', Category::InsecureDeserialization->label());
        self::assertSame('Workflow Bypass', Category::WorkflowBypass->label());
    }

    public function testFromTokenAcceptsValueCaseInsensitively(): void
    {
        self::assertSame(Category::Idor, Category::fromToken('IDOR'));
        self::assertSame(Category::Idor, Category::fromToken('idor'));
        self::assertSame(Category::MassAssignment, Category::fromToken('mass_assignment'));
        self::assertSame(Category::MassAssignment, Category::fromToken('  Mass_Assignment '));
    }

    public function testFromTokenAcceptsCweId(): void
    {
        self::assertSame(Category::MassAssignment, Category::fromToken('cwe-915'));
        self::assertSame(Category::Idor, Category::fromToken('CWE-639'));
    }

    public function testFromTokenReturnsNullForUnknown(): void
    {
        self::assertNull(Category::fromToken('sqli'));
        self::assertNull(Category::fromToken('CWE-89'));
        self::assertNull(Category::fromToken(''));
        self::assertNull(Category::fromToken('   '));
    }
}
