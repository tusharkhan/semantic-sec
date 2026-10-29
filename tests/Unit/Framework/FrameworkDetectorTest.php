<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Framework;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Framework\FrameworkDetector;
use TusharKhan\SemanticSec\Framework\FrameworkNotDetected;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;

final class FrameworkDetectorTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir().'/semantic-sec-fw-'.uniqid('', true);
        mkdir($this->dir);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir.'/*') ?: [] as $file) {
            unlink($file);
        }
        rmdir($this->dir);
    }

    public function testReadsMajorFromLockFile(): void
    {
        $found = (new FrameworkDetector())->detect(BenchmarkCorpus::root().'/laravel11-app');

        self::assertSame('laravel', $found->name);
        self::assertSame(11, $found->majorVersion);
    }

    public function testFallsBackToComposerJsonWithoutLock(): void
    {
        $found = (new FrameworkDetector())->detect(BenchmarkCorpus::root().'/laravel10-app');

        self::assertSame('laravel', $found->name);
        self::assertSame(10, $found->majorVersion);
    }

    public function testConstraintAlternativesUseHighestMajor(): void
    {
        $this->composer('{"require":{"laravel/framework":"^9.0|^10.0"}}');

        self::assertSame(10, (new FrameworkDetector())->detect($this->dir)->majorVersion);
    }

    public function testRangeConstraintUsesHighestMajor(): void
    {
        $this->composer('{"require":{"laravel/framework":">=10.0 <12"}}');

        self::assertSame(12, (new FrameworkDetector())->detect($this->dir)->majorVersion);
    }

    public function testFindsFrameworkInRequireDev(): void
    {
        $this->composer('{"require-dev":{"laravel/framework":"~10.48"}}');

        self::assertSame(10, (new FrameworkDetector())->detect($this->dir)->majorVersion);
    }

    public function testLockPackagesDevIsRead(): void
    {
        file_put_contents($this->dir.'/composer.lock', '{"packages":[],"packages-dev":[{"name":"laravel/framework","version":"v12.1.0"}]}');

        self::assertSame(12, (new FrameworkDetector())->detect($this->dir)->majorVersion);
    }

    public function testNonNumericLockVersionFallsBackToConstraint(): void
    {
        file_put_contents($this->dir.'/composer.lock', '{"packages":[{"name":"laravel/framework","version":"dev-master"}]}');
        $this->composer('{"require":{"laravel/framework":"11.x-dev"}}');

        self::assertSame(11, (new FrameworkDetector())->detect($this->dir)->majorVersion);
    }

    public function testMalformedJsonCountsAsNotFound(): void
    {
        file_put_contents($this->dir.'/composer.lock', '{not json');
        $this->composer('{"require":{"laravel/framework":"10.*"}}');

        self::assertSame(10, (new FrameworkDetector())->detect($this->dir)->majorVersion);
    }

    public function testThrowsWhenNoFrameworkFound(): void
    {
        $this->composer('{"require":{"monolog/monolog":"^3.0"}}');

        $this->expectException(FrameworkNotDetected::class);
        $this->expectExceptionMessage('--framework');

        (new FrameworkDetector())->detect($this->dir);
    }

    public function testForcedLaravelWithoutComposerFiles(): void
    {
        $found = (new FrameworkDetector())->detect($this->dir, 'laravel');

        self::assertSame('laravel', $found->name);
        self::assertNull($found->majorVersion);
    }

    public function testForcedNameIsCaseInsensitive(): void
    {
        self::assertSame('laravel', (new FrameworkDetector())->detect($this->dir, 'Laravel')->name);
    }

    public function testForcedUnsupportedFrameworkThrows(): void
    {
        $this->expectException(FrameworkNotDetected::class);
        $this->expectExceptionMessage('v1 supports: laravel');

        (new FrameworkDetector())->detect($this->dir, 'symfony');
    }

    private function composer(string $json): void
    {
        file_put_contents($this->dir.'/composer.json', $json);
    }
}
