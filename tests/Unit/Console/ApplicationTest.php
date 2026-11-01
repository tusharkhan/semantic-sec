<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Unit\Console;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Tester\ApplicationTester;
use TusharKhan\SemanticSec\Console\Application;

final class ApplicationTest extends TestCase
{
    public function testVersionFlagPrintsNameAndVersion(): void
    {
        $app = new Application();
        $app->setAutoExit(false);
        $tester = new ApplicationTester($app);

        $tester->run(['--version' => true]);

        self::assertStringContainsString('semantic-sec 0.1.0', $tester->getDisplay());
        self::assertSame(0, $tester->getStatusCode());
    }
}
