<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Console;

use Symfony\Component\Console\Application as BaseApplication;
use Symfony\Component\Console\Command\Command;
use TusharKhan\SemanticSec\Console\Commands\AnalyzeCommand;
use TusharKhan\SemanticSec\Console\Commands\BaselineCommand;
use TusharKhan\SemanticSec\Console\Commands\MapCommand;

final class Application extends BaseApplication
{
    public const NAME = 'semantic-sec';
    public const VERSION = '0.1.1';

    public function __construct()
    {
        parent::__construct(self::NAME, self::VERSION);
        foreach ([new MapCommand(), new AnalyzeCommand(), new BaselineCommand()] as $command) {
            self::attach($this, $command);
        }
    }

    // Symfony 8 removed add(); addCommand() exists from 7.4.
    public static function attach(BaseApplication $app, Command $command): void
    {
        // @phpstan-ignore function.alreadyNarrowedType (false on Symfony 6.4)
        if (method_exists($app, 'addCommand')) {
            $app->addCommand($command);
        } else {
            $app->add($command);
        }
    }
}
