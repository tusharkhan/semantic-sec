<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Console;

use Symfony\Component\Console\Application as BaseApplication;
use TusharKhan\SemanticSec\Console\Commands\AnalyzeCommand;
use TusharKhan\SemanticSec\Console\Commands\BaselineCommand;
use TusharKhan\SemanticSec\Console\Commands\MapCommand;

final class Application extends BaseApplication
{
    public const NAME = 'semantic-sec';
    public const VERSION = '0.1.0-dev';

    public function __construct()
    {
        parent::__construct(self::NAME, self::VERSION);
        $this->add(new MapCommand());
        $this->add(new AnalyzeCommand());
        $this->add(new BaselineCommand());
    }
}
