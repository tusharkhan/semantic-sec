<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Console;

use Symfony\Component\Console\Application as BaseApplication;

final class Application extends BaseApplication
{
    public const NAME = 'semantic-sec';
    public const VERSION = '0.1.0-dev';

    public function __construct()
    {
        parent::__construct(self::NAME, self::VERSION);
    }
}
