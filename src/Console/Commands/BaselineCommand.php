<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Console\Commands;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Input\InputInterface;

/** `semantic-sec baseline`: analyze with --generate-baseline always on, same options and seams. */
#[AsCommand(name: 'baseline', description: 'Analyze, then write every current finding\'s fingerprint to the baseline file (alias for analyze --generate-baseline)')]
final class BaselineCommand extends AnalyzeCommand
{
    protected function generatesBaseline(InputInterface $input): bool
    {
        return true;
    }
}
