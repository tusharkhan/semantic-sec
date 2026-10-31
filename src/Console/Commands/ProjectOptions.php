<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Console\Commands;

use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use TusharKhan\SemanticSec\Console\ExitCode;

/** Option helpers shared by the commands that read a project. */
trait ProjectOptions
{
    private function fail(OutputInterface $output, string $message): int
    {
        $err = $output instanceof ConsoleOutputInterface ? $output->getErrorOutput() : $output;
        $err->writeln('Error: '.$message);

        return ExitCode::ERROR;
    }

    private function stringOption(InputInterface $input, string $name): ?string
    {
        $value = $input->getOption($name);

        return is_string($value) && $value !== '' ? $value : null;
    }

    private function resolveRoot(mixed $option): ?string
    {
        $path = is_string($option) && $option !== '' ? $option : getcwd();
        if ($path === false) {
            return null;
        }
        if (! str_starts_with($path, '/')) {
            $cwd = getcwd();
            $path = ($cwd === false ? '' : $cwd).'/'.$path;
        }
        $real = realpath($path);

        return $real !== false && is_dir($real) ? $real : null;
    }
}
