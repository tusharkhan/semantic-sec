<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Console\Commands;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use TusharKhan\SemanticSec\Config\ConfigException;
use TusharKhan\SemanticSec\Console\ExitCode;
use TusharKhan\SemanticSec\Console\MapBuilder;
use TusharKhan\SemanticSec\Framework\DetectedFramework;
use TusharKhan\SemanticSec\Framework\FrameworkNotDetected;
use TusharKhan\SemanticSec\Framework\Laravel\AuthorizationMap;
use TusharKhan\SemanticSec\Framework\Laravel\AuthStrength;
use TusharKhan\SemanticSec\Framework\Laravel\RouteEntry;

#[AsCommand(name: 'map', description: 'Print the Laravel authorization map (no LLM, no API key)')]
final class MapCommand extends Command
{
    use ProjectOptions;

    protected function configure(): void
    {
        $this
            ->addOption('project-root', null, InputOption::VALUE_REQUIRED, 'Project root (default: current directory)')
            ->addOption('config', null, InputOption::VALUE_REQUIRED, 'Path to semantic-sec.yaml')
            ->addOption('framework', null, InputOption::VALUE_REQUIRED, 'Force the framework (laravel)')
            ->addOption('format', null, InputOption::VALUE_REQUIRED, 'console or json', 'console');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $format = (string) $input->getOption('format');
        if (! in_array($format, ['console', 'json'], true)) {
            return $this->fail($output, '--format must be console or json');
        }

        $root = $this->resolveRoot($input->getOption('project-root'));
        if ($root === null) {
            return $this->fail($output, 'Project root does not exist: '.(string) $input->getOption('project-root'));
        }

        try {
            [$map, $framework, $warnings] = (new MapBuilder())->build(
                $root,
                $this->stringOption($input, 'config'),
                $this->stringOption($input, 'framework'),
            );
        } catch (ConfigException|FrameworkNotDetected $e) {
            return $this->fail($output, $e->getMessage());
        }

        if ($format === 'json') {
            $output->writeln(json_encode($this->toArray($map, $framework, $warnings), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR));
        } else {
            $this->renderConsole($output, $map, $warnings);
        }

        return ExitCode::OK;
    }

    /** @param  list<string>  $warnings */
    private function renderConsole(OutputInterface $output, AuthorizationMap $map, array $warnings): void
    {
        $table = new Table($output);
        $table->setHeaders(['Method', 'URI', 'Action', 'Checks']);
        $withAuthorization = $authenticationOnly = $unprotected = 0;

        foreach ($map->routes as $route) {
            $table->addRow([
                implode('|', $route->methods),
                $route->uri,
                $route->action->isClosure() ? 'Closure' : ($route->action->symbol() ?? '?'),
                implode("\n", $this->collapsedChecks($route)),
            ]);
            $best = $this->best($route);
            match ($best) {
                AuthStrength::Authorization => $withAuthorization++,
                AuthStrength::Authentication => $authenticationOnly++,
                default => $unprotected++,
            };
        }
        $table->render();

        $output->writeln(sprintf(
            '%d routes: %d with authorization, %d authentication only, %d unprotected',
            count($map->routes),
            $withAuthorization,
            $authenticationOnly,
            $unprotected,
        ));

        if ($warnings !== []) {
            $output->writeln('');
            $output->writeln('Warnings');
            foreach ($warnings as $warning) {
                $output->writeln('  '.$warning);
            }
        }
    }

    private function best(RouteEntry $route): AuthStrength
    {
        $best = AuthStrength::None;
        foreach ($route->checks as $check) {
            if ($check->strength === AuthStrength::Authorization) {
                return AuthStrength::Authorization;
            }
            if ($check->strength === AuthStrength::Authentication) {
                $best = AuthStrength::Authentication;
            }
        }

        return $best;
    }

    /** @return list<string> */
    private function collapsedChecks(RouteEntry $route): array
    {
        $lines = [];
        foreach ($route->checks as $check) {
            $line = $check->kind->value.match ($check->strength) {
                AuthStrength::Authorization => '',
                AuthStrength::Authentication => ' (auth only)',
                AuthStrength::None => ' (none)',
            }.': '.$check->source;
            $lines[$line] = true;
        }

        return array_keys($lines);
    }

    /**
     * @param  list<string>  $warnings
     * @return array<string, mixed>
     */
    private function toArray(AuthorizationMap $map, DetectedFramework $framework, array $warnings): array
    {
        $routes = [];
        foreach ($map->routes as $route) {
            $routes[] = [
                'methods' => $route->methods,
                'uri' => $route->uri,
                'name' => $route->name,
                'action' => ['class' => $route->action->class, 'method' => $route->action->method, 'closure' => $route->action->isClosure()],
                'middleware' => $route->middleware,
                'withoutMiddleware' => $route->withoutMiddleware,
                'scopeBindings' => $route->scopeBindings,
                'file' => $route->file,
                'line' => $route->line,
                'parameters' => array_map(static fn ($p): array => ['name' => $p->name, 'field' => $p->field, 'optional' => $p->optional, 'boundModel' => $p->boundModel], $route->parameters),
                'checks' => array_map(static fn ($c): array => ['kind' => $c->kind->value, 'strength' => $c->strength->value, 'source' => $c->source, 'file' => $c->file, 'line' => $c->line, 'covers' => $c->covers, 'model' => $c->model], $route->checks),
            ];
        }

        return [
            'framework' => ['name' => $framework->name, 'major' => $framework->majorVersion],
            'routes' => $routes,
            'warnings' => $warnings,
        ];
    }
}
