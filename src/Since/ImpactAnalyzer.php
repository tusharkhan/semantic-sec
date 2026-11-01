<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Since;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\NodeFinder;
use TusharKhan\SemanticSec\Candidates\Candidate;
use TusharKhan\SemanticSec\Config\Config;
use TusharKhan\SemanticSec\Framework\DetectedFramework;
use TusharKhan\SemanticSec\Framework\Laravel\Ancestry;
use TusharKhan\SemanticSec\Framework\Laravel\ConstantEvaluator;
use TusharKhan\SemanticSec\Framework\Laravel\MiddlewareRegistry;
use TusharKhan\SemanticSec\Framework\Laravel\PolicyRegistry;
use TusharKhan\SemanticSec\Parsing\CallGraph\PathNode;
use TusharKhan\SemanticSec\Parsing\FileFinder;
use TusharKhan\SemanticSec\Parsing\ParseResult;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;

/** Which candidates a set of changed files can affect (SPEC §12); when in doubt a candidate is affected. */
final class ImpactAnalyzer
{
    public const GLOBAL_FILES = ['app/Http/Kernel.php', 'bootstrap/app.php', 'config/auth.php'];

    public const GLOBAL_SUFFIXES = ['AuthServiceProvider.php', 'RouteServiceProvider.php'];

    // A changed class extending one of these can change every route's middleware, policies, gates or route files.
    private const GLOBAL_BASES = ['Illuminate\\Foundation\\Http\\Kernel', 'Illuminate\\Support\\ServiceProvider'];

    private readonly MiddlewareRegistry $middleware;

    private readonly PolicyRegistry $policies;

    private readonly NodeFinder $finder;

    // Unresolved kinds whose record names the classes the call may land in.
    private const NAMED = ['may-be-overridden', 'ambiguous', 'not-found'];

    // Unresolved kinds matched by method name against every project class.
    private const NAME_MATCHED = ['unknown-type', 'dynamic', 'not-found'];

    private const RECORD = '~^(.*?):(\d+): \[([a-z-]+)\] (.*)$~s';

    /** @var array<string, array<string, true>>|null lower-cased method name => files declaring it */
    private ?array $methods = null;

    public function __construct(private readonly ParseResult $parsed, private readonly SymbolTable $symbols, private readonly Config $config)
    {
        $eval = new ConstantEvaluator();
        [$this->middleware] = MiddlewareRegistry::fromProject($parsed, $symbols, new DetectedFramework('laravel', null), $eval, $config->authMiddleware, $config->authorizationMiddleware);
        [$this->policies] = PolicyRegistry::fromProject($symbols, $eval);
        $this->finder = new NodeFinder();
    }

    /**
     * @param  list<Candidate>  $candidates
     * @param  list<string>  $changed  root-relative paths
     * @return list<Candidate> the affected candidates, in their original order
     */
    public function affected(array $candidates, array $changed): array
    {
        $set = [];
        foreach ($changed as $path) {
            $set[(string) preg_replace('~^(\./)+~', '', $path)] = true;
        }
        if ($set === []) {
            return [];
        }
        foreach (array_keys($set) as $path) {
            if ($this->widensToAll((string) $path)) {
                return $candidates;
            }
        }

        return array_values(array_filter($candidates, fn (Candidate $c): bool => array_intersect_key($this->files($c), $set) !== []));
    }

    /** @return array<string, true> every project file whose change can alter what the candidate's payload says or means */
    public function files(Candidate $candidate): array
    {
        $route = $candidate->route;
        $files = [$route->file => true];
        $classes = [];
        foreach ($route->checks as $check) {
            $files[$check->file] = true;
            foreach ([$check->model, $check->abilityModel] as $model) {
                if ($model !== null) {
                    $classes[] = $model;
                }
            }
            foreach ($check->abilities ?? [] as $ability) {
                foreach ($this->policies->gateDefinitions($ability) as $define) {
                    $files[$define->file] = true;
                }
            }
        }
        foreach ($route->parameters as $parameter) {
            if ($parameter->boundModel !== null) {
                $classes[] = $parameter->boundModel;
            }
        }
        foreach ($this->middleware->expand($route->middleware) as $name) {
            $classes[] = $this->middleware->classOf($name);
        }
        if ($route->action->class !== null) {
            $classes[] = $route->action->class;
        }
        foreach ($candidate->path->nodes as $node) {
            $files[$node->file] = true;
            foreach ([$node->method?->class, $node->closureClass] as $class) {
                if ($class !== null) {
                    $classes[] = $class;
                }
            }
            $fn = $node->method->node ?? $node->closure;
            if ($fn !== null) {
                // Models, FormRequests and any other project class the code names.
                foreach ($this->finder->findInstanceOf($fn, Node\Name::class) as $name) {
                    $classes[] = $name->toString();
                }
            }
        }
        $this->unresolvedFiles($candidate, $files, $classes);
        $seen = [];
        foreach ($classes as $class) {
            $this->classFiles(ltrim($class, '\\'), $files, $seen);
        }
        foreach (array_keys($seen) as $class) {
            $policy = $this->policies->policyFor((string) $class);
            if ($policy !== null) {
                $this->classFiles($policy, $files, $seen);
            }
        }

        return $files;
    }

    /**
     * Calls the call graph could not resolve: the classes their records name, and every project file declaring the called method name.
     *
     * @param  array<string, true>  $files
     * @param  list<string>  $classes
     */
    private function unresolvedFiles(Candidate $candidate, array &$files, array &$classes): void
    {
        foreach ($candidate->path->unresolved as $record) {
            if (preg_match(self::RECORD, $record, $m) !== 1) {
                continue;
            }
            [, , $line, $kind, $rest] = $m;
            [$text, $detail] = array_pad(explode(' → ', $rest, 2), 2, '');
            if (in_array($kind, self::NAMED, true)) {
                preg_match_all('~[A-Za-z_\\\\][\\w\\\\]*~', $detail.' '.(str_starts_with($text, 'action ') ? substr($text, 7) : ''), $tokens);
                foreach ($tokens[0] as $token) {
                    $file = $this->symbols->getClass(ltrim($token, '\\'))?->file;
                    if ($file !== null) {
                        $files[$file] = true;
                    }
                }
            }
            $names = [];
            if (in_array($kind, self::NAME_MATCHED, true)) {
                preg_match_all('~(?:->|::)\s*(\w+)\s*\(~', $text, $called);
                $names = $called[1];
                foreach ($candidate->path->nodes as $node) {
                    if ($node->file === $m[1] && $node->startLine <= (int) $line && (int) $line <= $node->endLine) {
                        array_push($names, ...$this->calledNames($node, (int) $line));
                    }
                }
            } elseif ($kind === 'depth-limit') {
                // The node's own calls were not followed: look one level deeper.
                foreach ($candidate->path->nodes as $node) {
                    if ($node->id === $text) {
                        array_push($names, ...$this->calledNames($node, null));
                    }
                }
            }
            foreach ($names as $name) {
                $files += $this->methodIndex()[strtolower($name)] ?? [];
            }
        }
    }

    /** @return list<string> method names called in the node's body, only on $line when given */
    private function calledNames(PathNode $node, ?int $line): array
    {
        $fn = $node->method->node ?? $node->closure;
        if ($fn === null) {
            return [];
        }
        $names = [];
        foreach ($this->finder->find($fn, static fn (Node $n): bool => $n instanceof Expr\MethodCall || $n instanceof Expr\NullsafeMethodCall || $n instanceof Expr\StaticCall) as $call) {
            /** @var Expr\MethodCall|Expr\NullsafeMethodCall|Expr\StaticCall $call */
            if ($call->name instanceof Node\Identifier && ($line === null || $call->getStartLine() === $line)) {
                $names[] = $call->name->toString();
            }
        }

        return $names;
    }

    /** @return array<string, array<string, true>> */
    private function methodIndex(): array
    {
        if ($this->methods === null) {
            $this->methods = [];
            foreach ($this->symbols->all() as $class) {
                if (str_starts_with($class->file, 'vendor/')) {
                    continue;
                }
                foreach (array_keys($class->methods) as $name) {
                    $this->methods[strtolower((string) $name)][$class->file] = true;
                }
            }
        }

        return $this->methods;
    }

    private function widensToAll(string $path): bool
    {
        if (in_array($path, self::GLOBAL_FILES, true)) {
            return true;
        }
        foreach (self::GLOBAL_SUFFIXES as $suffix) {
            if (str_ends_with($path, $suffix)) {
                return true;
            }
        }
        foreach ($this->symbols->classesInFile($path) as $class) {
            if (Ancestry::descendsFrom($this->symbols, $class->name, self::GLOBAL_BASES)) {
                return true;
            }
        }
        foreach ($this->parsed->failures as $failure) {
            if ($failure->path === $path) {
                return true;
            }
        }
        $file = $this->parsed->file($path);
        if ($file === null) {
            // A deleted (or renamed-away) PHP file may have been a policy, model or middleware.
            return ! is_file(rtrim($this->config->projectRoot, '/').'/'.$path) && (new FileFinder())->includes($path, $this->config->exclude);
        }

        return $this->loadsRouteFiles($file->ast);
    }

    /** @param array<Node\Stmt> $ast */
    private function loadsRouteFiles(array $ast): bool
    {
        if ($this->finder->findFirstInstanceOf($ast, Expr\Include_::class) !== null) {
            return true;
        }

        return $this->finder->findFirst($ast, static function (Node $n): bool {
            if (! ($n instanceof Expr\MethodCall || $n instanceof Expr\StaticCall) || ! $n->name instanceof Node\Identifier || strtolower($n->name->toString()) !== 'group') {
                return false;
            }
            $args = $n->getArgs();
            $body = $args === [] ? null : $args[count($args) - 1]->value;

            return ! $body instanceof Expr\Closure && ! $body instanceof Expr\ArrowFunction;
        }) !== null;
    }

    /**
     * Adds the files of a project class, its parents, traits and interfaces.
     *
     * @param  array<string, true>  $files
     * @param  array<string, true>  $seen
     */
    private function classFiles(string $class, array &$files, array &$seen): void
    {
        if ($class === '' || isset($seen[$class])) {
            return;
        }
        $symbol = $this->symbols->getClass($class);
        if ($symbol === null) {
            return;
        }
        $seen[$class] = true;
        $files[$symbol->file] = true;
        foreach ([$symbol->parent, ...$symbol->traits, ...$symbol->interfaces] as $related) {
            if ($related !== null) {
                $this->classFiles(ltrim($related, '\\'), $files, $seen);
            }
        }
    }
}
