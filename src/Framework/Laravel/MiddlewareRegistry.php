<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Framework\Laravel;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\NodeFinder;
use TusharKhan\SemanticSec\Framework\DetectedFramework;
use TusharKhan\SemanticSec\Parsing\ParseResult;
use TusharKhan\SemanticSec\Parsing\Symbols\ClassSymbol;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;

/** Resolves middleware aliases and groups from app source plus Laravel defaults. */
final class MiddlewareRegistry
{
    public const DEFAULT_ALIASES = [
        'auth' => 'Illuminate\Auth\Middleware\Authenticate',
        'auth.basic' => 'Illuminate\Auth\Middleware\AuthenticateWithBasicAuth',
        'auth.session' => 'Illuminate\Session\Middleware\AuthenticateSession',
        'cache.headers' => 'Illuminate\Http\Middleware\SetCacheHeaders',
        'can' => 'Illuminate\Auth\Middleware\Authorize',
        'guest' => 'Illuminate\Auth\Middleware\RedirectIfAuthenticated',
        'password.confirm' => 'Illuminate\Auth\Middleware\RequirePassword',
        'precognitive' => 'Illuminate\Foundation\Http\Middleware\HandlePrecognitiveRequests',
        'signed' => 'Illuminate\Routing\Middleware\ValidateSignature',
        'subscribed' => '\Spark\Http\Middleware\VerifyBillableIsSubscribed',
        'throttle' => 'Illuminate\Routing\Middleware\ThrottleRequests',
        'verified' => 'Illuminate\Auth\Middleware\EnsureEmailIsVerified',
    ];

    // Framework group members are never auth-relevant, so only the names are kept.
    public const DEFAULT_GROUPS = ['web' => [], 'api' => []];

    private const AUTHORIZE = 'Illuminate\\Auth\\Middleware\\Authorize';

    private const AUTHENTICATION_CLASSES = [
        'Illuminate\\Auth\\Middleware\\Authenticate',
        'Illuminate\\Auth\\Middleware\\AuthenticateWithBasicAuth',
        'Illuminate\\Auth\\Middleware\\EnsureEmailIsVerified',
        'Illuminate\\Routing\\Middleware\\ValidateSignature',
    ];

    private const KERNEL = 'Illuminate\Foundation\Http\Kernel';

    /** @var list<string> */
    private array $authMiddleware = [];

    /** @var list<string> */
    private array $authClasses = [];

    /** @var array<string, true> authorization_middleware entries, backslash-trimmed */
    private array $authorizationNames = [];

    /** @var array<string, true> the same entries lower-cased, for class matching */
    private array $authorizationClasses = [];

    /** @var array<string, string> target class => alias (first alias wins) */
    private array $targets = [];

    /**
     * @param  array<string, string>  $aliases  alias => class[:params], app entries first
     * @param  array<string, list<string>>  $groups
     */
    public function __construct(private array $aliases, private array $groups, private SymbolTable $symbols)
    {
        foreach (self::DEFAULT_ALIASES as $alias => $target) {
            if (isset($aliases[$alias])) {
                $this->targets[ltrim($target, '\\')] ??= $alias;
            }
        }
        foreach ($aliases as $alias => $target) {
            $this->targets[ltrim(explode(':', $target)[0], '\\')] ??= (string) $alias;
        }
    }

    /**
     * @param  list<string>  $authMiddleware  configured alias names or class FQNs that authenticate
     * @param  list<string>  $authorizationMiddleware  configured alias names or class FQNs that authorize
     * @return array{0: self, 1: list<string>}
     */
    public static function fromProject(ParseResult $parsed, SymbolTable $symbols, DetectedFramework $fw, ConstantEvaluator $eval, array $authMiddleware = [], array $authorizationMiddleware = []): array
    {
        $aliases = [];
        $groups = self::DEFAULT_GROUPS;
        $warnings = [];

        foreach ($symbols->all() as $class) {
            if (self::extendsKernel($class, $symbols)) {
                self::readKernel($class, $eval, $aliases, $groups, $warnings);
            }
        }
        $bootstrap = $parsed->file('bootstrap/app.php');
        if ($bootstrap !== null) {
            self::readBootstrap($bootstrap->ast, 'bootstrap/app.php', $eval, $aliases, $groups, $warnings);
        }

        $registry = new self($aliases + self::DEFAULT_ALIASES, $groups, $symbols);
        $registry->authMiddleware = array_map(static fn (string $m): string => ltrim($m, '\\'), $authMiddleware);
        $registry->authClasses = array_map('strtolower', $registry->authMiddleware);
        foreach ($authorizationMiddleware as $m) {
            $registry->authorizationNames[ltrim($m, '\\')] = true;
            $registry->authorizationClasses[strtolower(ltrim($m, '\\'))] = true;
        }

        return [$registry, $warnings];
    }

    public function canonical(string $middleware): string
    {
        $middleware = ltrim($middleware, '\\');
        $pos = strpos($middleware, ':');
        $name = $pos === false ? $middleware : substr($middleware, 0, $pos);
        $params = $pos === false ? '' : substr($middleware, $pos);

        if (isset($this->aliases[$name])) {
            return $name.$params;
        }
        $seen = [];
        $class = $name;
        while ($class !== null && ! isset($seen[$class])) {
            $seen[$class] = true;
            if (isset($this->targets[$class])) {
                return $this->targets[$class].$params;
            }
            $class = $this->symbols->getClass($class)?->parent;
        }

        return $middleware;
    }

    /**
     * @param  list<string>  $middleware
     * @return list<string>
     */
    public function expand(array $middleware): array
    {
        $out = [];
        $this->expandInto($middleware, [], $out);

        return array_keys($out);
    }

    public function kind(string $canonical): MiddlewareKind
    {
        $name = explode(':', $canonical, 2)[0];
        if (in_array($name, ['auth', 'auth.basic', 'verified', 'signed'], true)) {
            return MiddlewareKind::Authentication;
        }
        if ($this->isAbility($canonical)) {
            return MiddlewareKind::Ability;
        }
        if ($this->isConfiguredAuthorization($name)) {
            return MiddlewareKind::Authorization;
        }

        return $this->descendsFrom($name, self::AUTHENTICATION_CLASSES) || $this->isConfiguredAuth($name) ? MiddlewareKind::Authentication : MiddlewareKind::Other;
    }

    /** @return array{ability: string, arguments: list<string>}|null */
    public function ability(string $canonical): ?array
    {
        if (! $this->isAbility($canonical)) {
            return null;
        }
        $parts = explode(',', explode(':', $canonical, 2)[1]);
        $ability = array_shift($parts);

        return ['ability' => $ability, 'arguments' => $parts];
    }

    private function isAbility(string $canonical): bool
    {
        $parts = explode(':', $canonical, 2);

        return isset($parts[1]) && $parts[1] !== '' && ($parts[0] === 'can' || $this->descendsFrom($parts[0], [self::AUTHORIZE]));
    }

    // An authorization_middleware entry matches the alias name exactly, or the class FQN case-insensitively.
    private function isConfiguredAuthorization(string $name): bool
    {
        if ($this->authorizationNames === []) {
            return false;
        }
        $name = ltrim($name, '\\');
        if (isset($this->authorizationNames[$name])) {
            return true;
        }
        $class = isset($this->aliases[$name]) ? ltrim(explode(':', $this->aliases[$name])[0], '\\') : $name;
        // An unaliased name is compared as a class only when it looks like one.
        $isClass = isset($this->aliases[$name]) || str_contains($name, '\\') || $this->symbols->getClass($name) !== null;

        return $isClass && isset($this->authorizationClasses[strtolower($class)]);
    }

    // A configured entry matches the alias name, or the class (or an ancestor) case-insensitively.
    private function isConfiguredAuth(string $name): bool
    {
        if ($this->authMiddleware === []) {
            return false;
        }
        if (in_array($name, $this->authMiddleware, true)) {
            return true;
        }
        $class = isset($this->aliases[$name]) ? ltrim(explode(':', $this->aliases[$name])[0], '\\') : ltrim($name, '\\');
        $seen = [];
        while ($class !== '' && ! isset($seen[strtolower($class)])) {
            $seen[strtolower($class)] = true;
            if (in_array(strtolower($class), $this->authClasses, true)) {
                return true;
            }
            $parent = $this->symbols->getClass($class)?->parent;
            $class = $parent === null ? '' : ltrim($parent, '\\');
        }

        return false;
    }

    /** @param list<string> $bases */
    private function descendsFrom(string $alias, array $bases): bool
    {
        // An unaliased name is taken as a class FQN.
        $class = isset($this->aliases[$alias]) ? ltrim(explode(':', $this->aliases[$alias])[0], '\\') : ltrim($alias, '\\');
        return Ancestry::descendsFrom($this->symbols, $class, $bases);
    }

    /**
     * @param  list<string>  $items
     * @param  array<string, true>  $stack
     * @param  array<string, true>  $out
     */
    private function expandInto(array $items, array $stack, array &$out): void
    {
        foreach ($items as $item) {
            $name = ltrim($item, '\\');
            if (isset($this->groups[$name])) {
                if (! isset($stack[$name])) {
                    $this->expandInto($this->groups[$name], $stack + [$name => true], $out);
                }

                continue;
            }
            $out[$this->canonical($item)] = true;
        }
    }

    private static function extendsKernel(ClassSymbol $class, SymbolTable $symbols): bool
    {
        $seen = [];
        for ($parent = $class->parent; $parent !== null && ! isset($seen[$parent]); $parent = $symbols->getClass($parent)?->parent) {
            $seen[$parent] = true;
            if (ltrim($parent, '\\') === self::KERNEL) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  array<string, string>  $aliases
     * @param  array<string, list<string>>  $groups
     * @param  list<string>  $warnings
     */
    private static function readKernel(ClassSymbol $class, ConstantEvaluator $eval, array &$aliases, array &$groups, array &$warnings): void
    {
        foreach (['middlewareAliases', 'routeMiddleware'] as $prop) {
            $default = $class->properties[$prop]->default ?? null;
            if ($default instanceof Expr\Array_) {
                self::readAliases($default, $class->file, $eval, $class, $aliases, $warnings);
            }
        }
        $default = $class->properties['middlewareGroups']->default ?? null;
        if ($default instanceof Expr\Array_) {
            foreach ($default->items as $item) {
                $key = $item->key !== null ? $eval->string($item->key, $class->file, $class) : null;
                if ($key === null || ! $item->value instanceof Expr\Array_) {
                    $warnings[] = self::warn($class->file, $item);

                    continue;
                }
                $groups[$key] = self::members($item->value, $class->file, $eval, $class, $warnings);
            }
        }
    }

    /**
     * @param  array<Node\Stmt>  $ast
     * @param  array<string, string>  $aliases
     * @param  array<string, list<string>>  $groups
     * @param  list<string>  $warnings
     */
    private static function readBootstrap(array $ast, string $file, ConstantEvaluator $eval, array &$aliases, array &$groups, array &$warnings): void
    {
        $finder = new NodeFinder();
        foreach ($finder->findInstanceOf($ast, Expr\MethodCall::class) as $call) {
            if (! $call->name instanceof Node\Identifier || $call->name->toString() !== 'withMiddleware' || ! isset($call->args[0]) || ! $call->args[0] instanceof Node\Arg) {
                continue;
            }
            $closure = $call->args[0]->value;
            if (! $closure instanceof Expr\Closure && ! $closure instanceof Expr\ArrowFunction) {
                continue;
            }
            $param = $closure->params[0]->var ?? null;
            if (! $param instanceof Expr\Variable || ! is_string($param->name)) {
                continue;
            }
            $body = $closure instanceof Expr\Closure ? $closure->stmts : [$closure->expr];
            foreach ($finder->findInstanceOf($body, Expr\MethodCall::class) as $inner) {
                if (self::rootVariable($inner) === $param->name && $inner->name instanceof Node\Identifier) {
                    self::applyCall($inner, $file, $eval, $aliases, $groups, $warnings);
                }
            }
        }
    }

    private static function rootVariable(Expr $expr): ?string
    {
        while ($expr instanceof Expr\MethodCall) {
            $expr = $expr->var;
        }

        return $expr instanceof Expr\Variable && is_string($expr->name) ? $expr->name : null;
    }

    /**
     * @param  array<string, string>  $aliases
     * @param  array<string, list<string>>  $groups
     * @param  list<string>  $warnings
     */
    private static function applyCall(Expr\MethodCall $call, string $file, ConstantEvaluator $eval, array &$aliases, array &$groups, array &$warnings): void
    {
        $method = $call->name instanceof Node\Identifier ? $call->name->toString() : '';
        $args = array_values(array_filter($call->args, static fn ($a): bool => $a instanceof Node\Arg));

        if ($method === 'alias') {
            if (isset($args[0]) && $args[0]->value instanceof Expr\Array_) {
                self::readAliases($args[0]->value, $file, $eval, null, $aliases, $warnings);
            }

            return;
        }
        if ($method === 'web' || $method === 'api') {
            $append = self::namedOrPositional($args, 'append', 0);
            $prepend = self::namedOrPositional($args, 'prepend', 1);
            self::mutateGroup($groups, $method, $prepend, $append, $file, $eval, $warnings);

            return;
        }
        if (in_array($method, ['group', 'appendToGroup', 'prependToGroup'], true) && isset($args[0], $args[1])) {
            $name = $eval->string($args[0]->value, $file);
            if ($name === null) {
                $warnings[] = $file.':'.$call->getStartLine().': middleware entry could not be resolved';

                return;
            }
            if ($method === 'group') {
                $groups[$name] = self::members($args[1]->value, $file, $eval, null, $warnings);
            } else {
                self::mutateGroup($groups, $name, $method === 'prependToGroup' ? $args[1]->value : null, $method === 'appendToGroup' ? $args[1]->value : null, $file, $eval, $warnings);
            }
        }
    }

    /** @param list<Node\Arg> $args */
    private static function namedOrPositional(array $args, string $name, int $index): ?Expr
    {
        foreach ($args as $arg) {
            if ($arg->name?->toString() === $name) {
                return $arg->value;
            }
        }

        return isset($args[$index]) && $args[$index]->name === null ? $args[$index]->value : null;
    }

    /**
     * @param  array<string, list<string>>  $groups
     * @param  list<string>  $warnings
     */
    private static function mutateGroup(array &$groups, string $name, ?Expr $prepend, ?Expr $append, string $file, ConstantEvaluator $eval, array &$warnings): void
    {
        $before = $prepend !== null ? self::members($prepend, $file, $eval, null, $warnings) : [];
        $after = $append !== null ? self::members($append, $file, $eval, null, $warnings) : [];
        $groups[$name] = [...$before, ...($groups[$name] ?? []), ...$after];
    }

    /**
     * @param  array<string, string>  $aliases
     * @param  list<string>  $warnings
     */
    private static function readAliases(Expr\Array_ $array, string $file, ConstantEvaluator $eval, ?ClassSymbol $class, array &$aliases, array &$warnings): void
    {
        foreach ($array->items as $item) {
            $key = $item->key !== null ? $eval->string($item->key, $file, $class) : null;
            $value = $eval->string($item->value, $file, $class);
            if ($key === null || $value === null) {
                $warnings[] = self::warn($file, $item);

                continue;
            }
            $aliases[$key] ??= $value;
        }
    }

    /**
     * @param  list<string>  $warnings
     * @return list<string>
     */
    private static function members(Expr $expr, string $file, ConstantEvaluator $eval, ?ClassSymbol $class, array &$warnings): array
    {
        $items = $expr instanceof Expr\Array_ ? $expr->items : [new Node\ArrayItem($expr, null, false, $expr->getAttributes())];
        $out = [];
        foreach ($items as $item) {
            $value = $item->unpack ? null : $eval->string($item->value, $file, $class);
            if ($value === null) {
                $warnings[] = self::warn($file, $item);

                continue;
            }
            $out[] = $value;
        }

        return $out;
    }

    private static function warn(string $file, Node $node): string
    {
        return $file.':'.$node->getStartLine().': middleware entry could not be resolved';
    }
}
