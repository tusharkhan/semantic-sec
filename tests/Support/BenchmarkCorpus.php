<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support;

use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Stmt\ClassLike;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\Node\Stmt\Trait_;
use PhpParser\NodeFinder;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;
use PhpParser\ParserFactory;
use Symfony\Component\Yaml\Yaml;

final class BenchmarkCorpus
{
    public const APPS = ['laravel10-app', 'laravel11-app', 'laravel12-app'];

    // Missing set means existing: the original public route predates the blind corpus.
    /** @param array<mixed> $item */
    public static function set(array $item): string
    {
        return is_string($item['set'] ?? null) ? $item['set'] : 'existing';
    }

    /** @return list<array<string, mixed>> */
    public static function casesInSet(string $set): array
    {
        return array_values(array_filter(self::cases(), static fn (array $case): bool => self::set($case) === $set));
    }

    public static function root(): string
    {
        return dirname(__DIR__, 2) . '/benchmark';
    }

    /** @return list<array<string, mixed>> */
    public static function cases(): array
    {
        return self::list('cases');
    }

    /** @return list<array<string, mixed>> */
    public static function publicRoutes(): array
    {
        return self::list('public_routes');
    }

    // Maps App\X\Y::m to <root>/<app>/app/X/Y.php.
    public static function fileForSymbol(string $app, string $symbol): string
    {
        $class = explode('::', $symbol)[0];
        $relative = preg_replace('/^App\\\\/', '', $class) ?? $class;

        return self::root() . '/' . $app . '/app/' . str_replace('\\', '/', $relative) . '.php';
    }

    // Finds a method inside the class or trait named by the FQCN, never in another class.
    public static function findMethodInSource(string $code, string $fqcn, string $method): ?ClassMethod
    {
        $ast = (new ParserFactory())->createForNewestSupportedVersion()->parse($code) ?? [];
        $ast = (new NodeTraverser(new NameResolver()))->traverse($ast);
        $fqcn = ltrim($fqcn, '\\');

        $class = (new NodeFinder())->findFirst(
            $ast,
            static fn ($node): bool => ($node instanceof Class_ || $node instanceof Trait_)
                && $node->namespacedName !== null
                && $node->namespacedName->toString() === $fqcn,
        );

        return $class instanceof ClassLike ? $class->getMethod($method) : null;
    }

    /** @return list<array<string, mixed>> */
    private static function list(string $key): array
    {
        $data = Yaml::parseFile(self::root() . '/expected.yaml');
        $items = is_array($data) ? ($data[$key] ?? null) : null;

        if (! is_array($items)) {
            return [];
        }

        /** @var list<array<string, mixed>> */
        return array_values($items);
    }
}
