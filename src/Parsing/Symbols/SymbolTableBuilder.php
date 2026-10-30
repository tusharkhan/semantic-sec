<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Parsing\Symbols;

use PhpParser\Node;
use PhpParser\Node\ComplexType;
use PhpParser\Node\Identifier;
use PhpParser\Node\IntersectionType;
use PhpParser\Node\Name;
use PhpParser\Node\NullableType;
use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Stmt\ClassLike;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\Node\Stmt\Enum_;
use PhpParser\Node\Stmt\Interface_;
use PhpParser\Node\Stmt\Property;
use PhpParser\Node\Stmt\Trait_;
use PhpParser\Node\Stmt\TraitUse;
use PhpParser\Node\UnionType;
use PhpParser\NodeFinder;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;
use PhpParser\NodeVisitorAbstract;
use PHPStan\PhpDocParser\Ast\PhpDoc\PhpDocNode;
use PHPStan\PhpDocParser\Ast\Type\GenericTypeNode;
use PHPStan\PhpDocParser\Ast\Type\IdentifierTypeNode;
use PHPStan\PhpDocParser\Ast\Type\NullableTypeNode;
use PHPStan\PhpDocParser\Ast\Type\ThisTypeNode;
use PHPStan\PhpDocParser\Ast\Type\TypeNode;
use PHPStan\PhpDocParser\Ast\Type\UnionTypeNode;
use PHPStan\PhpDocParser\Lexer\Lexer;
use PHPStan\PhpDocParser\Parser\ConstExprParser;
use PHPStan\PhpDocParser\Parser\ParserException;
use PHPStan\PhpDocParser\Parser\PhpDocParser;
use PHPStan\PhpDocParser\Parser\TokenIterator;
use PHPStan\PhpDocParser\Parser\TypeParser;
use PHPStan\PhpDocParser\ParserConfig;
use TusharKhan\SemanticSec\Parsing\ParsedFile;
use TusharKhan\SemanticSec\Parsing\ParseResult;

final class SymbolTableBuilder
{
    private const BUILTINS = [
        'int', 'string', 'array', 'bool', 'float', 'mixed', 'callable', 'iterable',
        'object', 'void', 'null', 'false', 'true', 'never',
    ];

    private const LEGACY = [
        'integer' => 'int', 'boolean' => 'bool', 'double' => 'float', 'real' => 'float',
        'long' => 'int', 'number' => 'float', 'callback' => 'callable',
    ];

    private const DOC_ONLY_BUILTINS = ['scalar', 'resource', 'numeric'];

    private const PSEUDO = ['list', 'class-string', 'int-mask', 'key-of', 'value-of'];

    private PhpDocParser $docParser;

    private Lexer $lexer;

    public function __construct()
    {
        $config = new ParserConfig([]);
        $constExpr = new ConstExprParser($config);
        $this->lexer = new Lexer($config);
        $this->docParser = new PhpDocParser($config, new TypeParser($config, $constExpr), $constExpr);
    }

    public function build(ParseResult $result): SymbolTable
    {
        $classes = [];
        $failures = [];
        foreach ($result->files as $parsed) {
            try {
                $found = $this->symbolsForFile($parsed);
            } catch (\Throwable $e) {
                $failures[] = sprintf('%s: %s: %s', $parsed->file->path, $e::class, $e->getMessage());

                continue;
            }
            array_push($classes, ...$found);
        }

        return new SymbolTable($classes, $failures);
    }

    /** @return list<ClassSymbol> */
    private function symbolsForFile(ParsedFile $parsed): array
    {
        $resolver = new NameResolver(null, ['replaceNodes' => false]);
        $collector = new class ($this, $resolver, $parsed->file->path) extends NodeVisitorAbstract {
            /** @var list<ClassSymbol> */
            public array $found = [];

            public function __construct(
                private readonly SymbolTableBuilder $builder,
                private readonly NameResolver $resolver,
                private readonly string $file,
            ) {
            }

            public function enterNode(Node $node): null
            {
                if ($node instanceof ClassLike && $node->name !== null && $node->namespacedName !== null) {
                    $this->found[] = $this->builder->symbolFor($node, $this->file, $this->resolver);
                }

                return null;
            }
        };
        (new NodeTraverser($resolver, $collector))->traverse($parsed->ast);

        return $collector->found;
    }

    /** @internal Called by the traversal visitor. */
    public function symbolFor(ClassLike $node, string $file, NameResolver $resolver): ClassSymbol
    {
        $fqn = $node->namespacedName?->toString() ?? '';
        $context = $resolver->getNameContext();
        $templates = $this->templateNames($node);

        $parent = null;
        $interfaces = [];
        $kind = 'class';
        if ($node instanceof Class_) {
            $parent = $node->extends?->toString();
            $interfaces = array_values(array_map(static fn (Name $n): string => $n->toString(), $node->implements));
        } elseif ($node instanceof Interface_) {
            $kind = 'interface';
            $interfaces = array_values(array_map(static fn (Name $n): string => $n->toString(), $node->extends));
        } elseif ($node instanceof Enum_) {
            $kind = 'enum';
            $interfaces = array_values(array_map(static fn (Name $n): string => $n->toString(), $node->implements));
        } elseif ($node instanceof Trait_) {
            $kind = 'trait';
        }

        $traits = [];
        $properties = [];
        $methods = [];
        $resolve = static function (string $text) use ($context): string {
            if (stripos($text, 'namespace\\') === 0) {
                $namespace = $context->getNamespace()?->toString();
                $rest = substr($text, 10);

                return $namespace === null ? $rest : $namespace.'\\'.$rest;
            }

            return $context->getResolvedClassName(new Name($text))->toString();
        };

        foreach ($node->stmts as $stmt) {
            if ($stmt instanceof TraitUse) {
                foreach ($stmt->traits as $trait) {
                    $traits[] = $trait->toString();
                }
            } elseif ($stmt instanceof Property) {
                $native = $this->nativeType($stmt->type, $fqn, $parent);
                $doc = $native === null ? $this->docVarType($stmt, $fqn, $parent, $resolve, $templates) : null;
                foreach ($stmt->props as $prop) {
                    $properties[$prop->name->toString()] = new PropertySymbol($prop->name->toString(), $native ?? $doc, $prop->getStartLine(), $prop->default);
                }
            } elseif ($stmt instanceof ClassMethod) {
                $method = $this->methodSymbol($stmt, $fqn, $parent, $file, $resolve, $templates);
                $methods[strtolower($method->name)] = $method;
                if (strtolower($method->name) === '__construct') {
                    foreach ($stmt->params as $param) {
                        if ($param->isPromoted() && $param->var instanceof Node\Expr\Variable && is_string($param->var->name)) {
                            $properties[$param->var->name] = new PropertySymbol($param->var->name, $method->params[$param->var->name] ?? null, $param->getStartLine(), null);
                        }
                    }
                }
            }
        }

        $ctor = $methods['__construct'] ?? null;
        foreach ($ctor === null ? [] : $this->constructorAssignedTypes($ctor) as $name => $type) {
            $prop = $properties[$name] ?? null;
            if ($prop !== null && $prop->type === null) {
                $properties[$name] = new PropertySymbol($prop->name, $type, $prop->line, $prop->default);
            }
        }
        [$docProperties, $docMethods] = $this->classDocTags($node, $fqn, $parent, $resolve, $templates);

        return new ClassSymbol($fqn, $kind, $file, $node->getStartLine(), $node->getEndLine(), $parent, $interfaces, $traits, $properties, $methods, $node, $docProperties, $docMethods);
    }

    /**
     * @param  callable(string): string  $resolve
     * @param  list<string>  $templates
     */
    private function methodSymbol(ClassMethod $node, string $class, ?string $parent, string $file, callable $resolve, array $templates): MethodSymbol
    {
        $doc = $this->parseDoc($node);
        $templates = array_merge($templates, $this->templateNames($node));

        $docParams = [];
        foreach ($doc?->getParamTagValues() ?? [] as $tag) {
            $docParams[ltrim($tag->parameterName, '$')] = $tag->type;
        }

        $params = [];
        foreach ($node->params as $param) {
            if (! $param->var instanceof Node\Expr\Variable || ! is_string($param->var->name)) {
                continue;
            }
            $name = $param->var->name;
            $native = $this->nativeType($param->type, $class, $parent);
            $params[$name] = $native ?? (isset($docParams[$name]) ? $this->docType($docParams[$name], $class, $parent, $resolve, $templates) : null);
        }

        $returnType = $this->nativeType($node->returnType, $class, $parent);
        if ($returnType === null) {
            $tags = $doc?->getReturnTagValues() ?? [];
            $returnType = $tags !== [] ? $this->docType($tags[0]->type, $class, $parent, $resolve, $templates) : null;
        }
        $genericTags = $doc === null ? [] : ($doc->getReturnTagValues('@phpstan-return') ?: $doc->getReturnTagValues('@psalm-return') ?: $doc->getReturnTagValues());
        $returnGeneric = $genericTags !== [] ? $this->genericArgument($genericTags[0]->type, $class, $parent, $resolve, $templates) : null;

        return new MethodSymbol($class, $node->name->toString(), $file, $node->getStartLine(), $node->getEndLine(), $params, $returnType, $node->isStatic(), $node, $returnGeneric);
    }

    /**
     * The first class-like argument of a generic type, e.g. `HasMany<Invoice>`.
     *
     * @param  callable(string): string  $resolve
     * @param  list<string>  $templates
     */
    private function genericArgument(TypeNode $type, string $class, ?string $parent, callable $resolve, array $templates): ?string
    {
        if ($type instanceof NullableTypeNode) {
            return $this->genericArgument($type->type, $class, $parent, $resolve, $templates);
        }
        if ($type instanceof UnionTypeNode) {
            foreach ($type->types as $inner) {
                $found = $this->genericArgument($inner, $class, $parent, $resolve, $templates);
                if ($found !== null) {
                    return $found;
                }
            }

            return null;
        }
        if (! $type instanceof GenericTypeNode) {
            return null;
        }
        foreach ($type->genericTypes as $argument) {
            $name = $this->docType($argument, $class, $parent, $resolve, $templates);
            if ($name !== null && ! $this->isBuiltin($name)) {
                return $name;
            }
        }

        return null;
    }

    private function isBuiltin(string $name): bool
    {
        return in_array($name, self::BUILTINS, true) || in_array($name, self::DOC_ONLY_BUILTINS, true);
    }

    /**
     * Class-level @property* and @method tags; phpstan/psalm variants win over plain ones.
     *
     * @param  callable(string): string  $resolve
     * @param  list<string>  $templates
     * @return array{0: array<string, string>, 1: array<string, string>}
     */
    private function classDocTags(ClassLike $node, string $class, ?string $parent, callable $resolve, array $templates): array
    {
        $doc = $this->parseDoc($node);
        if ($doc === null) {
            return [[], []];
        }
        $properties = [];
        foreach (['@property', '@property-read', '@psalm-property', '@psalm-property-read', '@phpstan-property', '@phpstan-property-read'] as $tag) {
            $values = str_ends_with($tag, '-read') ? $doc->getPropertyReadTagValues($tag) : $doc->getPropertyTagValues($tag);
            foreach ($values as $value) {
                $type = $this->docType($value->type, $class, $parent, $resolve, $templates);
                if ($type !== null && $type !== 'null') {
                    $properties[ltrim($value->propertyName, '$')] = $type;
                }
            }
        }
        $methods = [];
        foreach (['@method', '@psalm-method', '@phpstan-method'] as $tag) {
            foreach ($doc->getMethodTagValues($tag) as $value) {
                $type = $value->returnType === null ? null : $this->docType($value->returnType, $class, $parent, $resolve, $templates);
                if ($type !== null && $type !== 'null') {
                    $methods[strtolower($value->methodName)] = $type;
                }
            }
        }

        return [$properties, $methods];
    }

    /**
     * Property types proven by top-level `$this->p = $param;` (or `$param ?? …`) constructor statements.
     *
     * @return array<string, string>
     */
    private function constructorAssignedTypes(MethodSymbol $ctor): array
    {
        $stmts = $ctor->node->stmts ?? [];
        $variadic = [];
        foreach ($ctor->node->params as $param) {
            if ($param->variadic && $param->var instanceof Node\Expr\Variable && is_string($param->var->name)) {
                $variadic[$param->var->name] = true;
            }
        }
        $topLevel = [];
        foreach ($stmts as $stmt) {
            if ($stmt instanceof Node\Stmt\Expression && $stmt->expr instanceof Node\Expr\Assign) {
                $topLevel[spl_object_id($stmt->expr)] = true;
            }
        }

        $finder = new NodeFinder();
        $written = [];
        $types = [];
        $writes = $finder->find($stmts, static fn (Node $n): bool => $n instanceof Node\Expr\Assign || $n instanceof Node\Expr\AssignRef
            || $n instanceof Node\Expr\AssignOp || $n instanceof Node\Stmt\Foreach_ || $n instanceof Node\Stmt\Catch_
            || $n instanceof Node\Expr\PreInc || $n instanceof Node\Expr\PreDec || $n instanceof Node\Expr\PostInc || $n instanceof Node\Expr\PostDec);
        foreach ($writes as $write) {
            $targets = match (true) {
                $write instanceof Node\Stmt\Foreach_ => [$write->keyVar, $write->valueVar],
                $write instanceof Node\Stmt\Catch_, $write instanceof Node\Expr\Assign, $write instanceof Node\Expr\AssignRef, $write instanceof Node\Expr\AssignOp,
                $write instanceof Node\Expr\PreInc, $write instanceof Node\Expr\PreDec, $write instanceof Node\Expr\PostInc, $write instanceof Node\Expr\PostDec => [$write->var],
                default => [],
            };
            foreach ($targets as $target) {
                if ($target === null) {
                    continue;
                }
                foreach ($finder->findInstanceOf([$target], Node\Expr\Variable::class) as $var) {
                    if (is_string($var->name)) {
                        $written[$var->name] = true;
                    }
                }
                if ($target instanceof Node\Expr\PropertyFetch && $target->var instanceof Node\Expr\Variable && $target->var->name === 'this' && $target->name instanceof Identifier) {
                    $value = $write instanceof Node\Expr\Assign && isset($topLevel[spl_object_id($write)]) ? $write->expr : null;
                    $value = $value instanceof Node\Expr\BinaryOp\Coalesce ? $value->left : $value;
                    $types[$target->name->toString()][] = $value instanceof Node\Expr\Variable && is_string($value->name) && ! isset($variadic[$value->name]) ? $value->name : null;
                }
            }
        }

        $out = [];
        foreach ($types as $property => $sources) {
            $resolved = [];
            foreach ($sources as $source) {
                $resolved[] = $source === null || isset($written[$source]) ? null : ($ctor->params[$source] ?? null);
            }
            $unique = array_unique($resolved, SORT_REGULAR);
            if (count($unique) === 1 && $unique[0] !== null) {
                $out[$property] = $unique[0];
            }
        }

        return $out;
    }


    /**
     * @param  callable(string): string  $resolve
     * @param  list<string>  $templates
     */
    private function docVarType(Property $node, string $class, ?string $parent, callable $resolve, array $templates): ?string
    {
        $tags = $this->parseDoc($node)?->getVarTagValues() ?? [];

        return $tags !== [] ? $this->docType($tags[0]->type, $class, $parent, $resolve, $templates) : null;
    }

    private function nativeType(Identifier|Name|ComplexType|null $type, string $class, ?string $parent): ?string
    {
        if ($type === null) {
            return null;
        }
        if ($type instanceof NullableType) {
            return $this->nativeType($type->type, $class, $parent);
        }
        if ($type instanceof UnionType || $type instanceof IntersectionType) {
            $first = null;
            foreach ($type->types as $inner) {
                $name = $this->nativeType($inner, $class, $parent);
                if ($name === null) {
                    continue;
                }
                if (! in_array($name, self::BUILTINS, true)) {
                    return $name;
                }
                $first ??= $name;
            }

            return $first;
        }

        $text = $type instanceof Name ? ltrim($type->toString(), '\\') : ($type instanceof Identifier ? $type->toString() : '');
        $lower = strtolower($text);
        if ($lower === 'self' || $lower === 'static') {
            return $class;
        }
        if ($lower === 'parent') {
            return $parent;
        }

        return in_array($lower, self::BUILTINS, true) ? $lower : $text;
    }

    /**
     * @param  callable(string): string  $resolve
     * @param  list<string>  $templates
     */
    private function docType(TypeNode $type, string $class, ?string $parent, callable $resolve, array $templates): ?string
    {
        if ($type instanceof NullableTypeNode) {
            return $this->docType($type->type, $class, $parent, $resolve, $templates);
        }
        if ($type instanceof GenericTypeNode) {
            return $this->docType($type->type, $class, $parent, $resolve, $templates);
        }
        if ($type instanceof ThisTypeNode) {
            return $class;
        }
        if ($type instanceof UnionTypeNode) {
            $first = null;
            foreach ($type->types as $inner) {
                $name = $this->docType($inner, $class, $parent, $resolve, $templates);
                if ($name === null || $name === 'null') {
                    continue;
                }
                if (! in_array($name, self::BUILTINS, true)) {
                    return $name;
                }
                $first ??= $name;
            }

            return $first;
        }
        if (! $type instanceof IdentifierTypeNode) {
            return null;
        }

        $text = $type->name;
        $lower = strtolower($text);
        if ($lower === 'self' || $lower === 'static' || $lower === '$this') {
            return $class;
        }
        if ($lower === 'parent') {
            return $parent;
        }
        if (isset(self::LEGACY[$lower])) {
            return self::LEGACY[$lower];
        }
        if (in_array($lower, self::BUILTINS, true) || in_array($lower, self::DOC_ONLY_BUILTINS, true)) {
            return $lower;
        }
        if (str_contains($text, '-') || in_array($lower, self::PSEUDO, true) || in_array($text, $templates, true)) {
            return null;
        }
        if (str_starts_with($text, '\\')) {
            return ltrim($text, '\\');
        }

        return $resolve($text);
    }

    /** @return list<string> */
    private function templateNames(Node $node): array
    {
        $names = [];
        foreach ($this->parseDoc($node)?->getTemplateTagValues() ?? [] as $tag) {
            $names[] = $tag->name;
        }

        return $names;
    }

    private function parseDoc(Node $node): ?PhpDocNode
    {
        $comment = $node->getDocComment();
        if ($comment === null) {
            return null;
        }

        try {
            return $this->docParser->parse(new TokenIterator($this->lexer->tokenize($comment->getText())));
        } catch (ParserException) {
            return null;
        }
    }
}
