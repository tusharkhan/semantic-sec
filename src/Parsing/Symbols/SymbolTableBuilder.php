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
use TusharKhan\SemanticSec\Parsing\ParseResult;

final class SymbolTableBuilder
{
    private const BUILTINS = [
        'int', 'string', 'array', 'bool', 'float', 'mixed', 'callable', 'iterable',
        'object', 'void', 'null', 'false', 'true', 'never',
    ];

    private const PSEUDO = ['list', 'scalar', 'numeric', 'resource', 'class-string', 'int-mask', 'key-of', 'value-of'];

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
        foreach ($result->files as $parsed) {
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
            array_push($classes, ...$collector->found);
        }

        return new SymbolTable($classes);
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
        $resolve = fn (string $text): string => $context->getResolvedClassName(new Name($text))->toString();

        foreach ($node->stmts as $stmt) {
            if ($stmt instanceof TraitUse) {
                foreach ($stmt->traits as $trait) {
                    $traits[] = $trait->toString();
                }
            } elseif ($stmt instanceof Property) {
                $native = $this->nativeType($stmt->type, $fqn, $parent);
                $doc = $native === null ? $this->docVarType($stmt, $fqn, $parent, $resolve, $templates) : null;
                foreach ($stmt->props as $prop) {
                    $properties[$prop->name->toString()] = new PropertySymbol($prop->name->toString(), $native ?? $doc, $prop->getStartLine());
                }
            } elseif ($stmt instanceof ClassMethod) {
                $method = $this->methodSymbol($stmt, $fqn, $parent, $file, $resolve, $templates);
                $methods[strtolower($method->name)] = $method;
                if (strtolower($method->name) === '__construct') {
                    foreach ($stmt->params as $param) {
                        if ($param->isPromoted() && $param->var instanceof Node\Expr\Variable && is_string($param->var->name)) {
                            $properties[$param->var->name] = new PropertySymbol($param->var->name, $method->params[$param->var->name] ?? null, $param->getStartLine());
                        }
                    }
                }
            }
        }

        return new ClassSymbol($fqn, $kind, $file, $node->getStartLine(), $node->getEndLine(), $parent, $interfaces, $traits, $properties, $methods);
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

        return new MethodSymbol($class, $node->name->toString(), $file, $node->getStartLine(), $node->getEndLine(), $params, $returnType, $node->isStatic(), $node);
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
        if (in_array($lower, self::BUILTINS, true)) {
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
