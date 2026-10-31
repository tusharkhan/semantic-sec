<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Payload;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use PhpParser\NodeFinder;
use TusharKhan\SemanticSec\Candidates\Candidate;
use TusharKhan\SemanticSec\Config\Config;
use TusharKhan\SemanticSec\Framework\Laravel\Ancestry;
use TusharKhan\SemanticSec\Framework\Laravel\AuthCheck;
use TusharKhan\SemanticSec\Framework\Laravel\AuthCheckExtractor;
use TusharKhan\SemanticSec\Framework\Laravel\AuthCheckKind;
use TusharKhan\SemanticSec\Framework\Laravel\AuthExpressions;
use TusharKhan\SemanticSec\Framework\Laravel\PolicyRegistry;
use TusharKhan\SemanticSec\Framework\Laravel\RouteEntry;
use TusharKhan\SemanticSec\Parsing\CallGraph\PathNode;
use TusharKhan\SemanticSec\Parsing\ParseResult;
use TusharKhan\SemanticSec\Parsing\Symbols\MethodSymbol;
use TusharKhan\SemanticSec\Parsing\Symbols\SymbolTable;

/** Builds the SPEC §9 payloads for one candidate: context, fenced line-tagged code, escaping, redaction, splitting. */
final class PayloadBuilder
{
    public const OPEN = '<untrusted_code>';

    public const CLOSE = '</untrusted_code>';

    private const TRUNCATED = '// … truncated';

    private const MODEL_ROOTS = ['Illuminate\\Database\\Eloquent\\Model', 'Illuminate\\Foundation\\Auth\\User', 'Illuminate\\Database\\Eloquent\\Relations\\Pivot', 'Illuminate\\Database\\Eloquent\\Relations\\MorphPivot'];

    private const MAX_KEY = 80;

    private readonly Pruner $pruner;

    private readonly Redactor $redactor;

    private readonly NodeFinder $finder;

    private readonly int $limit;

    /** @var list<string> */
    private readonly array $authHelpers;

    /** @var array<string, string> raw text => escaped and redacted */
    private array $finished = [];

    /** @var array<string, true> escaped lines this builder wrote (headers, markers), restored after redaction */
    private array $generated = [];

    public function __construct(
        ParseResult $parsed,
        private readonly SymbolTable $symbols,
        private readonly AuthCheckExtractor $extractor,
        private readonly PolicyRegistry $policies,
        private readonly string $frameworkNotes,
        Config $config,
    ) {
        $this->pruner = new Pruner($parsed);
        $this->redactor = new Redactor();
        $this->finder = new NodeFinder();
        $this->limit = $config->maxPayloadTokens;
        $this->authHelpers = $config->authHelpers;
    }

    /**
     * @param  int  $number  the candidate's position in the run, the `NNN` of every payload id
     * @return array{0: list<Payload>, 1: list<string>}
     */
    public function build(Candidate $candidate, int $number): array
    {
        $this->finished = [];
        $this->generated = [self::TRUNCATED => true];
        $warnings = [];
        try {
            $payloads = $this->payloads($candidate, $number, $warnings);
        } catch (\Throwable $e) {
            // Never drop a candidate: emit a payload that says the code is missing.
            $route = $candidate->route;
            $warnings[] = sprintf('%s:%d: payload build failed: %s', $route->file, $route->line, $e->getMessage());
            $context = $this->finish("Route:\n  ".self::key($route)."\n  declared at: ".$route->file.':'.$route->line."\n\nBuild error:\n  ".$e->getMessage());
            $code = self::OPEN."\n// payload could not be built; this route needs a manual review\n".self::CLOSE;
            $payloads = [new Payload(self::id($number, $route, 1), $candidate, $context, $code, 1, 1, true)];
        }
        foreach ($payloads as $payload) {
            $tokens = $payload->tokens();
            if ($tokens > $this->limit) {
                $warnings[] = sprintf('%s:%d: payload %s is %d tokens, over max_payload_tokens %d', $candidate->route->file, $candidate->route->line, $payload->id, $tokens, $this->limit);
            }
        }
        $this->finished = [];
        $this->generated = [];

        return [$payloads, $warnings];
    }

    /**
     * @param  list<string>  $warnings
     * @return list<Payload>
     */
    private function payloads(Candidate $candidate, int $number, array &$warnings): array
    {
        $route = $candidate->route;
        $path = $candidate->path;
        $blocks = [];
        $nodeChecks = [];
        foreach ($path->nodes as $node) {
            $blocks[] = ['node' => $node, 'lines' => $this->lines($node, $warnings)];
            $nodeChecks[$node->id] = $node === $path->entry() ? [] : $this->nodeChecks($node, $warnings);
        }
        $formRequests = $this->formRequests($path->entry(), $route);
        [$head, $notes] = $this->context($candidate, $formRequests, $nodeChecks);
        $unresolved = array_values(array_filter($path->unresolved, static fn (string $u): bool => ! str_contains($u, ': [facade] ')));
        $context = self::assemble($head, $unresolved, $notes);

        if ($this->fits($context, $blocks)) {
            return [new Payload(self::id($number, $route, 1), $candidate, $this->finish($context), $this->code($blocks), 1, 1, false)];
        }

        // Split: each part lists the unresolved calls of its own code; calls no node owns go to part 1.
        $owners = self::owners($unresolved, $path->nodes);
        $summary = $this->upstreamBase($route, $formRequests);
        $parts = [];
        $earlier = [];
        $ctxFor = function (array $partBlocks, bool $first) use (&$earlier, $head, $notes, $unresolved, $owners, $summary, $nodeChecks): string {
            $ids = [];
            foreach ($partBlocks as $b) {
                $ids[$b['node']->id] = true;
            }
            $own = [];
            foreach ($unresolved as $i => $u) {
                if ($owners[$i] === null ? $first : isset($ids[$owners[$i]])) {
                    $own[] = $u;
                }
            }

            return $this->withSummary(self::assemble($head, $own, $notes), $summary, $earlier, $nodeChecks);
        };
        foreach ($this->groups($blocks) as $group) {
            $current = [];
            foreach ($group as $block) {
                $trial = [...$current, $block];
                if ($current !== [] && ! $this->fits($ctxFor($trial, $parts === []), $trial)) {
                    $parts[] = [$ctxFor($current, $parts === []), $current, false];
                    array_push($earlier, ...array_map(static fn (array $b): PathNode => $b['node'], $current));
                    $current = [];
                }
                if ($current === [] && ! $this->fits($ctxFor([$block], $parts === []), [$block])) {
                    $ctx = $ctxFor([$block], $parts === []);
                    $parts[] = [$ctx, [$this->truncate($ctx, $block)], true];
                    $earlier[] = $block['node'];

                    continue;
                }
                $current[] = $block;
            }
            if ($current !== []) {
                $parts[] = [$ctxFor($current, $parts === []), $current, false];
                array_push($earlier, ...array_map(static fn (array $b): PathNode => $b['node'], $current));
            }
        }

        $out = [];
        foreach ($parts as $i => [$ctx, $partBlocks, $truncated]) {
            $out[] = new Payload(self::id($number, $route, $i + 1), $candidate, $this->finish($ctx), $this->code($partBlocks, $truncated), $i + 1, count($parts), $truncated);
        }

        return $out;
    }

    // ---- code ----------------------------------------------------------------------------------------------------

    /**
     * @param  list<string>  $warnings
     * @return list<array{line: int, text: string}>
     */
    private function lines(PathNode $node, array &$warnings): array
    {
        if ($node->method === null && $node->closure === null) {
            return [];
        }
        try {
            $lines = $this->pruner->prune($node, $this->authHelpers)->lines;
            foreach ($lines as $l) {
                if ($l['text'] === '// '.$node->id.': trivial accessor omitted') {
                    $this->generate('L'.$l['line'].'| '.$l['text']);
                }
            }

            return $lines;
        } catch (\Throwable $e) {
            $warnings[] = sprintf('%s:%d: could not prune %s: %s', $node->file, $node->startLine, $node->id, $e->getMessage());

            return [];
        }
    }

    /** @param list<array{line: int, text: string}> $lines */
    private function block(string $file, string $id, int $start, int $end, array $lines, bool $cut = false): string
    {
        if ($lines === []) {
            $header = $this->generate(sprintf('// FILE: %s :: %s (L%d-L%d)', $file, $id, $start, $end));

            return $cut ? $header : $header."\n".$this->generate('// '.$id.': source not available');
        }
        $numbers = array_map(static fn (array $l): int => $l['line'], $lines);
        $out = [$this->generate(sprintf('// FILE: %s :: %s (L%d-L%d)', $file, $id, min($numbers), max($numbers)))];
        foreach ($lines as $l) {
            $out[] = 'L'.$l['line'].'| '.$l['text'];
        }

        return implode("\n", $out);
    }

    /** @param list<array{node: PathNode, lines: list<array{line: int, text: string}>}> $blocks */
    private function code(array $blocks, bool $truncated = false): string
    {
        $parts = array_map(fn (array $b): string => $this->block($b['node']->file, $b['node']->id, $b['node']->startLine, $b['node']->endLine, $b['lines'], $truncated), $blocks);
        $inner = self::escape(implode("\n\n", $parts)).($truncated ? "\n".self::TRUNCATED : '');

        return $this->redact(self::OPEN."\n".$inner."\n".self::CLOSE);
    }

    /** @param list<array{node: PathNode, lines: list<array{line: int, text: string}>}> $blocks */
    private function fits(string $context, array $blocks, bool $truncated = false): bool
    {
        return TokenEstimator::estimate($this->finish($context)."\n\n".$this->code($blocks, $truncated)) <= $this->limit;
    }

    /**
     * The longest prefix of the node's lines that fits; at least the header.
     *
     * @param  array{node: PathNode, lines: list<array{line: int, text: string}>}  $block
     * @return array{node: PathNode, lines: list<array{line: int, text: string}>}
     */
    private function truncate(string $context, array $block): array
    {
        $low = 0;
        $high = count($block['lines']);
        while ($low < $high) {
            $mid = intdiv($low + $high + 1, 2);
            if ($this->fits($context, [['node' => $block['node'], 'lines' => array_slice($block['lines'], 0, $mid)]], true)) {
                $low = $mid;
            } else {
                $high = $mid - 1;
            }
        }
        return ['node' => $block['node'], 'lines' => array_slice($block['lines'], 0, $low)];
    }

    /**
     * Part 1 is the entry and its direct callees; then one group per further class, in path order.
     *
     * @param  list<array{node: PathNode, lines: list<array{line: int, text: string}>}>  $blocks
     * @return list<list<array{node: PathNode, lines: list<array{line: int, text: string}>}>>
     */
    private function groups(array $blocks): array
    {
        $first = [];
        $rest = [];
        foreach ($blocks as $block) {
            $node = $block['node'];
            if ($node->depth <= 1) {
                $first[] = $block;

                continue;
            }
            $rest[$node->method->class ?? $node->closureClass ?? 'closure@'.$node->file][] = $block;
        }

        return array_values(array_filter([$first, ...array_values($rest)], static fn (array $g): bool => $g !== []));
    }

    // ---- context -------------------------------------------------------------------------------------------------

    /**
     * @param  list<array{class: string, rules: string, authorize: string}>  $formRequests
     * @param  array<string, list<AuthCheck>>  $nodeChecks
     * @return array{list<string>, string} the sections before the unresolved calls, and the framework notes section
     */
    private function context(Candidate $candidate, array $formRequests, array $nodeChecks): array
    {
        $route = $candidate->route;
        $sections = [$this->routeSection($route)];

        $lines = [];
        foreach ($candidate->categories as $category) {
            $lines[] = '  - '.$category->value.': '.($candidate->reasons[$category->value] ?? '');
        }
        $sections[] = self::section('Candidate categories', $lines);

        $lines = [];
        foreach ($formRequests as $fr) {
            array_push($lines, '  '.$fr['class'], '    rules keys: '.$fr['rules'], '    authorize: '.$fr['authorize']);
        }
        $sections[] = self::section('FormRequest', $lines);

        $models = $this->models($candidate);
        $sections[] = self::section('Models', array_map(fn (string $m): string => '  '.$m.': '.$this->modelAttributes($m), $models));

        $checks = $route->checks;
        foreach ($nodeChecks as $found) {
            array_push($checks, ...$found);
        }
        $policies = $this->policyBlocks($models, $checks);
        $sections[] = $policies === [] ? '' : "Policies:\n".implode("\n\n", $policies);

        $notes = trim($this->frameworkNotes);

        return [array_values(array_filter($sections, static fn (string $s): bool => $s !== '')), $notes === '' ? '' : "Framework notes:\n".$notes];
    }

    /**
     * @param  list<string>  $head  sections before the unresolved calls
     * @param  list<string>  $unresolved
     */
    private static function assemble(array $head, array $unresolved, string $notes): string
    {
        $sections = [...$head, self::section('Unresolved calls', array_map(static fn (string $u): string => '  - '.$u, $unresolved)), $notes];

        return implode("\n\n", array_values(array_filter($sections, static fn (string $s): bool => $s !== '')));
    }

    /**
     * The id of the innermost node whose code holds each unresolved call, or null.
     *
     * @param  list<string>  $unresolved  "file:line: [kind] text"
     * @param  list<PathNode>  $nodes
     * @return list<?string>
     */
    private static function owners(array $unresolved, array $nodes): array
    {
        $out = [];
        foreach ($unresolved as $u) {
            $owner = null;
            $span = PHP_INT_MAX;
            if (preg_match('~^(.*?):(\d+): \[~', $u, $m) === 1) {
                foreach ($nodes as $node) {
                    $line = (int) $m[2];
                    if ($node->file === $m[1] && $line >= $node->startLine && $line <= $node->endLine && $node->endLine - $node->startLine < $span) {
                        $owner = $node->id;
                        $span = $node->endLine - $node->startLine;
                    }
                }
            }
            $out[] = $owner;
        }

        return $out;
    }

    /** @param list<string> $lines */
    private static function section(string $title, array $lines): string
    {
        return $lines === [] ? '' : $title.":\n".implode("\n", $lines);
    }

    private function routeSection(RouteEntry $route): string
    {
        $action = $route->action->symbol() ?? ($route->action->isClosure() ? 'closure' : 'unresolved');
        $lines = ['  '.self::key($route)];
        if ($route->name !== null) {
            $lines[] = '  name: '.$route->name;
        }
        $lines[] = '  action: '.$action;
        $lines[] = '  declared at: '.$route->file.':'.$route->line;
        $lines[] = '  middleware: '.($route->middleware === [] ? 'none' : implode(', ', $route->middleware));
        if ($route->withoutMiddleware !== []) {
            $lines[] = '  without middleware: '.implode(', ', $route->withoutMiddleware);
        }
        if ($route->parameters !== []) {
            $params = [];
            foreach ($route->parameters as $p) {
                $params[] = '{'.$p->name.($p->field === null ? '' : ':'.$p->field).($p->optional ? '?' : '').'}'
                    .($p->boundModel === null ? '' : ' bound to '.$p->boundModel).($p->domain ? ' (domain)' : '');
            }
            $lines[] = '  parameters: '.implode('; ', $params);
        }
        if ($route->scopeBindings !== null) {
            $lines[] = '  scope bindings: '.($route->scopeBindings ? 'on' : 'off');
        }
        if ($route->checks === []) {
            $lines[] = '  checks: none found';
        } else {
            $lines[] = '  checks:';
            foreach ($route->checks as $check) {
                $lines[] = '  - '.self::check($check);
            }
        }

        return "Route:\n".implode("\n", $lines);
    }

    private static function check(AuthCheck $c): string
    {
        $extra = [];
        if ($c->covers !== null) {
            $extra[] = 'covers {'.$c->covers.'}';
        }
        if ($c->routeWide) {
            $extra[] = 'route-wide';
        }
        if ($c->model !== null) {
            $extra[] = 'model '.$c->model;
        }

        return sprintf('%s/%s: %s (%s:%d)%s', $c->kind->value, $c->strength->value, $c->source, $c->file, $c->line, $extra === [] ? '' : ' ['.implode(', ', $extra).']');
    }

    /**
     * @param  list<array{class: string, rules: string, authorize: string}>  $formRequests
     * @return list<string>
     */
    private function upstreamBase(RouteEntry $route, array $formRequests): array
    {
        $lines = $route->checks === [] ? ['  route check: none'] : array_map(static fn (AuthCheck $c): string => '  route check: '.self::check($c), $route->checks);
        foreach ($formRequests as $fr) {
            $lines[] = sprintf('  FormRequest %s: rules keys: %s; authorize: %s', $fr['class'], $fr['rules'], $fr['authorize']);
        }

        return $lines;
    }

    /**
     * @param  list<string>  $summary
     * @param  list<PathNode>  $earlier
     * @param  array<string, list<AuthCheck>>  $nodeChecks
     */
    private function withSummary(string $context, array $summary, array $earlier, array $nodeChecks): string
    {
        $lines = $summary;
        foreach ($earlier as $node) {
            foreach ($nodeChecks[$node->id] ?? [] as $c) {
                $lines[] = sprintf('  earlier check: %s:%d %s/%s: %s (in %s)', $c->file, $c->line, $c->kind->value, $c->strength->value, $c->source, $node->id);
            }
        }

        return $context."\n\nUpstream summary:\n".implode("\n", $lines);
    }

    /**
     * @param  list<string>  $warnings
     * @return list<AuthCheck>
     */
    private function nodeChecks(PathNode $node, array &$warnings): array
    {
        $fn = $node->method ?? $node->closure;
        if (! $fn instanceof MethodSymbol && ! $fn instanceof Expr\Closure && ! $fn instanceof Expr\ArrowFunction) {
            return [];
        }
        try {
            return $this->extractor->bodyChecks($fn, $node->file, [])[0];
        } catch (\Throwable $e) {
            $warnings[] = sprintf('%s:%d: could not read checks in %s: %s', $node->file, $node->startLine, $node->id, $e->getMessage());

            return [];
        }
    }

    /** @return list<array{class: string, rules: string, authorize: string}> FormRequests type-hinted on the entry */
    private function formRequests(PathNode $entry, RouteEntry $route): array
    {
        $fn = $entry->method->node ?? $entry->closure;
        if ($fn === null) {
            return [];
        }
        $out = [];
        foreach ($fn->getParams() as $param) {
            $type = $param->type instanceof Node\Name ? ltrim($param->type->toString(), '\\') : null;
            if ($type === null || isset($out[$type]) || ! AuthExpressions::isFormRequest($this->symbols, $type)) {
                continue;
            }
            $out[$type] = ['class' => $type, 'rules' => $this->rulesKeys($type), 'authorize' => $this->authorizeSummary($type, $route)];
        }

        return array_values($out);
    }

    private function rulesKeys(string $class): string
    {
        $rules = $this->symbols->findMethod($class, 'rules');
        if ($rules === null) {
            return 'no rules() in the project';
        }
        $keys = [];
        $partial = false;
        $found = false;
        foreach ($this->finder->findInstanceOf($rules->node->stmts ?? [], Stmt\Return_::class) as $return) {
            if (! $return->expr instanceof Expr\Array_) {
                $partial = true;

                continue;
            }
            $found = true;
            foreach ($return->expr->items as $item) {
                if ($item->key instanceof Node\Scalar\String_) {
                    $keys[$item->key->value] = true;
                } else {
                    $partial = true;
                }
            }
        }
        if (! $found) {
            return sprintf('not statically readable (%s:%d)', $rules->file, $rules->startLine);
        }
        $text = $keys === [] ? 'none' : implode(', ', array_map('strval', array_keys($keys)));

        return $partial ? $text.' (plus keys not statically readable)' : $text;
    }

    private function authorizeSummary(string $class, RouteEntry $route): string
    {
        $short = substr($class, (int) strrpos('\\'.$class, '\\'));
        foreach ($route->checks as $c) {
            if ($c->kind === AuthCheckKind::FormRequest && preg_match('~^FormRequest '.preg_quote($short, '~').'\\b(?!\\\\)~', $c->source) === 1) {
                return $c->strength->value.': '.$c->source;
            }
        }
        $authorize = $this->symbols->findMethod($class, 'authorize');

        return match (true) {
            $authorize === null => 'no authorize() in the project',
            PolicyRegistry::allowsAll($authorize) => 'returns true',
            default => sprintf('defined at %s:%d (not in the route checks)', $authorize->file, $authorize->startLine),
        };
    }

    /** @return list<string> project models the route binds, its checks scope, or the path's code names */
    private function models(Candidate $candidate): array
    {
        $names = [];
        foreach ($candidate->route->parameters as $p) {
            if ($p->boundModel !== null) {
                $names[] = $p->boundModel;
            }
        }
        foreach ($candidate->route->checks as $c) {
            if ($c->model !== null) {
                $names[] = $c->model;
            }
        }
        foreach ($candidate->path->nodes as $node) {
            $fn = $node->method->node ?? $node->closure;
            if ($fn === null) {
                continue;
            }
            foreach ($this->finder->findInstanceOf($fn, Node\Name::class) as $name) {
                $names[] = $name->toString();
            }
        }
        $out = [];
        foreach ($names as $name) {
            $name = ltrim($name, '\\');
            if (! isset($out[$name]) && $this->symbols->getClass($name) !== null && Ancestry::descendsFrom($this->symbols, $name, self::MODEL_ROOTS)) {
                $out[$name] = true;
            }
        }

        return array_keys($out);
    }

    private function modelAttributes(string $model): string
    {
        $text = $this->listProperty($model, 'fillable').'; '.$this->listProperty($model, 'guarded');
        $lineage = $this->symbols->lineage($model);
        $root = $lineage === [] ? null : $lineage[count($lineage) - 1]->parent;
        if ($root !== null && ! in_array(ltrim($root, '\\'), self::MODEL_ROOTS, true) && $this->symbols->getClass($root) === null) {
            $text .= '; extends '.ltrim($root, '\\').' outside the project';
        }

        return $text;
    }

    private function listProperty(string $model, string $name): string
    {
        $property = $this->symbols->findProperty($model, $name);
        if ($property === null) {
            return '$'.$name.' not declared';
        }
        if ($property->default === null) {
            return '$'.$name.' declared without a value';
        }
        if (! $property->default instanceof Expr\Array_) {
            return '$'.$name.' not statically readable';
        }
        $values = [];
        foreach ($property->default->items as $item) {
            if ($item->key !== null || $item->unpack || ! $item->value instanceof Node\Scalar\String_) {
                return '$'.$name.' not statically readable';
            }
            $values[] = "'".$item->value->value."'";
        }

        return '$'.$name.' = ['.implode(', ', $values).']';
    }

    /**
     * Pruned, line-tagged policy methods for the abilities the checks name, on the policies of the given models.
     *
     * @param  list<string>  $models
     * @param  list<AuthCheck>  $checks
     * @return list<string>
     */
    private function policyBlocks(array $models, array $checks): array
    {
        $abilities = [];
        foreach ($checks as $c) {
            if (preg_match_all('~(?:\bcan:|\(\s*[\'"])([A-Za-z_][A-Za-z0-9_]*)~', $c->source, $m) > 0) {
                foreach ($m[1] as $ability) {
                    $abilities[strtolower($ability)] = $ability;
                }
            }
        }
        if ($abilities === []) {
            return [];
        }
        $methods = [];
        foreach ($models as $model) {
            $policy = $this->policies->policyFor($model);
            if ($policy === null) {
                continue;
            }
            foreach (['before', ...array_values($abilities)] as $ability) {
                $method = $this->policies->abilityHolder($policy, $ability);
                if ($method !== null) {
                    $methods[$method->id()] = $method;
                }
            }
        }
        $blocks = [];
        foreach ($methods as $method) {
            $node = new PathNode($method->id(), $method, null, $method->file, $method->startLine, $method->endLine, 0, null, null);
            $blocks[] = $this->block($method->file, $method->id(), $method->startLine, $method->endLine, $this->pruner->prune($node, $this->authHelpers)->lines);
        }

        return $blocks;
    }

    // ---- text ----------------------------------------------------------------------------------------------------

    private function finish(string $text): string
    {
        return $this->finished[$text] ??= $this->redact(self::escape($text));
    }

    // Redacts, then restores the builder's own header and marker lines (paths and ids only).
    private function redact(string $escaped): string
    {
        $redacted = $this->redactor->redact($escaped);
        $before = explode("\n", $escaped);
        $after = explode("\n", $redacted);
        if (count($before) !== count($after)) {
            return $redacted;
        }
        foreach ($before as $i => $line) {
            if (isset($this->generated[$line])) {
                $after[$i] = $line;
            }
        }

        return implode("\n", $after);
    }

    private function generate(string $line): string
    {
        $this->generated[self::escape($line)] = true;

        return $line;
    }

    // Neutralises anything that could open or close the fence, in any case or spacing.
    private static function escape(string $text): string
    {
        return (string) preg_replace('~<\s*(/?)\s*untrusted[_-]code~i', '<$1untrusted-code-escaped', $text);
    }

    private static function key(RouteEntry $route): string
    {
        return implode('|', $route->methods).' '.$route->uri;
    }

    private static function id(int $number, RouteEntry $route, int $part): string
    {
        $slug = trim((string) preg_replace('~[^a-z0-9]+~', '-', strtolower(self::key($route))), '-');
        $slug = rtrim(substr($slug, 0, self::MAX_KEY), '-');

        return sprintf('%03d-%s-%d', $number, $slug === '' ? 'route' : $slug, $part);
    }
}
