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

/**
 * Builds the SPEC §9 payloads for one candidate: context, fenced line-tagged code, escaping, redaction, splitting.
 *
 * @phpstan-type Block array{node: PathNode, lines: list<array{line: int, text: string}>, cut?: bool}
 */
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

    /** @var array<string, string> raw path or id => encoded, escaped and redacted */
    private array $safe = [];

    public function __construct(
        ParseResult $parsed,
        private readonly SymbolTable $symbols,
        private readonly AuthCheckExtractor $extractor,
        private readonly PolicyRegistry $policies,
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
        $warnings = [];
        try {
            $payloads = $this->payloads($candidate, $number, $warnings);
        } catch (\Throwable $e) {
            // Never drop a candidate: emit a payload that says the code is missing.
            $route = $candidate->route;
            $warnings[] = sprintf('%s:%d: payload build failed: %s', $route->file, $route->line, $e->getMessage());
            $context = $this->finish("Route:\n  ".self::enc(self::key($route))."\n  declared at: ".self::enc($route->file).':'.$route->line."\n\nBuild error:\n  ".self::enc($e->getMessage()));
            $code = self::OPEN."\n// payload could not be built; this route needs a manual review\n".self::CLOSE;
            $payloads = [new Payload($this->id($number, $route, 1), $candidate, $context, $code, 1, 1, true)];
        }
        foreach ($payloads as $payload) {
            $tokens = $payload->tokens();
            if ($tokens > $this->limit) {
                $warnings[] = sprintf('%s:%d: payload %s is %d tokens, over max_payload_tokens %d', $candidate->route->file, $candidate->route->line, $payload->id, $tokens, $this->limit);
            }
        }
        $this->finished = [];

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
        $checks = $route->checks;
        foreach ($nodeChecks as $found) {
            array_push($checks, ...$found);
        }
        [$policyBlocks, $policyNotes] = $this->policies($checks, $warnings);
        $head = $this->context($candidate, $formRequests);
        // Facade and Eloquent calls are framework code the LLM already knows; they only add noise.
        $unresolved = array_values(array_filter($path->unresolved, static fn (string $u): bool => ! str_contains($u, ': [facade] ') && ! str_contains($u, ': [eloquent] ')));
        $allIds = array_fill_keys(array_map(static fn (PathNode $n): string => $n->id, $path->nodes), true);
        $context = self::assemble($head, self::policySection($policyBlocks, $policyNotes, true), self::listed($unresolved, $allIds));

        if ($this->fits($context, [...$blocks, ...$policyBlocks])) {
            return [new Payload($this->id($number, $route, 1), $candidate, $this->finish($context), $this->code([...$blocks, ...$policyBlocks]), 1, 1, false)];
        }

        // Split: each part lists the unresolved calls of its own code; calls no node owns go to part 1, as does the policy code.
        $owners = self::owners($unresolved, $path->nodes);
        $summary = $this->upstreamBase($route, $formRequests);
        $parts = [];
        $earlier = [];
        $ctxFor = function (array $partBlocks, bool $first, array $earlier) use ($head, $unresolved, $owners, $summary, $nodeChecks, $policyBlocks, $policyNotes): string {
            $ids = [];
            foreach ($partBlocks as $b) {
                $ids[$b['node']->id] = true;
            }
            $before = [];
            foreach ($earlier as $node) {
                $before[$node->id] = true;
            }
            $own = [];
            $elsewhere = 0;
            foreach ($unresolved as $i => $u) {
                if ($owners[$i] === null ? $first : isset($ids[$owners[$i]])) {
                    $own[] = $u;
                } elseif ($owners[$i] === null || isset($before[$owners[$i]])) {
                    $elsewhere++;
                }
            }

            return $this->withSummary(self::assemble($head, self::policySection($policyBlocks, $policyNotes, $first), self::listed($own, $ids)), $summary, array_values($earlier), $nodeChecks, $elsewhere);
        };
        foreach ($this->groups($blocks) as $group) {
            $current = [];
            foreach ($group as $block) {
                $extra = $parts === [] ? $policyBlocks : [];
                $trial = [...$current, $block];
                if ($current !== [] && ! $this->fits($ctxFor($trial, $parts === [], $earlier), [...$trial, ...$extra])) {
                    $parts[] = [$ctxFor($current, $parts === [], $earlier), [...$current, ...$extra], false];
                    array_push($earlier, ...array_map(static fn (array $b): PathNode => $b['node'], $current));
                    $current = [];
                    $extra = [];
                }
                if ($current === [] && ! $this->fits($ctxFor([$block], $parts === [], $earlier), [$block, ...$extra])) {
                    $ctx = $ctxFor([$block], $parts === [], $earlier);
                    $parts[] = [$ctx, [$this->truncate($ctx, $block, $extra), ...$extra], true];
                    $earlier[] = $block['node'];

                    continue;
                }
                $current[] = $block;
            }
            if ($current !== []) {
                $parts[] = [$ctxFor($current, $parts === [], $earlier), [...$current, ...($parts === [] ? $policyBlocks : [])], false];
                array_push($earlier, ...array_map(static fn (array $b): PathNode => $b['node'], $current));
            }
        }

        // One part has nothing upstream to summarise.
        if (count($parts) === 1) {
            $parts[0][0] = $context;
        }
        $out = [];
        foreach ($parts as $i => [$ctx, $partBlocks, $truncated]) {
            $out[] = new Payload($this->id($number, $route, $i + 1), $candidate, $this->finish($ctx), $this->code($partBlocks), $i + 1, count($parts), $truncated);
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
            return $this->pruner->prune($node, $this->authHelpers)->lines;
        } catch (\Throwable $e) {
            $warnings[] = sprintf('%s:%d: could not prune %s: %s', $node->file, $node->startLine, $node->id, $e->getMessage());

            return [];
        }
    }

    /**
     * The block's lines, each flagged true when the builder wrote it (header, marker) rather than copied it from source.
     *
     * @param  Block  $block
     * @return list<array{string, bool}>
     */
    private function block(array $block): array
    {
        $node = $block['node'];
        $lines = $block['lines'];
        $id = $this->safe($node->id);
        $range = $lines === [] ? [$node->startLine, $node->endLine] : [min(array_column($lines, 'line')), max(array_column($lines, 'line'))];
        $out = [[sprintf('// FILE: %s :: %s (L%d-L%d)', $this->safe($node->file), $id, $range[0], $range[1]), true]];
        if ($lines === [] && ! ($block['cut'] ?? false)) {
            $out[] = ['// '.$id.': source not available', true];
        }
        foreach ($lines as $l) {
            $trivial = $l['text'] === '// '.$node->id.': trivial accessor omitted';
            $out[] = $trivial ? ['L'.$l['line'].'| // '.$id.': trivial accessor omitted', true] : ['L'.$l['line'].'| '.$l['text'], false];
        }
        if ($block['cut'] ?? false) {
            $out[] = [self::TRUNCATED, true];
        }

        return $out;
    }

    /**
     * Escapes and redacts the source lines; the builder's own lines are encoded and redacted piece by piece, then put back by index.
     *
     * @param  list<Block>  $blocks
     */
    private function code(array $blocks): string
    {
        $lines = [[self::OPEN, true]];
        foreach ($blocks as $i => $block) {
            if ($i > 0) {
                $lines[] = ['', true];
            }
            array_push($lines, ...$this->block($block));
        }
        $lines[] = [self::CLOSE, true];
        $raw = array_map(static fn (array $l): string => $l[1] ? $l[0] : self::escape($l[0]), $lines);
        $redacted = explode("\n", $this->redactor->redact(implode("\n", $raw)));
        if (count($redacted) !== count($raw)) {
            return implode("\n", $redacted);
        }
        foreach ($lines as $i => [$text, $generated]) {
            if ($generated) {
                $redacted[$i] = $text;
            }
        }

        return implode("\n", $redacted);
    }

    /** @param list<Block> $blocks */
    private function fits(string $context, array $blocks): bool
    {
        return TokenEstimator::estimate($this->finish($context)."\n\n".$this->code($blocks)) <= $this->limit;
    }

    /**
     * The longest prefix of the node's lines that fits beside the extra blocks; at least through the signature line, even
     * over the limit (build() then warns), since an empty part tells the reviewer nothing.
     *
     * @param  Block  $block
     * @param  list<Block>  $extra
     * @return Block
     */
    private function truncate(string $context, array $block, array $extra): array
    {
        $low = self::signatureLines($block);
        // A docblock gives way first when it alone would push the signature over the limit.
        if (! $this->fits($context, [['node' => $block['node'], 'lines' => array_slice($block['lines'], 0, $low), 'cut' => true], ...$extra])) {
            $block['lines'] = array_values(array_filter($block['lines'], static fn (array $l): bool => $l['line'] >= $block['node']->startLine));
            $low = self::signatureLines($block);
        }
        $high = count($block['lines']);
        while ($low < $high) {
            $mid = intdiv($low + $high + 1, 2);
            if ($this->fits($context, [['node' => $block['node'], 'lines' => array_slice($block['lines'], 0, $mid), 'cut' => true], ...$extra])) {
                $low = $mid;
            } else {
                $high = $mid - 1;
            }
        }

        return ['node' => $block['node'], 'lines' => array_slice($block['lines'], 0, $low), 'cut' => true];
    }

    /**
     * How many leading lines run through the function's signature line (docblock lines come first).
     *
     * @param  Block  $block
     */
    private static function signatureLines(array $block): int
    {
        $start = $block['node']->startLine;
        $fallback = null;
        foreach ($block['lines'] as $i => $line) {
            if ($line['line'] < $start) {
                continue;
            }
            $fallback ??= $i + 1;
            if (preg_match('/\b(function|fn)\b/', $line['text']) === 1) {
                return $i + 1;
            }
        }

        return $fallback ?? min(1, count($block['lines']));
    }

    /**
     * Part 1 is the entry and its direct callees; then one group per further class, in path order.
     *
     * @param  list<Block>  $blocks
     * @return list<list<Block>>
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
     * @return list<string> the sections before the policies
     */
    private function context(Candidate $candidate, array $formRequests): array
    {
        $sections = [$this->routeSection($candidate->route)];

        $lines = [];
        foreach ($candidate->categories as $category) {
            $lines[] = '  - '.$category->value.': '.self::enc($candidate->reasons[$category->value] ?? '');
        }
        $sections[] = self::section('Candidate categories', $lines);

        $lines = [];
        foreach ($formRequests as $fr) {
            array_push($lines, '  '.$fr['class'], '    rules keys: '.$fr['rules'], '    authorize: '.$fr['authorize']);
        }
        $sections[] = self::section('FormRequest', $lines);

        $models = $this->models($candidate);
        $sections[] = self::section('Models', array_map(fn (string $m): string => '  '.self::enc($m).': '.$this->modelAttributes($m), $models));

        return array_values(array_filter($sections, static fn (string $s): bool => $s !== ''));
    }

    /**
     * @param  list<string>  $head  sections before the policies
     * @param  list<string>  $unresolved
     */
    private static function assemble(array $head, string $policies, array $unresolved): string
    {
        $sections = [...$head, $policies, self::section('Unresolved calls', array_map(static fn (string $u): string => '  - '.self::enc($u), $unresolved))];

        return implode("\n\n", array_values(array_filter($sections, static fn (string $s): bool => $s !== '')));
    }

    /**
     * A pointer to the policy code (in the fence of part 1) plus the abilities that could not be verified.
     *
     * @param  list<Block>  $blocks
     * @param  list<string>  $notes
     */
    private static function policySection(array $blocks, array $notes, bool $first): string
    {
        $lines = [];
        if ($blocks !== []) {
            $lines[] = '  '.($first ? 'code below: ' : 'code in part 1: ').implode(', ', array_map(static fn (array $b): string => self::enc($b['node']->id), $blocks));
        }
        foreach ($notes as $note) {
            $lines[] = '  '.$note;
        }

        return self::section('Policies', $lines);
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

    /**
     * The unresolved calls a part shows: an already-visited call whose target's code is in the part is dropped, and
     * repeats of the same call text in one file collapse into the first, with a count.
     *
     * @param  list<string>  $unresolved  "file:line: [kind] text"
     * @param  array<string, true>  $ids  node ids whose code is in the part
     * @return list<string>
     */
    private static function listed(array $unresolved, array $ids): array
    {
        $first = [];
        $count = [];
        foreach ($unresolved as $u) {
            if (preg_match('~^(.*?):\d+: (\[already-visited\] .*) → (.+)$~', $u, $m) === 1 && isset($ids[$m[3]])) {
                continue;
            }
            $key = preg_match('~^(.*?):\d+: (\[.*)$~s', $u, $m) === 1 ? $m[1]."\0".$m[2] : $u;
            $first[$key] ??= $u;
            $count[$key] = ($count[$key] ?? 0) + 1;
        }
        $out = [];
        foreach ($first as $key => $u) {
            $out[] = $count[$key] > 1 ? $u.' ×'.$count[$key] : $u;
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
        $lines = ['  '.self::enc(self::key($route))];
        if ($route->name !== null) {
            $lines[] = '  name: '.self::enc($route->name);
        }
        $lines[] = '  action: '.self::enc($action);
        $lines[] = '  declared at: '.self::enc($route->file).':'.$route->line;
        $lines[] = '  middleware: '.($route->middleware === [] ? 'none' : self::enc(implode(', ', $route->middleware)));
        if ($route->withoutMiddleware !== []) {
            $lines[] = '  without middleware: '.self::enc(implode(', ', $route->withoutMiddleware));
        }
        if ($route->parameters !== []) {
            $params = [];
            foreach ($route->parameters as $p) {
                $params[] = '{'.$p->name.($p->field === null ? '' : ':'.$p->field).($p->optional ? '?' : '').'}'
                    .($p->boundModel === null ? '' : ' bound to '.$p->boundModel).($p->domain ? ' (domain)' : '');
            }
            $lines[] = '  parameters: '.self::enc(implode('; ', $params));
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

    // One encoded line; $paramCovers marks a callee check whose `covers` names the callee's own parameter.
    private static function check(AuthCheck $c, bool $paramCovers = false): string
    {
        $extra = [];
        if ($c->abilities !== null) {
            $extra[] = $c->abilities === [] ? 'ability unresolved' : 'ability '.implode(', ', array_map(self::quote(...), $c->abilities));
        }
        if ($c->abilityModel !== null) {
            $extra[] = 'on '.$c->abilityModel;
        }
        if ($c->covers !== null) {
            $extra[] = $paramCovers ? 'covers $'.$c->covers : 'covers {'.$c->covers.'}';
        }
        if ($c->routeWide) {
            $extra[] = 'route-wide';
        }
        if ($c->model !== null) {
            $extra[] = 'model '.$c->model;
        }

        return self::enc(sprintf('%s/%s: %s (%s:%d)%s', $c->kind->value, $c->strength->value, $c->source, $c->file, $c->line, $extra === [] ? '' : ' ['.implode(', ', $extra).']'));
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
     * @param  int  $elsewhere  unresolved calls listed in earlier parts
     */
    private function withSummary(string $context, array $summary, array $earlier, array $nodeChecks, int $elsewhere): string
    {
        $lines = $summary;
        foreach ($earlier as $node) {
            foreach ($nodeChecks[$node->id] ?? [] as $c) {
                $lines[] = '  earlier check in '.self::enc($node->id).': '.self::check($c, true);
            }
        }
        if ($elsewhere > 0) {
            $lines[] = '  Unresolved calls in earlier parts: '.$elsewhere;
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
        $bound = [];
        $params = $fn instanceof MethodSymbol ? $fn->params : [];
        foreach ($params as $name => $type) {
            if ($type !== null && $this->isModel($type)) {
                $bound[$name] = ltrim($type, '\\');
            }
        }
        try {
            return $this->extractor->bodyChecks($fn, $node->file, $bound)[0];
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
            $out[$type] = ['class' => self::enc($type), 'rules' => $this->rulesKeys($type), 'authorize' => self::enc($this->authorizeSummary($type, $route))];
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
            return sprintf('not statically readable (%s:%d)', self::enc($rules->file), $rules->startLine);
        }
        $text = $keys === [] ? 'none' : implode(', ', array_map(static fn (int|string $k): string => self::quote((string) $k), array_keys($keys)));

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
            if (! isset($out[$name]) && $this->isModel($name)) {
                $out[$name] = true;
            }
        }

        return array_keys($out);
    }

    private function isModel(string $class): bool
    {
        return $this->symbols->getClass($class) !== null && Ancestry::descendsFrom($this->symbols, $class, self::MODEL_ROOTS);
    }

    private function modelAttributes(string $model): string
    {
        $text = $this->listProperty($model, 'fillable').'; '.$this->listProperty($model, 'guarded');
        $lineage = $this->symbols->lineage($model);
        $root = $lineage === [] ? null : $lineage[count($lineage) - 1]->parent;
        if ($root !== null && ! in_array(ltrim($root, '\\'), self::MODEL_ROOTS, true) && $this->symbols->getClass($root) === null) {
            $text .= '; extends '.self::enc(ltrim($root, '\\')).' outside the project';
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
            $values[] = self::quote($item->value->value);
        }

        return '$'.$name.' = ['.implode(', ', $values).']';
    }

    /**
     * Policy methods and Gate::define callbacks for the abilities the checks name, as code blocks, plus notes for abilities that stay unverified.
     *
     * @param  list<AuthCheck>  $checks
     * @param  list<string>  $warnings
     * @return array{list<Block>, list<string>}
     */
    private function policies(array $checks, array &$warnings): array
    {
        $found = [];
        $notes = [];
        foreach ($checks as $c) {
            if ($c->abilities === null) {
                continue;
            }
            if ($c->abilities === []) {
                $notes[] = sprintf('ability at %s:%d: name not statically resolvable (unverified)', self::enc($c->file), $c->line);

                continue;
            }
            foreach ($c->abilities as $ability) {
                if ($this->policyMethods($c->abilityModel, $ability, $found)) {
                    continue;
                }
                $defines = $this->policies->gateDefinitions($ability);
                foreach ($defines as $define) {
                    if ($define->method !== null) {
                        $found[$define->method->id()] = new PathNode($define->method->id(), $define->method, null, $define->method->file, $define->method->startLine, $define->method->endLine, 0, null, null);
                    } elseif ($define->closure !== null) {
                        $id = 'gate:'.preg_replace('~\s+~', '_', $ability);
                        $found[$id] = new PathNode($id, null, $define->closure, $define->file, $define->closure->getStartLine(), $define->closure->getEndLine(), 0, null, null);
                    } else {
                        $notes[] = sprintf('ability %s: Gate::define at %s:%d: %s (unverified)', self::quote($ability), self::enc($define->file), $define->line, self::enc((string) $define->unresolved));
                    }
                }
                if ($defines === []) {
                    $notes[] = sprintf('ability %s: definition not found (unverified)', self::quote($ability));
                }
            }
        }
        $blocks = [];
        foreach ($found as $node) {
            $blocks[] = ['node' => $node, 'lines' => $this->lines($node, $warnings)];
        }

        return [$blocks, array_values(array_unique($notes))];
    }

    /**
     * Adds the policy's ability method (and its before()) when the model's policy defines it.
     *
     * @param  array<string, PathNode>  $found
     */
    private function policyMethods(?string $model, string $ability, array &$found): bool
    {
        $policy = $model === null ? null : $this->policies->policyFor($model);
        $method = $policy === null ? null : $this->policies->abilityHolder($policy, PolicyRegistry::abilityMethod($ability));
        if ($policy === null || $method === null) {
            return false;
        }
        $before = $this->symbols->findMethod($policy, 'before');
        foreach ($before === null ? [$method] : [$before, $method] as $m) {
            $found[$m->id()] ??= new PathNode($m->id(), $m, null, $m->file, $m->startLine, $m->endLine, 0, null, null);
        }

        return true;
    }

    // ---- text ----------------------------------------------------------------------------------------------------

    private function finish(string $text): string
    {
        return $this->finished[$text] ??= $this->redactor->redact(self::escape($text));
    }

    // A path or id for a builder-written line: one line, fence-safe, redacted on its own.
    private function safe(string $text): string
    {
        return $this->safe[$text] ??= $this->redactor->redact(self::escape(self::enc($text)));
    }

    // Shows control characters (line breaks above all) as escapes, so an app value never starts a new line.
    private static function enc(string $text): string
    {
        return (string) preg_replace_callback('~[\x00-\x1F\x7F]|\xC2\x85|\xE2\x80[\xA8\xA9]~', static fn (array $m): string => match ($m[0]) {
            "\n" => '\n',
            "\r" => '\r',
            "\t" => '\t',
            default => '\x'.strtoupper(bin2hex($m[0])),
        }, $text);
    }

    // A literal from the app's code: double-quoted, with backslashes, quotes and control characters escaped.
    private static function quote(string $text): string
    {
        return '"'.self::enc(str_replace(['\\', '"'], ['\\\\', '\\"'], $text)).'"';
    }

    // Neutralises anything that could pass for the fence tag: any case, spacing, separator or fullwidth variant, entity or not.
    private static function escape(string $text): string
    {
        return (string) preg_replace('~untrusted(?:[\s_\-]|\xEF\xBC\xBF|\xEF\xBC\x8D)*code~i', 'untrusted-code-escaped', $text);
    }

    private static function key(RouteEntry $route): string
    {
        return implode('|', $route->methods).' '.$route->uri;
    }

    private function id(int $number, RouteEntry $route, int $part): string
    {
        $slug = trim((string) preg_replace('~[^a-z0-9]+~', '-', strtolower($this->redactor->redact(self::key($route)))), '-');
        $slug = rtrim(substr($slug, 0, self::MAX_KEY), '-');

        return sprintf('%03d-%s-%d', $number, $slug === '' ? 'route' : $slug, $part);
    }
}
