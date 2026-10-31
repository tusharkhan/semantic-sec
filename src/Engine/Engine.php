<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Engine;

use TusharKhan\SemanticSec\Analysis\Category;
use TusharKhan\SemanticSec\Analysis\Confidence;
use TusharKhan\SemanticSec\Config\Config;
use TusharKhan\SemanticSec\Llm\ClientFactory;
use TusharKhan\SemanticSec\Llm\ClientInterface;
use TusharKhan\SemanticSec\Llm\FindingSchema;
use TusharKhan\SemanticSec\Llm\GroundingChecker;
use TusharKhan\SemanticSec\Llm\LlmOutcome;
use TusharKhan\SemanticSec\Llm\LlmResponse;
use TusharKhan\SemanticSec\Llm\RequestPool;
use TusharKhan\SemanticSec\Llm\ResponseValidator;
use TusharKhan\SemanticSec\Parsing\ParseResult;
use TusharKhan\SemanticSec\Parsing\Suppression;
use TusharKhan\SemanticSec\Payload\Payload;

/**
 * Payloads to findings: cache or pool, grounding, fingerprint, suppressions, dedup, baseline, then filters (SPEC §11).
 *
 * @phpstan-import-type Stats from AnalysisResult
 */
final class Engine
{
    private const TAGGED = '~^L\d+\|~m';

    /** @param ClientInterface $client the provider client behind ClientFactory::validated(); Ok answers are re-validated anyway */
    public function __construct(
        private readonly ClientInterface $client,
        private readonly ResultCache $cache,
        private readonly Fingerprinter $fingerprinter,
        private readonly GroundingChecker $grounding,
        private readonly ParseResult $parsed,
        private readonly Config $config,
        private readonly Baseline $baseline,
    ) {
    }

    /** @param list<Payload> $payloads */
    public function run(array $payloads, int $candidates): AnalysisResult
    {
        /** @var Stats $stats */
        $stats = [
            'candidates' => $candidates, 'payloads' => count($payloads), 'skipped' => 0, 'unsent' => 0, 'sent' => 0, 'cacheHits' => 0,
            'ok' => 0, 'refused' => 0, 'truncated' => 0, 'invalid' => 0, 'failed' => 0, 'dropped' => 0, 'filtered' => 0, 'tokens' => 0, 'budgetExceeded' => false,
        ];
        $seen = [];
        foreach ($payloads as $p) {
            if (isset($seen[$p->id])) {
                throw new \LogicException("duplicate payload id {$p->id}");
            }
            $seen[$p->id] = true;
        }
        $warnings = $this->directiveWarnings();

        /** @var list<array{Payload, LlmResponse}> $answers */
        $answers = [];
        /** @var array<string, Payload> $misses */
        $misses = [];
        foreach ($payloads as $p) {
            if (preg_match(self::TAGGED, $p->code) !== 1) {
                $stats['skipped']++;
                $warnings[] = "payload {$p->id}: no source code to send, skipped";

                continue;
            }
            $hit = $this->cache->get($p);
            if ($hit !== null) {
                $stats['cacheHits']++;
                $answers[] = [$p, $hit];

                continue;
            }
            $misses[$p->id] = $p;
        }

        array_push($answers, ...$this->send($misses, $stats, $warnings));
        array_push($warnings, ...$this->cache->warnings());

        [$vulnerabilities, $drops] = $this->ground($answers);
        $stats['dropped'] = array_sum($drops);
        ksort($drops);
        foreach ($drops as $kind => $n) {
            $warnings[] = sprintf('dropped %d finding%s not grounded in the payload: %s', $n, $n === 1 ? '' : 's', $kind);
        }

        [$active, $suppressed, $reasonless] = $this->suppress($vulnerabilities);
        array_push($warnings, ...$reasonless);

        $findings = [];
        $baselined = [];
        $filtered = [];
        foreach ((new Deduplicator())->merge($active) as $v) {
            if ($this->baseline->contains($v->fingerprint)) {
                $baselined[] = $v;
            } elseif ($v->severity->atLeast($this->config->level)) {
                $findings[] = ['vulnerability' => $v, 'failing' => $v->confidence->atLeast($this->config->minConfidence)];
            } else {
                $filtered[] = $v;
                $stats['filtered']++;
            }
        }

        return new AnalysisResult($findings, $suppressed, $baselined, $warnings, $stats, $filtered);
    }

    /**
     * Sends cache misses through the pool; Ok answers are cached, everything else becomes a warning, in payload order.
     *
     * @param  array<string, Payload>  $misses
     * @param  Stats  $stats
     * @param  list<string>  $warnings
     * @return list<array{Payload, LlmResponse}>
     */
    private function send(array $misses, array &$stats, array &$warnings): array
    {
        $schema = FindingSchema::schema();
        $system = $this->cache->systemPrompt();
        $requests = [];
        foreach ($misses as $p) {
            $requests[] = ClientFactory::request($this->config, $p->id, $system, $p->text(), $schema);
        }
        $pool = (new RequestPool($this->client, $this->config->concurrency, $this->config->budgetTokens))->run($requests);
        $stats['tokens'] = $pool->usedTokens;
        $stats['budgetExceeded'] = $pool->budgetExceeded;

        $responses = [];
        foreach ($pool->responses as $r) {
            $responses[$r->payloadId] = $r;
        }
        $failures = [];
        foreach ($pool->failures as $f) {
            $failures[$f['payloadId']] = $f['error'];
        }

        $answers = [];
        $unsent = 0;
        foreach ($misses as $id => $p) {
            $r = $responses[$id] ?? null;
            if ($r === null) {
                if (isset($failures[$id])) {
                    $stats['sent']++;
                    $stats['failed']++;
                    $warnings[] = "payload {$id}: {$failures[$id]}";
                } else {
                    $unsent++;
                }

                continue;
            }
            $stats['sent']++;
            // Only data that passes the schema is trusted, whatever client produced it.
            $outcome = $r->outcome === LlmOutcome::Ok && ($r->data === null || ResponseValidator::errors($r->data) !== []) ? LlmOutcome::Invalid : $r->outcome;
            $stats[$outcome->value]++;
            if ($outcome === LlmOutcome::Ok) {
                $this->cache->put($p, $r);
                $answers[] = [$p, $r];
            } else {
                $warnings[] = "payload {$id}: {$outcome->value}".($r->detail === null || $r->detail === '' ? '' : " ({$r->detail})");
            }
        }
        if ($unsent > 0) {
            $stats['unsent'] = $unsent;
            $warnings[] = sprintf('%d payload%s not sent: token budget exhausted', $unsent, $unsent === 1 ? '' : 's');
        }

        return $answers;
    }

    /**
     * @param  list<array{Payload, LlmResponse}>  $answers
     * @return array{list<Vulnerability>, array<string, int>} fingerprinted findings, and drop counts by reason kind
     */
    private function ground(array $answers): array
    {
        $out = [];
        $drops = [];
        foreach ($answers as [$p, $r]) {
            $list = $r->data['findings'] ?? [];
            foreach (is_array($list) ? $list : [] as $finding) {
                [$grounded, $reason] = is_array($finding) ? $this->grounding->ground($finding, $p) : [null, 'malformed finding'];
                $category = is_array($grounded) && is_string($grounded['category'] ?? null) ? Category::tryFrom($grounded['category']) : null;
                if ($grounded === null || $category === null) {
                    $kind = self::dropKind($reason ?? 'malformed finding');
                    $drops[$kind] = ($drops[$kind] ?? 0) + 1;

                    continue;
                }
                // SPEC §9: a finding from a truncated payload is never more than medium confidence.
                if ($p->truncated && ($grounded['confidence'] ?? null) === Confidence::High->value) {
                    $grounded['confidence'] = Confidence::Medium->value;
                }
                $file = is_string($grounded['file'] ?? null) ? $grounded['file'] : '';
                $symbol = is_string($grounded['symbol'] ?? null) ? $grounded['symbol'] : '';
                try {
                    $out[] = Vulnerability::fromGrounded($grounded, $p, $r->model, $this->fingerprinter->fingerprint($file, $symbol, $category, $p));
                } catch (\InvalidArgumentException) {
                    $drops['malformed finding'] = ($drops['malformed finding'] ?? 0) + 1;
                }
            }
        }
        // Completion order varies, so suppression ties resolve the same way Deduplicator's do.
        usort($out, static fn (Vulnerability $a, Vulnerability $b): int => strcmp($a->fingerprint, $b->fingerprint) ?: strcmp($a->payloadId, $b->payloadId) ?: $a->line <=> $b->line ?: strcmp($a->title, $b->title));

        return [$out, $drops];
    }

    /**
     * A finding goes to suppressed only when a directive in its own file covers its own line and category (SPEC §11.1).
     *
     * @param  list<Vulnerability>  $vulnerabilities  sorted
     * @return array{list<Vulnerability>, list<array{vulnerability: Vulnerability, suppression: Suppression}>, list<string>}
     */
    private function suppress(array $vulnerabilities): array
    {
        $by = [];
        $hidden = [];
        $active = [];
        $reasonless = [];
        foreach ($vulnerabilities as $v) {
            $s = $this->parsed->file($v->file)?->suppressions->find($v->line, $v->category);
            if ($s === null) {
                $active[] = $v;

                continue;
            }
            $by[$v->fingerprint] ??= $s;
            $hidden[] = $v;
            if ($s->reason === null) {
                $reasonless[$s->file.':'.$s->commentLine] = "{$s->file}:{$s->commentLine}: suppression without a reason honoured";
            }
        }
        // Only covered findings are merged here; an uncovered one with the same fingerprint stays active.
        $suppressed = array_map(static fn (Vulnerability $v): array => ['vulnerability' => $v, 'suppression' => $by[$v->fingerprint]], (new Deduplicator())->merge($hidden));

        return [$active, $suppressed, array_values($reasonless)];
    }

    // Malformed or misplaced directives, reported once per run.
    /** @return list<string> */
    private function directiveWarnings(): array
    {
        $out = [];
        foreach ($this->parsed->files as $file) {
            array_push($out, ...$file->suppressions->invalid);
        }

        return $out;
    }

    // The reason without the model's values, so one warning covers every drop of a kind.
    private static function dropKind(string $reason): string
    {
        return match (true) {
            str_starts_with($reason, 'file ') => 'file not in payload',
            str_starts_with($reason, 'line L') => 'line not in payload',
            str_starts_with($reason, 'line ') => 'line outside its symbol',
            default => 'malformed finding',
        };
    }
}
