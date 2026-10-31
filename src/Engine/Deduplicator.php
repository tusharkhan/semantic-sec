<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Engine;

/** Collapses findings that share a fingerprint (SPEC §11.3). */
final class Deduplicator
{
    /**
     * Keeps the highest severity, then the highest confidence, with every path step merged uniquely: the winner's first, then the rest in sorted order.
     *
     * @param  list<Vulnerability>  $findings
     * @return list<Vulnerability>  one per fingerprint, sorted by fingerprint
     */
    public function merge(array $findings): array
    {
        // Pool completion order varies, so ties resolve by fingerprint, payloadId, line, then title.
        usort($findings, static fn (Vulnerability $a, Vulnerability $b): int => strcmp($a->fingerprint, $b->fingerprint) ?: strcmp($a->payloadId, $b->payloadId) ?: $a->line <=> $b->line ?: strcmp($a->title, $b->title));
        $groups = [];
        foreach ($findings as $finding) {
            $groups[$finding->fingerprint][] = $finding;
        }

        $out = [];
        foreach ($groups as $group) {
            $best = $group[0];
            foreach ($group as $candidate) {
                if (self::outranks($candidate, $best)) {
                    $best = $candidate;
                }
            }
            if (count($group) === 1) {
                $out[] = $best;

                continue;
            }
            $path = [];
            foreach ([$best, ...array_filter($group, static fn (Vulnerability $v): bool => $v !== $best)] as $member) {
                foreach ($member->path as $step) {
                    $path[$step['file']."\0".$step['line']."\0".$step['symbol']] ??= $step;
                }
            }
            $out[] = $best->withPath(array_values($path));
        }

        return $out;
    }

    private static function outranks(Vulnerability $a, Vulnerability $b): bool
    {
        return [$a->severity->rank(), $a->confidence->rank()] > [$b->severity->rank(), $b->confidence->rank()];
    }
}
