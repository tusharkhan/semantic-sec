<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support\Benchmark;

/**
 * Every verdict, sliced by set, app and confidence on demand.
 *
 * @phpstan-import-type Finding from CaseVerdict
 *
 * @phpstan-type Unattributed array{app: string, set: string|null, finding: Finding}
 */
final class Score
{
    public const SETS = ['existing', 'blind'];

    /**
     * @param list<CaseVerdict> $cases
     * @param list<PublicVerdict> $publics
     * @param list<Unattributed> $unattributed safe-code findings no case or public route accounts for; set is null when the app mixes sets
     */
    public function __construct(public readonly array $cases, public readonly array $publics, public readonly array $unattributed = [])
    {
    }

    public function verdict(string $id): CaseVerdict
    {
        foreach ($this->cases as $verdict) {
            if ($verdict->case->id === $id) {
                return $verdict;
            }
        }

        throw new \InvalidArgumentException("no verdict for case {$id}");
    }

    // A null set or app means all of them; failingOnly counts findings at medium or high confidence only.
    public function counts(?string $set = null, ?string $app = null, bool $failingOnly = false): Counts
    {
        $cases = array_filter($this->cases, static fn (CaseVerdict $v): bool => ($set === null || $v->case->set === $set) && ($app === null || $v->case->app === $app));
        $publics = array_filter($this->publics, static fn (PublicVerdict $p): bool => ($set === null || $p->route->set === $set) && ($app === null || $p->route->app === $app));
        $unattributed = array_filter($this->unattributed, static fn (array $u): bool => ($set === null || $u['set'] === $set) && ($app === null || $u['app'] === $app)
            && (! $failingOnly || in_array($u['finding']['confidence'], Scorer::FAILING, true)));
        $mismatches = 0;
        foreach ($cases as $v) {
            $mismatches += ($v->mapVulnerable['ok'] ? 0 : 1) + ($v->mapSafe['ok'] ? 0 : 1);
        }

        return new Counts(
            cases: count($cases),
            found: count(array_filter($cases, static fn (CaseVerdict $v): bool => $failingOnly ? $v->foundFailing : $v->found)),
            flagged: count(array_filter($cases, static fn (CaseVerdict $v): bool => $failingOnly ? $v->flaggedFailing : $v->flagged)),
            publicRoutes: count($publics),
            publicViolations: count(array_filter($publics, static fn (PublicVerdict $p): bool => ($failingOnly ? $p->byFailing : $p->by) !== null)),
            mapVariants: 2 * count($cases),
            mapMismatches: $mismatches,
            unattributed: count($unattributed),
            foundStrict: count(array_filter($cases, static fn (CaseVerdict $v): bool => $failingOnly ? $v->foundStrictFailing : $v->foundStrict)),
        );
    }

    /** @return list<string> */
    public function apps(): array
    {
        $apps = array_unique([...array_map(static fn (CaseVerdict $v): string => $v->case->app, $this->cases), ...array_map(static fn (PublicVerdict $p): string => $p->route->app, $this->publics)]);
        sort($apps);

        return $apps;
    }

    /** @return list<string> sets that have at least one case or public route, in SETS order */
    public function sets(): array
    {
        $present = [...array_map(static fn (CaseVerdict $v): string => $v->case->set, $this->cases), ...array_map(static fn (PublicVerdict $p): string => $p->route->set, $this->publics)];

        return array_values(array_filter(self::SETS, static fn (string $s): bool => in_array($s, $present, true)));
    }

    // True when any case credits a post-hoc accept, so strict and accepted found counts can differ.
    public function hasPosthoc(): bool
    {
        foreach ($this->cases as $v) {
            if ($v->case->vulnerable->posthoc) {
                return true;
            }
        }

        return false;
    }

    // True when the dry-run selection was measured for at least one case.
    public function selectionMeasured(): bool
    {
        foreach ($this->cases as $v) {
            if ($v->selectedVulnerable !== null) {
                return true;
            }
        }

        return false;
    }

    /**
     * Vulnerable routes not selected for their category, and candidate:false safe routes that were selected.
     *
     * @return list<array{case: BenchmarkCase, variant: string, expected: string, actual: string}>
     */
    public function selectionMisses(): array
    {
        $misses = [];
        foreach ($this->cases as $v) {
            if ($v->selectedVulnerable === false) {
                $misses[] = ['case' => $v->case, 'variant' => 'vulnerable', 'expected' => 'selected for '.$v->case->category, 'actual' => self::selection($v->vulnerableCategories)];
            }
            if ($v->selectedSafe === true && $v->case->safe->candidate === false) {
                $misses[] = ['case' => $v->case, 'variant' => 'safe', 'expected' => 'not selected (candidate: false)', 'actual' => self::selection($v->safeCategories)];
            }
        }

        return $misses;
    }

    /** @param list<string>|null $categories */
    public static function selection(?array $categories): string
    {
        return $categories === null || $categories === [] ? 'not selected' : 'selected for '.implode(', ', $categories);
    }
}
