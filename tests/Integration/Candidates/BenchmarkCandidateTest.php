<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Integration\Candidates;

use PHPUnit\Framework\TestCase;
use TusharKhan\SemanticSec\Analysis\Category;
use TusharKhan\SemanticSec\Candidates\Candidate;
use TusharKhan\SemanticSec\Candidates\CandidateSelector;
use TusharKhan\SemanticSec\Candidates\Exclusion;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkCorpus;
use TusharKhan\SemanticSec\Tests\Support\BenchmarkMaps;

/** The M4 gate on the set it was built for (existing); the blind set's selection is measured by bin/benchmark. */
final class BenchmarkCandidateTest extends TestCase
{
    /** @var array<string, array{0: array<string, Candidate>, 1: list<Exclusion>}> */
    private static array $runs = [];

    public function testEveryVulnerableVariantIsACandidateForItsCategory(): void
    {
        $checked = 0;
        foreach (BenchmarkCorpus::casesInSet('existing') as $case) {
            $key = (string) $case['vulnerable']['route'];
            $candidate = self::selected((string) $case['app'])[0][$key] ?? null;
            self::assertNotNull($candidate, sprintf('%s vulnerable %s not selected; exclusions: %s', $case['id'], $key, self::excluded((string) $case['app'], $key)));
            $categories = array_map(static fn (Category $c): string => $c->value, $candidate->categories);
            self::assertContains($case['category'], $categories, sprintf('%s vulnerable %s selected for [%s] (%s); exclusions: %s', $case['id'], $key, implode(', ', $categories), self::reasons($candidate), self::excluded((string) $case['app'], $key)));
            $checked++;
        }
        self::assertSame(15, $checked);
    }

    public function testEveryCandidateFalseSafeVariantIsNotSelected(): void
    {
        $checked = 0;
        foreach (BenchmarkCorpus::casesInSet('existing') as $case) {
            if (($case['safe']['candidate'] ?? true) !== false) {
                continue;
            }
            $key = (string) $case['safe']['route'];
            self::assertNotNull(BenchmarkMaps::build((string) $case['app'])->find($key), $key.' not in the map');
            $candidate = self::selected((string) $case['app'])[0][$key] ?? null;
            self::assertNull($candidate, sprintf('%s safe %s selected: %s', $case['id'], $key, $candidate === null ? '' : self::reasons($candidate)));
            $checked++;
        }
        self::assertSame(15, $checked);
    }

    public function testBlindUnscopedTenantListIsSelectedAndItsScopedTwinIsNot(): void
    {
        $case = null;
        foreach (BenchmarkCorpus::casesInSet('blind') as $c) {
            $case = $c['id'] === 'idor-tenant-list-unscoped' ? $c : $case;
        }
        self::assertNotNull($case);
        [$selected] = self::selected((string) $case['app']);
        $vuln = $selected[(string) $case['vulnerable']['route']] ?? null;
        self::assertNotNull($vuln, 'vulnerable not selected; exclusions: '.self::excluded((string) $case['app'], (string) $case['vulnerable']['route']));
        self::assertSame('unscoped read of owned Ticket collection', $vuln->reasons['idor'] ?? null);
        $safe = (string) $case['safe']['route'];
        self::assertArrayNotHasKey($safe, $selected, 'safe selected: '.(isset($selected[$safe]) ? self::reasons($selected[$safe]) : ''));
    }

    public function testEveryExclusionHasAJustification(): void
    {
        foreach (BenchmarkCorpus::APPS as $app) {
            foreach ([false, true] as $deep) {
                [, $exclusions] = self::selected($app, $deep);
                self::assertNotSame([], $exclusions);
                foreach ($exclusions as $exclusion) {
                    if ($exclusion->reason === CandidateSelector::NO_TRIGGER || str_starts_with($exclusion->reason, CandidateSelector::NO_TRIGGER_PREFIX)) {
                        continue;
                    }
                    self::assertNotSame('', trim($exclusion->checkSource), sprintf('%s %s %s: %s', $app, $exclusion->routeKey, $exclusion->category->value ?? '*', $exclusion->reason));
                }
            }
        }
    }

    public function testDeepSelectsAtLeastAsMuch(): void
    {
        foreach (BenchmarkCorpus::APPS as $app) {
            $normal = self::selected($app)[0];
            $deep = self::selected($app, true)[0];
            foreach ($normal as $key => $candidate) {
                self::assertArrayHasKey($key, $deep);
                foreach ($candidate->categories as $category) {
                    self::assertContains($category, $deep[$key]->categories, $key);
                }
            }
        }
    }

    public function testDeepReasonsKeepTheNormalDetail(): void
    {
        foreach (BenchmarkCorpus::APPS as $app) {
            $deep = self::selected($app, true)[0];
            foreach (self::selected($app)[0] as $key => $candidate) {
                foreach ($candidate->reasons as $category => $reason) {
                    self::assertSame(self::deepPrefixed($category, $reason), $deep[$key]->reasons[$category] ?? null, $app.' '.$key.' '.$category);
                }
            }
        }
    }

    /** @return array{0: array<string, Candidate>, 1: list<Exclusion>} */
    private static function selected(string $app, bool $deep = false): array
    {
        $cacheKey = $app.($deep ? ':deep' : '');
        if (! isset(self::$runs[$cacheKey])) {
            $selector = BenchmarkMaps::selector($app);
            [$candidates] = $selector->select(BenchmarkMaps::build($app), $deep);
            $byKey = [];
            foreach ($candidates as $candidate) {
                foreach ($candidate->route->keys() as $key) {
                    $byKey[$key] = $candidate;
                }
            }
            self::$runs[$cacheKey] = [$byKey, $selector->exclusions()];
        }

        return self::$runs[$cacheKey];
    }

    private static function reasons(Candidate $candidate): string
    {
        $out = [];
        foreach ($candidate->reasons as $category => $reason) {
            $out[] = $category.': '.$reason;
        }

        return implode('; ', $out);
    }

    private static function excluded(string $app, string $key): string
    {
        $out = [];
        foreach (self::selected($app)[1] as $e) {
            if ($e->routeKey === $key) {
                $out[] = ($e->category->value ?? '*').': '.$e->reason.' ['.$e->checkSource.']';
            }
        }

        return $out === [] ? 'none' : implode('; ', $out);
    }

    // --deep relabels only the categories it stops excluding; the normal detail follows the prefix.
    private static function deepPrefixed(string $category, string $reason): string
    {
        return in_array($category, [Category::Idor->value, Category::MissingAuthorization->value], true) ? '--deep: '.$reason : $reason;
    }
}
