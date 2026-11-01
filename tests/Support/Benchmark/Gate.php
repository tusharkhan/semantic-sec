<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support\Benchmark;

/**
 * SPEC §15 release gate, plus a precision guard on safe-code findings no case accounts for; pass is null when a criterion has nothing to measure.
 *
 * @phpstan-type Criterion array{criterion: string, label: string, threshold: string, value: float|int|null, numerator: int, denominator: int, pass: bool|null}
 */
final class Gate
{
    public const MIN_FOUND = 0.70;

    public const MAX_FLAGGED = 0.10;

    /** @return list<Criterion> */
    public static function evaluate(Counts $c): array
    {
        $found = $c->foundRate();
        $flagged = $c->flaggedRate();
        $map = $c->mapRate();

        return [
            ['criterion' => 'found', 'label' => 'Vulnerable variants found at the right symbol', 'threshold' => '≥ 70%', 'value' => $found, 'numerator' => $c->found, 'denominator' => $c->cases, 'pass' => $found === null ? null : $found >= self::MIN_FOUND],
            ['criterion' => 'flagged', 'label' => 'Safe variants flagged', 'threshold' => '≤ 10%', 'value' => $flagged, 'numerator' => $c->flagged, 'denominator' => $c->cases, 'pass' => $flagged === null ? null : $flagged <= self::MAX_FLAGGED],
            ['criterion' => 'unattributed', 'label' => 'Findings in safe code that no case accounts for', 'threshold' => '0', 'value' => $c->unattributed, 'numerator' => $c->unattributed, 'denominator' => $c->cases, 'pass' => self::zero($c->unattributed, $c->cases)],
            ['criterion' => 'public', 'label' => 'Findings on public-by-design routes', 'threshold' => '0', 'value' => $c->publicViolations, 'numerator' => $c->publicViolations, 'denominator' => $c->publicRoutes, 'pass' => self::zero($c->publicViolations, $c->publicRoutes)],
            ['criterion' => 'map', 'label' => 'Expected authorization checks in the map', 'threshold' => '100%', 'value' => $map, 'numerator' => $c->mapVariants - $c->mapMismatches, 'denominator' => $c->mapVariants, 'pass' => $map === null ? null : $c->mapMismatches === 0],
        ];
    }

    // False on any failure; null when the slice has no cases (n/a never counts as a pass); true otherwise.
    /** @param list<Criterion> $criteria */
    public static function verdict(array $criteria): ?bool
    {
        $measured = false;
        foreach ($criteria as $criterion) {
            if ($criterion['pass'] === false) {
                return false;
            }
            $measured = $measured || ($criterion['criterion'] === 'found' && $criterion['pass'] !== null);
        }

        return $measured ? true : null;
    }

    // Any hit fails; zero hits with nothing in scope is n/a.
    private static function zero(int $hits, int $scope): ?bool
    {
        return $hits > 0 ? false : ($scope === 0 ? null : true);
    }
}
