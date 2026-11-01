<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support\Benchmark;

/**
 * SPEC §15 release gate; pass is null when a criterion has nothing to measure.
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
            ['criterion' => 'public', 'label' => 'Findings on public-by-design routes', 'threshold' => '0', 'value' => $c->publicViolations, 'numerator' => $c->publicViolations, 'denominator' => $c->publicRoutes, 'pass' => $c->publicViolations === 0],
            ['criterion' => 'map', 'label' => 'Expected authorization checks in the map', 'threshold' => '100%', 'value' => $map, 'numerator' => $c->mapVariants - $c->mapMismatches, 'denominator' => $c->mapVariants, 'pass' => $map === null ? null : $c->mapMismatches === 0],
        ];
    }

    /** @param list<Criterion> $criteria */
    public static function passes(array $criteria): bool
    {
        foreach ($criteria as $criterion) {
            if ($criterion['pass'] === false) {
                return false;
            }
        }

        return true;
    }
}
