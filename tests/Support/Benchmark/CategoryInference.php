<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Tests\Support\Benchmark;

use TusharKhan\SemanticSec\Analysis\Category;

/** Maps a competitor finding onto our five categories; the first matching rule wins and is returned with it. */
final class CategoryInference
{
    public const ACCESS_CONTROL = 'idor|missing_authorization';

    private const CWE = [
        '639' => 'idor',
        '566' => 'idor',
        '862' => 'missing_authorization',
        '915' => 'mass_assignment',
        '502' => 'insecure_deserialization',
        '841' => 'workflow_bypass',
        '284' => self::ACCESS_CONTROL,
        '285' => self::ACCESS_CONTROL,
        '863' => self::ACCESS_CONTROL,
    ];

    // Checked in this order; specific flaw types before the ownership and authorization wording they often contain.
    private const KEYWORDS = [
        'mass_assignment' => '/mass[\s_-]*assign|over-?posting|\$fillable|\$guarded|force-?fill|request(\(\))?->all\(\)|\bfill\(|arbitrary (fields|attributes|columns)/i',
        'insecure_deserialization' => '/deseriali[sz]|unseriali[sz]e|object injection|gadget chain/i',
        'workflow_bypass' => '/workflow|state[\s_-]*(machine|transition)|status transition|business[\s_-]*logic|skip\w*\s+(the\s+)?(\w+\s+)?(approval|review|step|state|check)|after it (shipped|was|has)|out of order|race condition/i',
        'idor' => '/\bidor\b|insecure direct object|object[\s_-]*level|\bbola\b|another (user|tenant|team|account|customer|merchant|organi[sz]ation)|other (users|tenants|teams|accounts|customers)|belong\w* to (another|other|a different)|ownership|owned by|not (scoped|owned)|enumerat\w* (ids?|records)|horizontal privilege|cross-?(tenant|team|account|user)/i',
        'missing_authorization' => '/missing[\s_-]*authori[sz]ation|no authori[sz]ation|without (any )?authori[sz]ation|privilege[\s_-]*escalation|vertical privilege|role check|non-?(admin|merchant|manager|owner)\b|admin[\s_-]*only|unauthenticated access/i',
    ];

    private const GENERIC = '/authori[sz]|access[\s_-]*control|permission|privilege|forbidden|broken access/i';

    /**
     * @param array<mixed> $finding
     *
     * @return array{0: string, 1: string} the category (ours, alternatives joined by |, or Scorer::ANY_CATEGORY) and the rule that decided it
     */
    public static function infer(array $finding): array
    {
        $category = self::text($finding, 'category');
        $primary = $category.' '.self::text($finding, 'description');
        $all = $primary.' '.self::text($finding, 'exploit_scenario').' '.self::text($finding, 'recommendation').' '.self::text($finding, 'cwe');
        if (preg_match('/\bCWE[\s_-]*(\d+)\b/i', $all, $m) === 1 && isset(self::CWE[$m[1]])) {
            return [self::CWE[$m[1]], 'cwe'];
        }
        $token = Category::fromToken((string) preg_replace('/[\s-]+/', '_', $category));
        if ($category !== '' && $token !== null) {
            return [$token->value, 'category-field'];
        }
        foreach (self::KEYWORDS as $ours => $pattern) {
            if (preg_match($pattern, $primary) === 1) {
                return [$ours, 'keyword:'.$ours];
            }
        }
        $scenario = self::text($finding, 'exploit_scenario');
        foreach (self::KEYWORDS as $ours => $pattern) {
            if (preg_match($pattern, $scenario) === 1) {
                return [$ours, 'exploit:'.$ours];
            }
        }
        if (preg_match(self::GENERIC, $primary.' '.$scenario) === 1) {
            return [self::ACCESS_CONTROL, 'access-control'];
        }

        return [Scorer::ANY_CATEGORY, 'none'];
    }

    /** @return list<string> every rule id infer() can return, in its order */
    public static function rules(): array
    {
        return ['cwe', 'category-field', ...array_map(static fn (string $c): string => 'keyword:'.$c, array_keys(self::KEYWORDS)), ...array_map(static fn (string $c): string => 'exploit:'.$c, array_keys(self::KEYWORDS)), 'access-control', 'none'];
    }

    /** @param array<mixed> $finding */
    private static function text(array $finding, string $key): string
    {
        return is_scalar($finding[$key] ?? null) ? (string) $finding[$key] : '';
    }
}
