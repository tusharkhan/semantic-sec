<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Config;

use TusharKhan\SemanticSec\Analysis\Confidence;
use TusharKhan\SemanticSec\Analysis\Severity;

final readonly class Config
{
    public const DEFAULT_SENSITIVE_FIELDS = [
        'is_admin', 'role', 'role_id', 'admin', 'balance', 'credits', 'email_verified_at',
        'password', 'user_id', 'owner_id', 'team_id', 'tenant_id', 'status',
    ];

    /**
     * @param  list<string>  $paths
     * @param  list<string>  $exclude
     * @param  list<string>  $laravelRouteFiles
     * @param  list<string>  $sensitiveFields
     * @param  list<string>  $authHelpers
     * @param  list<CustomRuleset>  $rulesets
     */
    public function __construct(
        public string $projectRoot,
        public string $provider,
        public ?string $model,
        public ?string $apiKeyEnv,
        public ?string $baseUrl,
        public int $concurrency,
        public ?int $budgetTokens,
        public int $maxPayloadTokens,
        public int $maxDepth,
        public Severity $level,
        public Confidence $minConfidence,
        public array $paths,
        public array $exclude,
        public array $laravelRouteFiles,
        public array $sensitiveFields,
        public array $authHelpers,
        public array $rulesets,
    ) {
    }
}
