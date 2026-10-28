<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Analysis;

enum Category: string
{
    case Idor = 'idor';
    case MissingAuthorization = 'missing_authorization';
    case MassAssignment = 'mass_assignment';
    case InsecureDeserialization = 'insecure_deserialization';
    case WorkflowBypass = 'workflow_bypass';

    public function cweId(): string
    {
        return match ($this) {
            self::Idor => 'CWE-639',
            self::MissingAuthorization => 'CWE-862',
            self::MassAssignment => 'CWE-915',
            self::InsecureDeserialization => 'CWE-502',
            self::WorkflowBypass => 'CWE-841',
        };
    }

    public function label(): string
    {
        return match ($this) {
            self::Idor => 'Insecure Direct Object Reference (IDOR)',
            self::MissingAuthorization => 'Missing Authorization',
            self::MassAssignment => 'Mass Assignment',
            self::InsecureDeserialization => 'Insecure Deserialization',
            self::WorkflowBypass => 'Workflow Bypass',
        };
    }

    // Matches the enum value or its CWE id, case-insensitively.
    public static function fromToken(string $token): ?self
    {
        $token = strtolower(trim($token));

        foreach (self::cases() as $case) {
            if ($token === $case->value || $token === strtolower($case->cweId())) {
                return $case;
            }
        }

        return null;
    }
}
