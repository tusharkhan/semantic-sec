<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Framework;

final class FrameworkDetector
{
    private const PACKAGE = 'laravel/framework';

    public function detect(string $projectRoot, ?string $forced = null): DetectedFramework
    {
        if ($forced !== null && strtolower($forced) !== 'laravel') {
            throw new FrameworkNotDetected(sprintf('Unsupported framework "%s"; v1 supports: laravel', $forced));
        }

        $major = $this->lockMajor($projectRoot.'/composer.lock') ?? $this->constraintMajor($projectRoot.'/composer.json');

        if ($forced !== null) {
            return new DetectedFramework('laravel', $major);
        }

        if ($major === null && ! $this->declaresLaravel($projectRoot)) {
            throw new FrameworkNotDetected(sprintf(
                'No supported framework detected in %s. Use --framework=laravel to force it.',
                $projectRoot,
            ));
        }

        return new DetectedFramework('laravel', $major);
    }

    private function declaresLaravel(string $root): bool
    {
        foreach ($this->read($root.'/composer.lock', ['packages', 'packages-dev']) as $package) {
            if (is_array($package) && ($package['name'] ?? null) === self::PACKAGE) {
                return true;
            }
        }

        return $this->constraints($root.'/composer.json') !== [];
    }

    private function lockMajor(string $file): ?int
    {
        foreach ($this->read($file, ['packages', 'packages-dev']) as $package) {
            if (! is_array($package) || ($package['name'] ?? null) !== self::PACKAGE) {
                continue;
            }
            $version = $package['version'] ?? null;
            if (is_string($version) && preg_match('/^v?(\d+)\./', $version, $m) === 1) {
                return (int) $m[1];
            }
        }

        return null;
    }

    private function constraintMajor(string $file): ?int
    {
        $majors = [];
        foreach ($this->constraints($file) as $constraint) {
            // Version-token starts only; digits after a dot are minors.
            if (preg_match_all('/(?<![\d.])(\d+)/', $constraint, $m) > 0) {
                array_push($majors, ...array_map('intval', $m[1]));
            }
        }

        return $majors === [] ? null : max($majors);
    }

    /** @return list<string> */
    private function constraints(string $file): array
    {
        $found = [];
        foreach ($this->read($file, ['require', 'require-dev']) as $name => $constraint) {
            if ($name === self::PACKAGE && is_string($constraint)) {
                $found[] = $constraint;
            }
        }

        return $found;
    }

    /**
     * @param  list<string>  $sections
     * @return array<array-key, mixed>
     */
    private function read(string $file, array $sections): array
    {
        $raw = is_file($file) ? file_get_contents($file) : false;
        if ($raw === false) {
            return [];
        }
        $data = json_decode($raw, true);
        if (! is_array($data)) {
            return [];
        }

        $merged = [];
        foreach ($sections as $section) {
            $part = $data[$section] ?? null;
            if (is_array($part)) {
                $merged = array_merge($merged, $part);
            }
        }

        return $merged;
    }
}
