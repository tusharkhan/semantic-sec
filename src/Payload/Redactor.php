<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Payload;

/**
 * Scrubs secret-looking literals from payload text (code and context) before it is written or sent.
 *
 * Passes: PEM bodies, known token formats anywhere, URL passwords anywhere, unquoted KEY=value
 * lines, then a literal scanner (single, double, heredoc, nowdoc) applying the entropy rule.
 * Only content is replaced (with `<redacted>`); quotes and markers stay, so line count is stable.
 * Quoted strings that do not close on their own line are not treated as literals.
 *
 * Entropy rule: a literal's content is redacted when ALL hold:
 *  - length >= 20 and no whitespace;
 *  - Shannon entropy (bits per byte) > 4.0;
 *  - NOT excluded by any of:
 *    - contains `\` (class name);
 *    - contains `/` and every non-empty `/` segment has entropy <= 4.0 (path);
 *    - starts with `scheme://` (URL; passwords are handled separately);
 *    - starts with `/` or contains `{` (route URI);
 *    - `name:args` with name `[A-Za-z_][\w.-]*` (not `base64`) and args of `,`/`|`/`:`-separated
 *      tokens over `[A-Za-z0-9_.*-]`, each <= 32 chars with entropy <= 4.0 (middleware);
 *    - only `[a-z0-9._-]` and entropy <= 4.5 (config key, slug).
 */
final class Redactor
{
    private const MARK = '<redacted>';

    private const OPEN = '~\'|"|<<<[ \t]*(["\']?)([A-Za-z_][A-Za-z0-9_]*)\1\r?\n~';

    private const TAG = '~^(L\d+\| )?~';

    private const TOKENS = [
        '~(?<![A-Z0-9])AKIA[0-9A-Z]{16}~',
        '~(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{20,}~',
        '~(?<![A-Za-z0-9])(?:sk_live_|sk_test_|pk_live_|rk_live_)[A-Za-z0-9]{16,}~',
        '~(?<![A-Za-z0-9])(?:ghp_|gho_)[A-Za-z0-9]{20,}~',
        '~(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{20,}~',
        '~(?<![A-Za-z0-9])xox[abpr]-[A-Za-z0-9-]+~',
        '~(?<![A-Za-z0-9_-])eyJ[\w-]+\.[\w-]+\.[\w-]+~',
    ];

    public function redact(string $text): string
    {
        $text = $this->redactPem($text);
        $text = $this->redactTokens($text);
        $text = $this->redactEnvLines($text);

        return $this->scanLiterals($text);
    }

    private function redactPem(string $text): string
    {
        $out = preg_replace_callback(
            '~(-----BEGIN [A-Z ]*PRIVATE KEY-----)(.*?)(-----END [A-Z ]*PRIVATE KEY-----|\z)~s',
            function (array $m): string {
                $lines = explode("\n", $m[2]);
                if (count($lines) === 1) {
                    return $m[1] . ($m[2] === '' ? '' : self::MARK) . $m[3];
                }
                foreach ($lines as $i => $line) {
                    $prefix = $i === 0 ? '' : $this->tagOf($line);
                    $rest = substr($line, strlen($prefix));
                    $lines[$i] = trim($rest) === '' ? $line : $prefix . self::MARK;
                }

                return $m[1] . implode("\n", $lines) . $m[3];
            },
            $text,
        );

        return $out ?? $text;
    }

    private function redactTokens(string $text): string
    {
        foreach (self::TOKENS as $pattern) {
            $text = preg_replace($pattern, self::MARK, $text) ?? $text;
        }

        // URL password: scheme://user:pass@host
        return preg_replace('~(\b[a-z][a-z0-9+.-]{1,15}://[^/\s:@\'"]+:)[^@\s/\'"]+@~i', '$1' . self::MARK . '@', $text) ?? $text;
    }

    private function redactEnvLines(string $text): string
    {
        $out = preg_replace_callback(
            '~^((?:L\d+\| )?[A-Z][A-Z0-9_]*=)([^\s\'"]+)(?=\r?$)~m',
            fn (array $m): string => $m[1] . $this->redactContent($m[2]),
            $text,
        );

        return $out ?? $text;
    }

    private function scanLiterals(string $text): string
    {
        $out = '';
        $pos = 0;

        while (preg_match(self::OPEN, $text, $m, PREG_OFFSET_CAPTURE, $pos) === 1) {
            $start = $m[0][1];
            $token = $m[0][0];
            $out .= substr($text, $pos, $start - $pos);

            if ($token === "'" || $token === '"') {
                $end = $this->findClose($text, $start + 1, $token);
                if ($end === null) {
                    $out .= $token;
                    $pos = $start + 1;

                    continue;
                }
                $content = substr($text, $start + 1, $end - $start - 1);
                $out .= $token . $this->redactContent($content) . $token;
                $pos = $end + 1;

                continue;
            }

            $bodyStart = $start + strlen($token);
            $id = preg_quote($m[2][0] ?? '', '~');
            $bodyEnd = strlen($text);
            if (preg_match('~^(?:L\d+\| )?[ \t]*' . $id . '(?![A-Za-z0-9_])~m', $text, $c, PREG_OFFSET_CAPTURE, $bodyStart) === 1) {
                $bodyEnd = $c[0][1];
            }
            $out .= $token . $this->redactHeredocBody(substr($text, $bodyStart, $bodyEnd - $bodyStart));
            $pos = $bodyEnd;
        }

        return $out . substr($text, $pos);
    }

    private function findClose(string $text, int $from, string $quote): ?int
    {
        $len = strlen($text);
        for ($i = $from; $i < $len; $i++) {
            $c = $text[$i];
            if ($c === '\\') {
                $i++;
            } elseif ($c === $quote) {
                return $i;
            } elseif ($c === "\n") {
                return null;
            }
        }

        return null;
    }

    private function redactHeredocBody(string $body): string
    {
        $lines = explode("\n", $body);
        foreach ($lines as $i => $line) {
            $prefix = $this->tagOf($line);
            $rest = substr($line, strlen($prefix));
            $trimmed = trim($rest);
            if ($trimmed === '') {
                continue;
            }
            $redacted = $this->redactContent($trimmed);
            if ($redacted !== $trimmed) {
                $indent = substr($rest, 0, strlen($rest) - strlen(ltrim($rest)));
                $lines[$i] = $prefix . $indent . $redacted . (str_ends_with($line, "\r") ? "\r" : '');
            }
        }

        return implode("\n", $lines);
    }

    private function tagOf(string $line): string
    {
        return preg_match(self::TAG, $line, $m) === 1 ? ($m[1] ?? '') : '';
    }

    private function redactContent(string $c): string
    {
        return $this->isSecret($c) ? self::MARK : $c;
    }

    private function isSecret(string $c): bool
    {
        if (strlen($c) < 20 || preg_match('~\s~', $c) === 1 || $this->entropy($c) <= 4.0) {
            return false;
        }

        return ! $this->isExcluded($c);
    }

    private function isExcluded(string $c): bool
    {
        if (str_contains($c, '\\')) {
            return true;
        }
        if (str_contains($c, '/') && $this->allSegmentsLow($c)) {
            return true;
        }
        if (preg_match('~^[A-Za-z][A-Za-z0-9+.-]*://~', $c) === 1) {
            return true;
        }
        if ($c[0] === '/' || str_contains($c, '{')) {
            return true;
        }
        if ($this->isMiddleware($c)) {
            return true;
        }

        return preg_match('~^[a-z0-9._-]+$~', $c) === 1 && $this->entropy($c) <= 4.5;
    }

    private function allSegmentsLow(string $c): bool
    {
        foreach (explode('/', $c) as $segment) {
            if ($segment !== '' && $this->entropy($segment) > 4.0) {
                return false;
            }
        }

        return true;
    }

    private function isMiddleware(string $c): bool
    {
        if (preg_match('~^([A-Za-z_][\w.-]*):([A-Za-z0-9_.,|:*-]+)$~', $c, $m) !== 1 || strtolower($m[1]) === 'base64') {
            return false;
        }
        $tokens = preg_split('~[,|:]~', $m[2]);
        foreach ($tokens === false ? [] : $tokens as $t) {
            if (strlen($t) > 32 || $this->entropy($t) > 4.0) {
                return false;
            }
        }

        return true;
    }

    private function entropy(string $s): float
    {
        $len = strlen($s);
        if ($len === 0) {
            return 0.0;
        }
        $h = 0.0;
        foreach (count_chars($s, 1) as $n) {
            $p = $n / $len;
            $h -= $p * log($p, 2);
        }

        return $h;
    }
}
