<?php

declare(strict_types=1);

namespace TusharKhan\SemanticSec\Payload;

/**
 * Scrubs secret-looking text from payloads (code and context) before it is written or sent.
 *
 * Passes: PEM bodies; vendor token formats and URL passwords anywhere; quoted values after
 * secret-ish key names; unquoted KEY=value lines; then a scanner that walks literals (single,
 * double, heredoc, nowdoc) and comments (`//`, `#`, block) and checks each token inside them.
 * Only content is replaced (with `<redacted>`), so the line count is unchanged. Quoted strings
 * must close on their own line; comments are skipped when pairing quotes.
 *
 * A token (whole literal, or a piece split on whitespace and `= : ? & , ; | " ' ( ) [ ] < > { }`)
 * is redacted when length >= 20, it has no whitespace, it is NOT excluded, and its Shannon
 * entropy (bits per byte) exceeds a threshold chosen by alphabet:
 *  - pure hex of length >= 32: 3.0
 *  - `[a-z0-9]` with letters and digits, length >= 24: 3.5
 *  - `[A-Za-z0-9+/=_-]` with lower and upper: 3.2 with a digit, 3.5 without
 *  - anything else: 4.0
 * Exclusions (checked first):
 *  - class-name shape (`A\B\C`, `A\B@m`, `A::m`) or UPPER_SNAKE constant;
 *  - strict camelCase or PascalCase words (every hump has a lowercase letter);
 *  - `scheme://` URLs (their query pieces are still checked as tokens);
 *  - path or route shape: contains `/` or `{`, no `+`, no trailing `=`, and every segment
 *    (after dropping `{param}`) is word-like: no hex run >= 16, entropy <= 4.0, and each
 *    `-_.`-part is lowercase/digits, UPPERCASE/digits, or strict camel/Pascal;
 *  - rule or middleware list: `|`-separated `name[:a,b,c]` with a word-like name (not `base64`)
 *    and word-like args, e.g. `required|exists:payment_methods,id`, `can:view,invoice`;
 *  - slug or config key: `[a-z0-9._-]` containing `.`, `_` or `-` with entropy <= 4.5, or
 *    lowercase letters only, shorter than 24, entropy <= 4.5.
 */
final class Redactor
{
    private const MARK = '<redacted>';

    private const OPEN = '~\'|"|//|#(?!\[)|/\*|<<<[ \t]*(["\']?)([A-Za-z_][A-Za-z0-9_]*)\1\r?\n~';

    private const TAG = '~^(L\d+\| )?~';

    private const KEYWORDS = 'password|passwd|secret|token|api[_-]?key|private[_-]?key|auth';

    private const RULE_WORDS = [
        'required', 'nullable', 'string', 'confirmed', 'sometimes', 'email', 'numeric', 'integer', 'boolean',
        'array', 'date', 'file', 'image', 'unique', 'exists', 'accepted', 'present', 'filled', 'password',
        'encrypted', 'datetime', 'hashed', 'json', 'object', 'collection', 'float', 'double', 'decimal',
        'timestamp', 'sanctum', 'passport', 'database', 'session', 'bearer', 'basic', 'digest', 'bcrypt', 'argon',
    ];

    private const TOKENS = [
        '~(?<![A-Z0-9])AKIA[0-9A-Z]{16}~',
        '~(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{20,}~',
        '~(?<![A-Za-z0-9])(?:sk_live_|sk_test_|pk_live_|rk_live_)[A-Za-z0-9]{16,}~',
        '~(?<![A-Za-z0-9])(?:whsec_)[A-Za-z0-9]{16,}~',
        '~(?<![A-Za-z0-9])gh[surop]_[A-Za-z0-9]{20,}~',
        '~(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{20,}~',
        '~(?<![A-Za-z0-9])glpat-[A-Za-z0-9_-]{20,}~',
        '~(?<![A-Za-z0-9])xox[abpr]-[A-Za-z0-9-]+~',
        '~(?<![A-Za-z0-9])AIza[0-9A-Za-z_-]{35}~',
        '~(?<![A-Za-z0-9])SG\.[\w-]{22}\.[\w-]{43}~',
        '~(?<![A-Za-z0-9])(?:SK|AC)[0-9a-f]{32}(?![A-Za-z0-9])~',
        '~(?<![A-Za-z0-9])key-[0-9a-f]{32}(?![A-Za-z0-9])~',
        '~(?<![A-Za-z0-9_-])eyJ[\w-]+\.[\w-]+\.[\w-]+~',
    ];

    public function redact(string $text): string
    {
        $text = $this->redactPem($text);
        $text = $this->redactTokens($text);
        $text = $this->redactQuotedKeyValues($text);
        $text = $this->redactEnvLines($text);

        return $this->scan($text);
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
        $text = preg_replace('~(hooks\.slack\.com/services/)[A-Za-z0-9/_-]+~', '$1' . self::MARK, $text) ?? $text;

        // URL password: scheme://user:pass@host (user may be empty)
        return preg_replace('~(\b[a-z][a-z0-9+.-]{1,15}://[^/\s:@\'"]*:)[^@\s\'"]+@~i', '$1' . self::MARK . '@', $text) ?? $text;
    }

    private function redactQuotedKeyValues(string $text): string
    {
        $key = '[\w-]*(?:' . self::KEYWORDS . ')(?-i:(?![a-z]))[\w-]*';
        $out = preg_replace_callback(
            '~(' . $key . '[\'"]?[ \t]*(?:=>|=(?!=)|:(?!:))[ \t]*)([\'"])([^\'"\s\r\n]{6,})\2~i',
            fn (array $m): string => $m[1] . $m[2] . ($this->keepKeyValue($m[3], $m[2] === '"') ? $m[3] : self::MARK) . $m[2],
            $text,
        );
        $out = $out ?? $text;
        $out = preg_replace_callback(
            '~(env\(\s*[\'"]' . $key . '[\'"]\s*,\s*)([\'"])([^\'"\s\r\n]{6,})\2~i',
            fn (array $m): string => $m[1] . $m[2] . ($this->keepKeyValue($m[3]) ? $m[3] : self::MARK) . $m[2],
            $out,
        );

        return $out ?? $text;
    }

    private function keepKeyValue(string $v, bool $interpolates = true): bool
    {
        if ($v === self::MARK || preg_match($interpolates ? '~[${%]~' : '~[{%]~', $v) === 1) {
            return true;
        }
        if (in_array(strtolower($v), self::RULE_WORDS, true) || $this->isRuleList($v) || $this->isClassName($v)) {
            return true;
        }

        return preg_match('~^[A-Za-z_][\w]*(?:\.[A-Za-z_]\w*)+$~', $v) === 1 && preg_match('~\d~', $v) !== 1;
    }

    private function redactEnvLines(string $text): string
    {
        $out = preg_replace_callback(
            '~^((?:L\d+\| )?[ \t]*(?:(?://|\#)[ \t]*)?(?:export[ \t]+)?)([A-Z][A-Z0-9_]*)([ \t]*=[ \t]*)([^\s\'"]+)(?=\r?$)~m',
            function (array $m): string {
                $v = $m[4];
                if ($v[0] === '<' || $v[0] === '$') {
                    return $m[0];
                }
                $secretKey = preg_match('~' . self::KEYWORDS . '~i', $m[2]) === 1 && strlen($v) >= 6;
                $redact = $secretKey ? ! $this->keepKeyValue($v) : $this->isSecret($v);

                return $m[1] . $m[2] . $m[3] . ($redact ? self::MARK : $v);
            },
            $text,
        );

        return $out ?? $text;
    }

    private function scan(string $text): string
    {
        $out = '';
        $pos = 0;
        $len = strlen($text);

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
                $out .= $token . $this->redactText($content) . $token;
                $pos = $end + 1;

                continue;
            }

            if ($token === '//' || $token === '#') {
                $nl = strpos($text, "\n", $start);
                $end = $nl === false ? $len : $nl;
                $out .= $token . $this->redactText(substr($text, $start + strlen($token), $end - $start - strlen($token)));
                $pos = $end;

                continue;
            }

            if ($token === '/*') {
                $close = strpos($text, '*/', $start + 2);
                $end = $close === false ? $len : $close;
                $out .= $token . $this->redactText(substr($text, $start + 2, $end - $start - 2));
                $pos = $end;

                continue;
            }

            $bodyStart = $start + strlen($token);
            $id = preg_quote($m[2][0] ?? '', '~');
            $bodyEnd = $len;
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
            $lines[$i] = $prefix . $this->redactText(substr($line, strlen($prefix)));
        }

        return implode("\n", $lines);
    }

    private function tagOf(string $line): string
    {
        return preg_match(self::TAG, $line, $m) === 1 ? ($m[1] ?? '') : '';
    }

    private function redactText(string $s): string
    {
        if (strlen($s) < 6) {
            return $s;
        }
        $key = '[\w-]*(?:' . self::KEYWORDS . ')(?-i:(?![a-z]))[\w-]*';
        $s = preg_replace_callback(
            '~(' . $key . '[\'"]?[ \t]*(?:=>|=(?!=)|:(?!:)(?=[ \t]))[ \t]*)([^\s\'",;&]{6,})~i',
            function (array $m): string {
                $v = $m[2];
                $ok = preg_match('~^[$%{<\[(]|[(>]~', $v) === 1 || preg_match('~[^A-Za-z]~', $v) !== 1 || $this->keepKeyValue($v);

                return $m[1] . ($ok ? $v : self::MARK);
            },
            $s,
        ) ?? $s;
        if (preg_match('~[\s"\'()\[\]<>{}]~', $s) !== 1 && $this->isSecret($s)) {
            return self::MARK;
        }

        return preg_replace_callback(
            '~[^\s=:?&,;|"\'()\[\]<>{}]{20,}~',
            fn (array $m): string => $this->isSecret($m[0]) ? self::MARK : $m[0],
            $s,
        ) ?? $s;
    }

    private function isSecret(string $c): bool
    {
        $c = rtrim($c, '.');
        if (strlen($c) < 20 || preg_match('~\s~', $c) === 1 || $this->isExcluded($c)) {
            return false;
        }

        return $this->entropy($c) > $this->threshold($c);
    }

    private function threshold(string $c): float
    {
        $len = strlen($c);
        if ($len >= 32 && preg_match('~^[0-9a-fA-F]+$~', $c) === 1) {
            return 3.0;
        }
        if ($len >= 24 && preg_match('~^[a-z0-9]+$~', $c) === 1 && preg_match('~\d~', $c) === 1 && preg_match('~[a-z]~', $c) === 1) {
            return 3.5;
        }
        if (preg_match('~^[A-Za-z0-9+/=_-]+$~', $c) === 1 && preg_match('~[a-z]~', $c) === 1 && preg_match('~[A-Z]~', $c) === 1) {
            return preg_match('~\d~', $c) === 1 ? 3.2 : 3.5;
        }

        return 4.0;
    }

    private function isExcluded(string $c): bool
    {
        if ($this->isClassName($c) || preg_match('~^[A-Z][A-Z0-9_]+$~', $c) === 1 || $this->isCamel($c)) {
            return true;
        }
        if (preg_match('~^(?:[A-Za-z][A-Za-z0-9+.-]*:)?//~', $c) === 1) {
            return true;
        }
        if ((str_contains($c, '/') || str_contains($c, '{')) && $this->isPathLike($c)) {
            return true;
        }
        if ($this->isRuleList($c)) {
            return true;
        }
        if (preg_match('~\\\\[dDwWsSbB./]|^/?\^~', $c) === 1) {
            return true;
        }
        if ($c[0] === '$' && preg_match('~^\$[A-Za-z_]\w*$~', $c) === 1 && ($this->isCamel(substr($c, 1)) || $this->isWordish(substr($c, 1)))) {
            return true;
        }
        if ($this->isWordJoined($c)) {
            return true;
        }
        $slug = preg_match('~^[a-z0-9._*-]+$~', $c) === 1;
        if ($slug && preg_match('~[._-]~', $c) === 1 && $this->entropy($c) <= 4.5) {
            return true;
        }

        return preg_match('~^[a-z]+$~', $c) === 1 && strlen($c) < 24 && $this->entropy($c) <= 4.5;
    }

    private function isClassName(string $c): bool
    {
        if (preg_match('~^\\\\?[A-Za-z_]\w*(?:\\\\{1,2}[A-Za-z_]\w*)+(?:@\w+|::\w+)?$~', $c) !== 1 && preg_match('~^[A-Za-z_]\w*::\w+$~', $c) !== 1) {
            return false;
        }
        foreach (preg_split('~[\\\\:@]+~', $c) ?: [] as $part) {
            if (! $this->isWordish($part)) {
                return false;
            }
        }

        return true;
    }

    private function isWordJoined(string $c): bool
    {
        if (preg_match('~^[A-Za-z0-9]+(?:[-_.][A-Za-z0-9]+)+$~', $c) !== 1) {
            return false;
        }
        foreach (preg_split('~[-_.]+~', $c) ?: [] as $part) {
            $word = preg_match('~^\d+$~', $part) === 1
                || preg_match('~^[A-Z]+\d*$~', $part) === 1
                || (preg_match('~^[A-Za-z][a-z]*\d*$~', $part) === 1 && (strlen($part) <= 2 || preg_match('~[aeiouy]~', $part) === 1) && strlen($part) <= 14)
                || $this->isCamel($part);
            if (! $word) {
                return false;
            }
        }

        return true;
    }

    private function isCamel(string $c): bool
    {
        $hump = '(?:[A-Z][a-z]+[0-9]*|[A-Z][0-9]+|[A-Z]{2,}(?=[A-Z][a-z]|$))';

        if (preg_match('~^[a-z]+[0-9]*' . $hump . '+$~', $c) !== 1 && preg_match('~^' . $hump . '+$~', $c) !== 1) {
            return false;
        }
        // every lowercase word needs a vowel (or be a known acronym) so random mixed-case strings do not pass
        preg_match_all('~[A-Z]?[a-z]+~', $c, $words);
        foreach ($words[0] as $w) {
            $w = strtolower($w);
            if (preg_match('~[aeiouy]~', $w) !== 1 && ! in_array($w, ['pdf', 'url', 'sql', 'csv', 'xml', 'dto', 'php', 'api', 'db', 'ip', 'ui', 'qr', 'js', 'css', 'html', 'http', 'ssl', 'tls', 'jwt', 'sms', 'cdn', 'crm', 'hr', 'ssn', 'tz'], true)) {
                return false;
            }
        }

        return true;
    }

    private function isPathLike(string $c): bool
    {
        if (str_contains($c, '+') || str_ends_with($c, '=')) {
            return false;
        }
        $stripped = preg_replace('~\{[^}/]*\}~', '', $c) ?? $c;
        foreach (explode('/', $stripped) as $segment) {
            if (! $this->isWordish($segment)) {
                return false;
            }
        }

        return true;
    }

    private function isWordish(string $segment): bool
    {
        if ($segment === '') {
            return true;
        }
        if (preg_match('~^[\w.@\~*?:=#%-]+$~', $segment) !== 1 || $this->entropy($segment) > 4.0) {
            return false;
        }
        foreach (preg_split('~[^A-Za-z0-9]+~', $segment) ?: [] as $part) {
            if ($part === '' || preg_match('~^[a-z0-9]+$|^[A-Z0-9]+$~', $part) === 1) {
                if (strlen($part) >= 16 && preg_match('~^[0-9a-fA-F]+$~', $part) === 1 && preg_match('~\d~', $part) === 1) {
                    return false;
                }

                continue;
            }
            if (! $this->isCamel($part)) {
                return false;
            }
        }

        return true;
    }

    private function isRuleList(string $c): bool
    {
        if (! str_contains($c, '|') && ! str_contains($c, ':')) {
            return false;
        }
        foreach (explode('|', $c) as $rule) {
            if (preg_match('~^([A-Za-z_][\w.]*)(?::(.*))?$~', $rule, $m) !== 1 || strtolower($m[1]) === 'base64' || ! $this->isWordish($m[1])) {
                return false;
            }
            foreach (isset($m[2]) ? explode(',', $m[2]) : [] as $arg) {
                if (preg_match('~^[\w.*=:\\\\/@$-]*$~', $arg) !== 1 || ! $this->isWordish(str_replace(['\\', '/', '$'], '_', $arg))) {
                    return false;
                }
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
