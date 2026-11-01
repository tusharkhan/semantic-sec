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
 *  - pure hex of length >= 32: 2.8
 *  - `[a-z0-9]` with letters and digits, length >= 24: 3.3
 *  - uppercase letters only, length >= 24: 3.6
 *  - `[A-Za-z0-9+/=_-]` with lower and upper: 3.2 with a digit, 3.5 without
 *  - uppercase/digits with a letter and a digit, length >= 20: 3.5
 *  - three or more of lower, upper, digit, symbol: 3.3
 *  - anything else: 4.0
 * Exclusions (checked first):
 *  - class-name shape (`A\B\C`, `A\B@m`, `A::m`; a part may hold one short vowel-less word like `Ghl`) or UPPER_SNAKE constant;
 *  - dotted or wildcard key whose segments are `*`, digits or word-like (`numbersInfo.*.friendly_name`);
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

    private const NEVER_KEYS = ['name', 'column', 'table', 'endpoint', 'driver', 'guard', 'provider', 'header', 'field', 'type', 'model', 'route', 'url'];

    private const PASSWORD_KEYS = ['password', 'passwd', 'pass', 'pwd', 'secret', 'secrets', 'credentials', 'passphrase', 'privatekey', 'apikey'];

    private const KEY_PREFIXES = ['api', 'private', 'secret', 'encryption', 'signing', 'app', 'access', 'client', 'master', 'license'];

    private const KNOWN_RULES = [
        'required', 'nullable', 'sometimes', 'string', 'integer', 'numeric', 'boolean', 'array', 'email', 'confirmed',
        'min', 'max', 'size', 'between', 'in', 'not_in', 'unique', 'exists', 'date', 'date_format', 'after', 'before',
        'after_or_equal', 'before_or_equal', 'same', 'different', 'regex', 'alpha', 'alpha_num', 'alpha_dash', 'file',
        'image', 'mimes', 'mimetypes', 'dimensions', 'url', 'uuid', 'json', 'accepted', 'present', 'filled', 'digits',
        'digits_between', 'ip', 'bail', 'current_password', 'password', 'hashed', 'encrypted', 'datetime', 'timestamp',
        'object', 'collection', 'float', 'double', 'decimal', 'int', 'bool', 'real', 'date', 'immutable_date',
        'immutable_datetime', 'prohibited', 'required_if', 'required_with', 'required_without', 'gt', 'gte', 'lt', 'lte',
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
        $text = $this->redactLineKeyValues($text);

        return $this->scan($text);
    }

    // Known token formats only, with no entropy guessing; for our own paths and labels.
    public function redactKnownTokens(string $text): string
    {
        return $this->redactTokens($this->redactPem($text));
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
        // Telegram bot token `bot<id>:<secret>`: only the secret, never the path after it.
        $text = preg_replace('~(?<![A-Za-z0-9])((?:bot)?\d{6,12}:)[A-Za-z0-9_-]{30,}~', '$1' . self::MARK, $text) ?? $text;

        // URL password: scheme://user:pass@host (user may be empty)
        return preg_replace('~(\b[a-z][a-z0-9+.-]{1,15}://[^/\s:@\'"]*:)[^@\s\'"]+@~i', '$1' . self::MARK . '@', $text) ?? $text;
    }

    private function redactQuotedKeyValues(string $text): string
    {
        $out = preg_replace_callback(
            '~(?<![\w.-])([\'"]?)([A-Za-z_][\w.-]*)([\'"]?)([ \t]*(?:=>|=(?!=)|:(?!:))[ \t]*)([\'"])((?:\\\\.|(?!\5)[^\\\\\r\n])+)\5~',
            function (array $m): string {
                if ($m[1] !== $m[3] || ($m[3] === '' && str_contains($m[4], ':') && ! preg_match('~:[ \t]~', $m[4]))) {
                    return $m[0];
                }

                return $m[1] . $m[2] . $m[3] . $m[4] . $m[5] . ($this->redactKeyed($m[2], $m[6], $m[5] === '"') ? self::MARK : $m[6]) . $m[5];
            },
            $text,
        );
        $out = $out ?? $text;
        $out = preg_replace_callback(
            '~(\b(?:env|getenv|config)\(\s*([\'"])([\w.-]+)\2\s*,\s*)([\'"])((?:\\\\.|(?!\4)[^\\\\\r\n])+)\4~',
            fn (array $m): string => $m[1] . $m[4] . ($this->redactKeyed($m[3], $m[5], $m[4] === '"') ? self::MARK : $m[5]) . $m[4],
            $out,
        );

        return $out ?? $text;
    }

    /** Unquoted `key=value` / `key: value` lines (.env, YAML), with `export`, comment marks and any key case. */
    private function redactLineKeyValues(string $text): string
    {
        $out = preg_replace_callback(
            '~^((?:L\d+\| )?[ \t]*(?:(?://|\#)[ \t]*)?(?:export[ \t]+)?)([A-Za-z_][A-Za-z0-9_.-]*)([ \t]*=[ \t]*|:[ \t]+)([^\s\'"]+)(?=\r?$)~m',
            function (array $m): string {
                $v = $m[4];
                if (preg_match('~[;{(]$~', $v) === 1 || $v[0] === '<' || str_starts_with($v, '${') || str_starts_with($v, '$(')) {
                    return $m[0];
                }
                $class = $this->keyClass($m[2]);
                $redact = $class === 0 ? $this->isSecret($v) : $this->redactKeyed($m[2], $v, false);

                return $m[1] . $m[2] . $m[3] . ($redact ? self::MARK : $v);
            },
            $text,
        );

        return $out ?? $text;
    }

    /** 1 = password class, 2 = token class, -1 = never secret by name, 0 = no opinion; decided by the last key segment. */
    private function keyClass(string $key): int
    {
        $parts = preg_split('~[_.\-]+~', strtolower((string) preg_replace('~([a-z0-9])([A-Z])~', '$1_$2', $key))) ?: [];
        $parts = array_values(array_filter($parts, fn (string $p): bool => $p !== ''));
        $last = $parts[count($parts) - 1] ?? '';
        $prev = $parts[count($parts) - 2] ?? '';
        if (in_array($last, self::NEVER_KEYS, true)) {
            return -1;
        }
        if (in_array($last, self::PASSWORD_KEYS, true)) {
            return 1;
        }
        if ($last === 'key') {
            return in_array($prev, self::KEY_PREFIXES, true) ? 1 : 2;
        }

        return in_array($last, ['token', 'auth'], true) ? 2 : 0;
    }

    private function redactKeyed(string $key, string $v, bool $interpolates): bool
    {
        $class = $this->keyClass($key);
        if ($class <= 0 || $v === '' || $v === self::MARK) {
            return false;
        }
        if ($interpolates && preg_match('~\$\w|\{\$~', $v) === 1) {
            return false;
        }
        if ($this->isKnownRuleList($v) || $this->isClassName($v)) {
            return false;
        }
        if ($class === 1) {
            return true;
        }
        $slug = preg_match('~^[a-z][a-z0-9]*(?:[_-][a-z0-9]+)*:?$~', $v) === 1 && $this->entropy($v) <= 4.5;

        return ! $slug && ! (str_contains($v, '/') && $this->isPathLike($v));
    }

    private function isKnownRuleList(string $v): bool
    {
        foreach (explode('|', $v) as $rule) {
            if (preg_match('~^([a-z_]+)(?::.*)?$~i', $rule, $m) !== 1 || ! in_array(strtolower($m[1]), self::KNOWN_RULES, true)) {
                return false;
            }
        }

        return true;
    }

    private function scan(string $text): string
    {
        $out = '';
        $pos = 0;
        $len = strlen($text);

        while (preg_match(self::OPEN, $text, $m, PREG_OFFSET_CAPTURE, $pos) === 1) {
            $start = $m[0][1];
            $token = $m[0][0];
            $out .= $this->redactCode(substr($text, $pos, $start - $pos));

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

        return $out . $this->redactCode(substr($text, $pos));
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

    /** Text outside literals and comments (also context prose): token check only. */
    private function redactCode(string $s): string
    {
        return preg_replace_callback(
            '~[A-Za-z0-9+/=_-]{20,}~',
            fn (array $m): string => preg_match('~\d~', $m[0]) === 1 && preg_match('~[A-Za-z]~', $m[0]) === 1 && $this->isSecret($m[0]) ? self::MARK : $m[0],
            $s,
        ) ?? $s;
    }

    private function redactText(string $s): string
    {
        if (strlen($s) < 3) {
            return $s;
        }
        $s = preg_replace_callback(
            '~(?<![\w.-])([\'"]?)([A-Za-z_][\w.-]*)([\'"]?)([ \t]*(?:=>|=(?!=)|:(?!:)(?=[ \t]))[ \t]*)([^\s\'",;&]+)~',
            function (array $m): string {
                $v = $m[5];
                if ($m[1] !== $m[3] || preg_match('~^[$%{<\[(]|[(>]~', $v) === 1 || preg_match('~\w~', $v) !== 1) {
                    return $m[0];
                }

                return $m[1] . $m[2] . $m[3] . $m[4] . ($this->redactKeyed($m[2], $v, false) ? self::MARK : $v);
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
        $c = rtrim($c, '.\\');
        if (strlen($c) < 20 || preg_match('~\s~', $c) === 1 || $this->isExcluded($c)) {
            return false;
        }

        return $this->entropy($c) > $this->threshold($c);
    }

    private function threshold(string $c): float
    {
        $len = strlen($c);
        if ($len >= 32 && preg_match('~^[0-9a-fA-F]+$~', $c) === 1) {
            return 2.8;
        }
        if ($len >= 24 && preg_match('~^[A-Z]+$~', $c) === 1) {
            return 3.6;
        }
        if ($len >= 20 && preg_match('~^[A-Z0-9]+$~', $c) === 1 && preg_match('~\d~', $c) === 1 && preg_match('~[A-Z]~', $c) === 1) {
            return 3.5;
        }
        if ($len >= 24 && preg_match('~^[a-z0-9]+$~', $c) === 1 && preg_match('~\d~', $c) === 1 && preg_match('~[a-z]~', $c) === 1) {
            return 3.3;
        }
        if (preg_match('~^[A-Za-z0-9+/=_-]+$~', $c) === 1 && preg_match('~[a-z]~', $c) === 1 && preg_match('~[A-Z]~', $c) === 1) {
            return preg_match('~\d~', $c) === 1 ? 3.2 : 3.5;
        }

        $classes = (int) (preg_match('~[a-z]~', $c) === 1) + (int) (preg_match('~[A-Z]~', $c) === 1) + (int) (preg_match('~\d~', $c) === 1) + (int) (preg_match('~[^A-Za-z0-9]~', $c) === 1);

        return $classes >= 3 ? 3.3 : 4.0;
    }

    private function isExcluded(string $c): bool
    {
        if ($this->isClassName($c) || $this->isUpperSnake($c) || $this->isCamelIdentifier($c) || $this->isDottedKey($c)) {
            return true;
        }
        if ($this->isUrl($c)) {
            return true;
        }
        if ((str_contains($c, '/') || str_contains($c, '{')) && $this->isPathLike($c)) {
            return true;
        }
        if (str_contains($c, ',') && $this->isWordishList($c)) {
            return true;
        }
        if ($this->isRuleList($c)) {
            return true;
        }
        if (preg_match('~(?<!\\\\)\\\\[dDwWsSbB./]|^/?\^.*\$/?$~', $c) === 1) {
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
            if ($part !== '' && ! $this->isCamel($part, 1) && preg_match('~^(?:[a-z0-9_]+|[A-Z0-9_]+)$~', $part) !== 1) {
                return false;
            }
        }

        return true;
    }

    // A validation or config key: `.`-separated segments that are each `*`, digits, or word-like.
    private function isDottedKey(string $c): bool
    {
        if (preg_match('~^[A-Za-z_][\w-]*(?:\.(?:\*|\d+|[A-Za-z_][\w-]*))+$~', $c) !== 1) {
            return false;
        }
        foreach (explode('.', $c) as $segment) {
            if ($segment !== '*' && ! ctype_digit($segment) && ! $this->isWordish($segment)) {
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

    private function isUpperSnake(string $c): bool
    {
        if (preg_match('~^[A-Z]+[0-9]{0,2}(?:_[A-Z]+[0-9]{0,2})+$~', $c) !== 1) {
            return false;
        }
        foreach (explode('_', $c) as $part) {
            if (strlen($part) > 12) {
                return false;
            }
        }

        return $this->entropy($c) <= 4.2;
    }

    private function isCamelIdentifier(string $c): bool
    {
        return preg_match('~\d~', (string) preg_replace('~[A-Z]\d+~', '', $c)) !== 1 && $this->isCamel($c) && $this->entropy($c) <= 4.5;
    }

    // $vowelless: how many short (<= 4 letters) vowel-less words may pass, e.g. `Ghl` or `Cfg` in a class name.
    private function isCamel(string $c, int $vowelless = 0): bool
    {
        if (preg_match('~[a-z]~', $c) !== 1) {
            return false;
        }
        $hump = '(?:[A-Z][a-z]+[0-9]*|[A-Z][0-9]+|[A-Z](?=[A-Z][a-z])|[A-Z]{2,}(?=[A-Z][a-z]|$))';

        if (preg_match('~^[a-z]+[0-9]*' . $hump . '+$~', $c) !== 1 && preg_match('~^' . $hump . '+$~', $c) !== 1) {
            return false;
        }
        // every lowercase word needs a vowel (or be a known acronym) so random mixed-case strings do not pass
        preg_match_all('~[A-Z]?[a-z]+~', $c, $words);
        foreach ($words[0] as $w) {
            $w = strtolower($w);
            if (preg_match('~[aeiouy]~', $w) !== 1 && ! in_array($w, ['pdf', 'url', 'sql', 'csv', 'xml', 'dto', 'php', 'api', 'db', 'ip', 'ui', 'qr', 'js', 'css', 'html', 'http', 'ssl', 'tls', 'jwt', 'sms', 'cdn', 'crm', 'hr', 'ssn', 'tz'], true)) {
                if ($vowelless < 1 || strlen($w) > 4) {
                    return false;
                }
                $vowelless--;
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

    /** `[scheme:]//[user@]host[:port]` then end, `/`, `?` or `#`; host is dotted, localhost, an IPv4 or `[ipv6]`; never after `base64:`. */
    private function isUrl(string $c): bool
    {
        $host = '(?:localhost|\d{1,3}(?:\.\d{1,3}){3}|\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)';
        if (preg_match('~^((?:[A-Za-z][A-Za-z0-9+.-]*:)?)//(?:[^/@\s]*@)?(' . $host . ')(?::\d+)?(?:[/?#]|$)~', $c, $m) !== 1) {
            return false;
        }

        return strtolower($m[1]) !== 'base64:' && $this->entropy($m[2]) <= 4.0;
    }

    private function isWordishList(string $c): bool
    {
        foreach (explode(',', $c) as $part) {
            if (! $this->isWordish($part)) {
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
