# semantic-sec

A CLI tool that finds authorization and business-logic vulnerabilities (such as IDOR) in Laravel applications. It parses the project to build an authorization map of routes and the checks that protect them, picks candidate routes that lack an ownership check, and can optionally ask an LLM to confirm each one.

Status: under development.

## Running analyze

```
export ANTHROPIC_API_KEY=...                       # or OPENAI_API_KEY for provider openai
vendor/bin/semantic-sec analyze --project-root=/path/to/laravel-app
vendor/bin/semantic-sec analyze app/Http/Controllers/Billing   # report only candidates under these paths
vendor/bin/semantic-sec analyze --level=medium --min-confidence=high --budget=200000
```

`analyze` maps the routes, picks candidates, sends one payload per candidate to the LLM, and prints one line per finding, a summary and any warnings.

**API key.** It is read from the environment: `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` by default, or the variable that `api_key_env` names in `semantic-sec.yaml`. The key itself never goes in the YAML. A missing key exits 2, naming the variable and never its value. `--dry-run` needs no key.

**Exit codes**

| Code | Meaning |
|---|---|
| 0 | Clean: no findings, or only suppressed, baselined or non-failing (below `--min-confidence`) ones |
| 1 | At least one failing finding. This wins over 3 |
| 2 | Tool error: bad config or flag, no framework detected, missing API key, unsafe `.semantic-sec/` directory, or every request failed |
| 3 | Token budget exceeded with no failing finding (partial results are still printed) |

**`--budget N`** is a hard cap on provider tokens. Before each request the run reserves twice the prompt plus `max_tokens`, so one request needs about 35k tokens of headroom at the default `max_tokens` of 16000. A budget below that sends nothing and exits 3.

**`authorization_middleware`** lists your own authorization middleware (an alias or class name, without `:` parameters). Routes behind it count as authorization-checked, so they are no longer `missing_authorization` candidates. IDOR is still checked, because such middleware doesn't prove ownership of a record.

```yaml
authorization_middleware:
  - permission
```

**Trust boundary.** `semantic-sec.yaml`, `@semantic-sec-ignore` suppression comments and `.semantic-sec/cache/` are all trusted input. Anyone who can change them can hide a finding. Add `.semantic-sec/` to your `.gitignore`. In CI on pull requests you don't trust, run with `--no-cache`, because a committed cache entry can hide a finding.

## Dry run

Pick candidate routes and write the payloads an LLM would get, without sending anything (no API key, no network):

```
vendor/bin/semantic-sec analyze --dry-run --project-root=/path/to/laravel-app
vendor/bin/semantic-sec analyze --dry-run --deep --format=json   # also review routes that have an authorization check
```

The system prompt lands in `.semantic-sec/dry-run/000-system.txt` and the payloads in `NNN-<verb-uri-slug>-<part>.txt` beside it, inside the project, secrets redacted. `semantic-sec map` prints the authorization map on its own.

## Groq

Groq speaks the OpenAI Chat Completions API, so it is not a separate provider. Point the `openai` provider at Groq's base URL in `semantic-sec.yaml`:

```yaml
provider: openai
base_url: https://api.groq.com/openai/v1
api_key_env: GROQ_API_KEY
model: openai/gpt-oss-120b
```

Put the key in your environment (`export GROQ_API_KEY=...`), never in the YAML. `api_key_env` names the variable; the key itself is never read from the config file.
