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
| 1 | At least one failing finding. This wins over 2 and 3 |
| 2 | Tool error: bad config or flag, no framework detected, missing API key, unsafe `.semantic-sec/` directory, or every request failed. With `--strict`, also any failed, refused, invalid or truncated request or unsent payload; the summary names it (`strict: 3 failed, 2 unsent`), and strict 2 beats 3 |
| 3 | Token budget exceeded with no failing finding (partial results are still printed) |

**`--budget N`** is a hard cap on provider tokens. Before each request the run reserves twice the prompt plus `max_tokens`, so one request needs about 35k tokens of headroom at the default `max_tokens` of 16000. A budget below that sends nothing and exits 3.

**`authorization_middleware`** lists your own authorization middleware (an alias or class name, without `:` parameters). Routes behind it count as authorization-checked, so they are no longer `missing_authorization` candidates. IDOR is still checked, because such middleware doesn't prove ownership of a record.

```yaml
authorization_middleware:
  - permission
```

**Trust boundary.** `semantic-sec.yaml`, `@semantic-sec-ignore` suppression comments, the baseline file and `.semantic-sec/cache/` are all trusted input. Anyone who can change them can hide a finding. Add `.semantic-sec/` to your `.gitignore`. In CI on pull requests you don't trust, run with `--no-cache`, because a committed cache entry can hide a finding, and use only a baseline you control (an explicit `--baseline` path the PR cannot edit) or none, because the PR can edit `semantic-sec-baseline.json`.

## Baselines

Accept today's findings and fail only on new ones:

```
vendor/bin/semantic-sec baseline --project-root=/path/to/laravel-app      # same as analyze --generate-baseline
vendor/bin/semantic-sec analyze --project-root=/path/to/laravel-app       # uses semantic-sec-baseline.json if present
vendor/bin/semantic-sec analyze --baseline=ci/baseline.json               # or an explicit file (must exist)
```

Generating runs the full analysis and writes the fingerprint of every finding, including non-failing and below-`--level` ones (not suppressed ones), to `semantic-sec-baseline.json` in the project root. It exits 0 whatever it found, unless every request failed. The file is sorted and pretty-printed, so commit it and review its diffs. Later runs list matching findings as baselined instead of reporting them. A fingerprint covers the file, symbol, category and the symbol's code, so editing a baselined method brings its finding back. A malformed baseline file is exit 2.

**What a fingerprint does not cover.** A fingerprint hashes only the finding's own method. A baselined finding stays hidden when only a callee, the route, its middleware or a policy changes, even if that change makes the flaw worse. One fingerprint also covers every flaw of the same category in that method, so a second IDOR added to a baselined method without touching the first stays hidden too. Review such changes by hand; removing the entry from the baseline brings the finding back.

The baseline is trusted input, like suppression comments: anyone who can edit it can hide a finding.

## Changed code only (`--since`)

On a pull request, send only the routes the PR's commits can affect:

```
vendor/bin/semantic-sec analyze --since=origin/main
```

It runs `git diff --name-only <ref>...HEAD`, so only committed changes since the merge base count. A route is sent when the change touches its route file, any method on its execution path, or a middleware, policy, FormRequest or model it uses. A change to `app/Http/Kernel.php`, `bootstrap/app.php`, any service provider, a deleted PHP file or a file that failed to parse sends every route. Changes to `config/`, `composer.lock` or `semantic-sec.yaml` do not; run without `--since` after those. Routes left out are counted as `unaffected` in the summary. A PR that touches no route sends nothing and exits 0. A ref that isn't a commit, or a project that isn't in a git repository, exits 2. `--since` with `--dry-run` writes only the affected payloads; it can't be combined with `--generate-baseline`.

The project may live in a subdirectory of the repository. The checkout needs the full history so git can find the merge base:

```yaml
on: pull_request
jobs:
  semantic-sec:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: shivammathur/setup-php@v2
        with:
          php-version: '8.2'
      - run: composer install --no-interaction --no-progress
      - run: vendor/bin/semantic-sec analyze --since=origin/${{ github.base_ref }} --no-cache --format=sarif --output=semantic-sec.sarif
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

The PR's own `semantic-sec-baseline.json` is read by default, and the PR can edit it; see the trust boundary above before running this on pull requests you don't trust.

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
