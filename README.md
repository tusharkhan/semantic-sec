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

**Trust boundary.** `semantic-sec.yaml`, `@semantic-sec-ignore` suppression comments, the baseline file and `.semantic-sec/cache/` are all trusted input. Anyone who can change them can hide a finding. Add `.semantic-sec/` to your `.gitignore`. In CI on pull requests you don't trust, run with `--no-cache`, because a committed cache entry can hide a finding, and use only a baseline you control (an explicit `--baseline` path the PR cannot edit) or `--no-baseline`, because the PR can edit `semantic-sec-baseline.json`.

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

It runs `git diff --name-only <ref>...HEAD`, so only committed changes since the merge base count. Your git config cannot change the listed paths (`diff.relative` and similar settings are overridden).

A route is sent when the change touches its route file, any method on its execution path, a middleware, policy, FormRequest or model it uses, or a file its unresolved calls may reach. That last case covers a subclass that may override a called method, and any class declaring a method the path calls on an untyped receiver or past the depth limit. A change to `app/Http/Kernel.php`, `bootstrap/app.php`, `config/auth.php`, any service provider, a deleted PHP file or a file that failed to parse sends every route.

Some changes are not followed:

- changes to the rest of `config/`, `composer.lock` or `semantic-sec.yaml`; run without `--since` after those
- a callee reached only through a call with no method name at all (`new $class(…)`, `$fn(…)`, `$obj->{$name}(…)`)

Routes left out are counted as `unaffected` in the summary. A PR that touches no route sends nothing and exits 0. A ref that isn't a commit, or a project that isn't in a git repository, exits 2; in a shallow clone the message says to fetch full history. `--since` with `--dry-run` writes only the affected payloads. It can't be combined with `--generate-baseline`.

**GitHub Actions.** The workflow below is for **pull requests from branches of the same repository only**: fork PRs get no secrets, so the job skips them. **Never switch it to `pull_request_target`.** That trigger gives the job your secrets while it checks out and runs the PR's code (`composer install`, `vendor/bin`), so any fork could steal the API key.

Even on same-repo PRs, the PR controls `semantic-sec.yaml`, `semantic-sec-baseline.json` and `.semantic-sec/`, so the job reads the config and baseline from the base branch and skips the cache. `fetch-depth: 0` gives git the merge base. If the project lives in a subdirectory, prefix the `git show` paths and pass `--project-root`.

```yaml
on: pull_request
permissions:
  contents: read
jobs:
  semantic-sec:
    if: github.event.pull_request.head.repo.full_name == github.repository
    runs-on: ubuntu-latest
    env:
      BASE: origin/${{ github.base_ref }}
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: shivammathur/setup-php@v2
        with:
          php-version: '8.2'
      - run: composer install --no-interaction --no-progress
      - name: Config and baseline from the base branch
        run: |
          git show "$BASE:semantic-sec.yaml" > "$RUNNER_TEMP/semantic-sec.yaml" 2>/dev/null || : > "$RUNNER_TEMP/semantic-sec.yaml"
          if git show "$BASE:semantic-sec-baseline.json" > "$RUNNER_TEMP/baseline.json" 2>/dev/null; then
            echo "BASELINE=--baseline=$RUNNER_TEMP/baseline.json" >> "$GITHUB_ENV"
          else
            echo "BASELINE=--no-baseline" >> "$GITHUB_ENV"
          fi
      - run: vendor/bin/semantic-sec analyze --since="$BASE" --config="$RUNNER_TEMP/semantic-sec.yaml" "$BASELINE" --no-cache --format=sarif --output=semantic-sec.sarif
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

An empty config file means the defaults. `--no-baseline` reads no baseline at all, not even the default file. `@semantic-sec-ignore` comments in the PR's own code still apply, so review new suppression comments in the PR.

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
