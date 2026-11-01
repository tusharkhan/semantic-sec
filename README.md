# semantic-sec

semantic-sec is a command-line tool that finds authorization flaws in Laravel applications: IDOR, missing authorization, mass assignment, insecure deserialization and workflow bypass. Linters and rule-based scanners can't see these flaws, because the vulnerable code is syntactically fine; what's wrong is a missing ownership check. semantic-sec builds a map of every route and the checks that protect it, picks the routes that look unprotected, and asks an LLM of your choice to confirm each one against the real code. It is for Laravel teams who want these checks in code review and CI, with their own API key.

**Status:** v0.1, pre-1.0. Options, output and fingerprints may still change between minor versions.

- [Install](#install)
- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Providers](#providers)
- [Running analyze](#running-analyze)
- [Output formats](#output-formats)
- [Configuration](#configuration)
- [Suppressions](#suppressions)
- [Baselines](#baselines)
- [Changed code only (`--since`)](#changed-code-only---since)
- [CI](#ci)
- [Privacy: what leaves your machine](#privacy-what-leaves-your-machine)
- [Security caveats](#security-caveats)
- [Accuracy](#accuracy)
- [Limitations](#limitations)
- [Contributing](#contributing)
- [License](#license)

## Install

**Composer**, for projects that run on PHP 8.2 or later:

```
composer require --dev tusharkhan/semantic-sec:^0.1
vendor/bin/semantic-sec --version
```

**PHAR**, for projects on PHP 7.4–8.1, or when Composer can't fit semantic-sec's dependencies (Symfony 6.4 or 7, Guzzle 7) next to yours. Each GitHub release has `semantic-sec.phar` and its SHA-256:

```
curl -fsSLO https://github.com/tusharkhan/semantic-sec/releases/download/v0.1.0/semantic-sec.phar
curl -fsSLO https://github.com/tusharkhan/semantic-sec/releases/download/v0.1.0/semantic-sec.phar.sha256
sha256sum -c semantic-sec.phar.sha256          # macOS: shasum -a 256 -c semantic-sec.phar.sha256
php semantic-sec.phar --version                # needs PHP 8.2+
```

The tool itself needs PHP 8.2 to run, but it only *reads* your project. It parses the source as text (PHP 7.4–8.4 syntax), never loads or runs it, and doesn't need the project's `vendor/`. So you can run the PHAR with PHP 8.2+ on your machine or in CI against a project that still runs on PHP 7.4–8.1.

The checksum file comes from the same release, so it proves the download is intact, not that the release is genuine. In CI, pin the hash you checked once instead of downloading it each time.

Wherever this README says `vendor/bin/semantic-sec`, the PHAR works the same way as `php semantic-sec.phar`.

## Quick start

Run these from your Laravel project's root, or pass `--project-root=/path/to/app`.

**1. See the authorization map.** No LLM, no API key, nothing leaves the machine:

```
vendor/bin/semantic-sec map
```

It lists every route, its controller action and the checks that protect it (middleware, policies, FormRequest `authorize()`, controller calls, query scoping), then a count of routes with authorization, with authentication only, and unprotected. `--format=json` gives the same as JSON. If a route shows as unprotected but your own middleware or helper protects it, tell semantic-sec about it in the [configuration](#configuration) (`authorization_middleware`, `auth_helpers`).

**2. See exactly what would be sent.** Still no key and no network:

```
vendor/bin/semantic-sec analyze --dry-run
```

This writes the system prompt to `.semantic-sec/dry-run/000-system.txt` and every payload to `NNN-<verb-uri-slug>-<part>.txt` beside it, with secrets redacted. Read a few to see what the LLM would get. `--dry-run --format=json` lists the payloads on stdout.

**3. Run the analysis:**

```
export ANTHROPIC_API_KEY=...
vendor/bin/semantic-sec analyze
```

Add `.semantic-sec/` to your `.gitignore`: it holds the dry-run output and the answer cache.

## How it works

1. **Authorization map.** semantic-sec parses every PHP file in the project (skipping `vendor/`, `node_modules/`, `storage/`, `bootstrap/cache/`, `.git/` and `.semantic-sec/`). It resolves each route to its action and bound models, and records every check that protects it. This is deterministic, and it is what `map` prints.
2. **Candidate selection.** Only routes that look like a flaw go further: a user-controlled identifier with no ownership check, a state change with no authorization, request data mass-assigned to a model with sensitive fillable fields, `unserialize()` on user data, or a status change with no guard. Everything else never reaches the LLM. `--deep` also sends routes that already have an authorization check.
3. **Payloads.** For each candidate, the call graph is traced to `max_depth` (default 3). Low-risk code and comments are pruned, every line is tagged with its line number, and a context block describes the route and its checks. Secret-looking string literals are redacted, and the code is fenced as untrusted data.
4. **LLM.** Each payload goes to the provider as one structured-output request. Answers are cached in `.semantic-sec/cache/`.
5. **Validation and grounding.** Each answer must match the finding schema; an invalid one is retried once, then dropped. Each finding's file and line must be a line that was actually in the payload, or the finding is dropped.
6. **Fingerprints.** Each finding gets a fingerprint from its file, symbol, CWE and the symbol's normalised code. Duplicates are merged, then suppressions, the baseline, `--level` and `--min-confidence` are applied.

**What it looks for:**

| Category | Meaning | CWE |
|---|---|---|
| `idor` | A record fetched or changed by a user-supplied ID with no ownership check | CWE-639 |
| `missing_authorization` | A privileged action with no authorization at all | CWE-862 |
| `mass_assignment` | Request data written to a model whose `$guarded`/`$fillable` lets sensitive fields through | CWE-915 |
| `insecure_deserialization` | `unserialize()` on user-controlled data | CWE-502 |
| `workflow_bypass` | A state transition that isn't enforced, such as refunding an unpaid order | CWE-841 |

SQL injection, XSS, SSRF, secrets and dependency CVEs are out of scope. Use a taint analyser such as Psalm and `composer audit` for those.

## Providers

The API key is always read from the environment, never from the config file.

**Anthropic** (the default). Set `ANTHROPIC_API_KEY`. The recommended model is in [`config/defaults.php`](config/defaults.php), refreshed each release; set `model` in the config or pass `--model` to use another. `effort` (default `high`) applies to Anthropic only.

**OpenAI.** Set `provider: openai` and `OPENAI_API_KEY`. It also has a recommended model in `config/defaults.php`.

**Groq** and other OpenAI-compatible APIs. Groq speaks the OpenAI Chat Completions API, so it is not a separate provider. Point the `openai` provider at Groq's base URL:

```yaml
provider: openai
base_url: https://api.groq.com/openai/v1
api_key_env: GROQ_API_KEY
model: openai/gpt-oss-120b
```

Then `export GROQ_API_KEY=...`. `api_key_env` names the variable; the key itself never goes in the YAML.

**Ollama**, for local models. Set `provider: ollama`; it needs no key and talks to `http://localhost:11434` unless you set `base_url`. Its limits:

- There is no recommended model. Name one in `semantic-sec.yaml`, or the run exits 2 with `ollama needs a model in semantic-sec.yaml`.
- Expect lower quality. The accuracy figures below were measured with Anthropic only; local models haven't been benchmarked.
- The answer must be the JSON object, optionally inside one ```` ```json ```` fence. Anything else counts as invalid: it is retried once, then dropped.
- semantic-sec doesn't set Ollama's context window (`num_ctx`). A payload can be up to `max_payload_tokens` (default 8000) plus the system prompt, which may be more than the model's default. Raise `num_ctx` in the model, or lower `max_payload_tokens`.

## Running analyze

```
vendor/bin/semantic-sec analyze --project-root=/path/to/laravel-app
vendor/bin/semantic-sec analyze app/Http/Controllers/Billing   # report only candidates under these paths
vendor/bin/semantic-sec analyze --level=medium --min-confidence=high --budget=200000
```

`analyze` maps the routes, picks candidates, sends their payloads to the LLM, and prints each finding: severity and title, file, line, symbol, category, confidence, context, flaw, suggested fix, and the patch when there is one. It then prints a summary and any warnings.

**API key.** It is read from `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` by default, or from the variable that `api_key_env` names. A missing key exits 2, naming the variable and never its value. `--dry-run` needs no key.

| Option | What it does |
|---|---|
| `[paths...]` | Report only candidates under these paths (relative to the project root or the cwd). The whole project is still parsed. Replaces the config's `paths` |
| `--project-root` | The Laravel app to scan (default: the cwd) |
| `--config` | A `semantic-sec.yaml` to use instead of the one in the project root |
| `--framework` | Skip detection and force `laravel` |
| `--format` | `console` (default), `json`, `sarif` or `gitlab-sast`; see [Output formats](#output-formats). With `--dry-run`, `json` lists the payloads, and `sarif` and `gitlab-sast` exit 2 |
| `--output` | Write the report to this file instead of stdout. Stdout stays empty and the summary goes to stderr; exit codes don't change. Exit 2 with `--dry-run` |
| `--level` | Minimum severity to report and fail on: `low`, `medium`, `high` (default) or `critical`. Findings below it are only counted (and kept in JSON) |
| `--min-confidence` | Below this confidence (`low`, `medium` (default) or `high`) a finding is still reported, marked `not failing`. It never fails the build, and in SARIF it is a `note` |
| `--strict` | Exit 2 when any request failed, was refused, was invalid or truncated, or a payload went unsent, so a partial run can't pass CI. A failing finding (exit 1) still wins. Ignored with `--dry-run` |
| `--provider` / `--model` | Override the config: `anthropic`, `openai` or `ollama`, and the model id |
| `--concurrency` | Parallel requests (default 5) |
| `--budget` | Hard cap on provider tokens; see below |
| `--deep` | Also send routes that already have an authorization check. More recall, more cost, more false positives |
| `--no-cache` | Ignore cached answers (new answers are still cached). Use it in CI on code you don't trust |
| `--dry-run` | Write the system prompt and payloads to `.semantic-sec/dry-run/` instead of sending them; no network, no key |
| `--baseline`, `--no-baseline`, `--generate-baseline` | See [Baselines](#baselines) |
| `--since` | See [Changed code only](#changed-code-only---since) |

`--level`, `--min-confidence`, `--provider`, `--model`, `--concurrency` and `--budget` override the config file and are validated the same way. Flags, the config file and the API key are checked before the project is parsed.

**`--budget N`** is a hard cap on provider tokens. Before each request the run reserves twice the prompt plus `max_tokens`, so one request needs about 35k tokens of headroom at the default `max_tokens` of 16000. A budget below that sends nothing and exits 3. Partial results are still printed.

**Exit codes**

| Code | Meaning |
|---|---|
| 0 | Clean: no findings, or only suppressed, baselined or non-failing (below `--min-confidence`) ones |
| 1 | At least one failing finding. This wins over 2 and 3 |
| 2 | Tool error: bad config or flag, no framework detected, missing API key, unsafe `.semantic-sec/` directory, or every request failed. With `--strict`, also any failed, refused, invalid or truncated request or unsent payload; the summary names it (`strict: 3 failed, 2 unsent`), and strict 2 beats 3 |
| 3 | Token budget exceeded with no failing finding (partial results are still printed) |

**Paths you write to.** `--output` and the baseline writers (`--generate-baseline`, `semantic-sec baseline`) refuse a target that is a symlink, and any existing ancestor directory that is a symlink, and they write through a temp file in the same directory. On macOS `/tmp` and `/var` are themselves symlinks, so pass a path under the project, or resolve it first: `--output="$(realpath out)/report.sarif"`.

**Memory.** `semantic-sec` raises PHP's `memory_limit` to `1G` when it is lower, since real projects exceed the 128M default. Set `SEMANTIC_SEC_MEMORY_LIMIT` (`2G`, `-1`, …) to choose another.

**`map`** takes `--project-root`, `--config`, `--framework` and `--format` (`console` or `json`). **`baseline`** takes every `analyze` option.

## Output formats

- **`console`** (default). A header with the provider and model, then findings grouped by file, the suppressed and baselined lists, a summary (candidates, payloads, requests by outcome, findings, tokens, budget) and warnings. Below-`--level` findings appear only as a count.
- **`json`.** `{version, tool, summary, findings[], suppressed[], baselined[], filtered[], warnings[]}`. Each finding has `title, category, severity, confidence, file, line, symbol, context, flaw, fix, patch, path[]`, then `fingerprint`, `failing`, `routeKey` and `model`. `summary` includes `exitCode`.
- **`sarif`.** SARIF 2.1.0 for GitHub code scanning and other SARIF viewers. Results are the reported findings only; suppressed, baselined and below-`--level` findings are counted in `run.properties.summary`, not listed. Critical and high are `error`, medium is `warning`, low is `note`, and a non-failing finding is always `note`. Each result carries `partialFingerprints."semanticSec/v1"`.
- **`gitlab-sast`.** A GitLab SAST report (schema 15.2.5) for `artifacts: reports: sast`. Like SARIF, it lists only reported findings. Severities are `Critical`, `High`, `Medium` and `Low`, and a non-failing finding is `Info`. Each vulnerability's id is derived from its fingerprint, so it is stable across runs and line moves.

With `json`, `sarif` and `gitlab-sast`, stdout carries only the document; the summary and warnings go to stderr, so stdout stays parseable.

## Configuration

semantic-sec reads `semantic-sec.yaml` from the project root if it exists, or the file `--config` names. Every key is optional. Unknown keys are an error (exit 2), which catches typos.

| Key | Default | What it does |
|---|---|---|
| `provider` | `anthropic` | `anthropic`, `openai` or `ollama` |
| `model` | `null` | `null` uses the provider's model in `config/defaults.php`; `ollama` needs one |
| `effort` | `high` | Anthropic only: `low`, `medium`, `high`, `xhigh` or `max` |
| `api_key_env` | `null` | The environment variable holding the key; `null` means `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` |
| `base_url` | `null` | The provider's API URL, e.g. Groq's with `provider: openai` |
| `concurrency` | `5` | Parallel requests |
| `budget_tokens` | `null` | Hard cap on provider-reported tokens; `null` is unlimited. Below about 35k nothing is sent |
| `max_payload_tokens` | `8000` | Larger payloads are split; one method over the limit is cut and its findings capped at medium confidence |
| `max_depth` | `3` | How deep the call graph is traced, from 1 to 5 |
| `level` | `high` | Same as `--level` |
| `min_confidence` | `medium` | Same as `--min-confidence` |
| `paths` | `[]` | Default report scope; `[paths...]` on the command line replaces it |
| `exclude` | `[]` | Extra globs (relative to the project root) of files to skip entirely |
| `laravel.route_files` | `[]` | Route files added to the auto-discovered ones |
| `laravel.sensitive_fields` | `[]` | Added to the built-in list: `is_admin`, `role`, `role_id`, `admin`, `balance`, `credits`, `email_verified_at`, `password`, `user_id`, `owner_id`, `team_id`, `tenant_id`, `status` |
| `auth_helpers` | `[]` | Your own authorization helpers, by method name or `Class::method`. A call to one counts as an authorization check |
| `auth_middleware` | `[]` | Your own *authentication* middleware, by alias or class name |
| `authorization_middleware` | `[]` | Your own *authorization* middleware, by alias or class name, without `:` parameters. Group names are not expanded; list the member alias or class |
| `rulesets` | `[]` | Extra rules appended to the system prompt, each `{name, prompt}` |

```yaml
provider: anthropic
level: medium
exclude:
  - "app/Legacy/*"
auth_helpers:
  - ownsOrFail
authorization_middleware:
  - permission   # covers routes using permission:manage
rulesets:
  - name: tenancy
    prompt: "Every Eloquent query on tenant models must be scoped by team_id."
```

Routes behind `authorization_middleware` count as authorization-checked, so they are no longer `missing_authorization` candidates. IDOR is still checked, because such middleware doesn't prove ownership of a record.

## Suppressions

Silence a finding you have reviewed with a comment in the code:

```php
// @semantic-sec-ignore idor: shared invoices are public by contract
public function show(int $id) { ... }
```

The form is `// @semantic-sec-ignore <category|CWE-ID|all>[: reason]`, for example `idor`, `CWE-639` or `all`. It also works inside a docblock.

- On a method signature or in its docblock, it covers the whole method. Anywhere else, it covers the next statement.
- Above a `namespace` or class declaration it is rejected with a warning; only method and statement scope exist.
- A suppression with no reason is honoured, with a warning. A comment that mentions `@semantic-sec-ignore` but doesn't parse is reported as malformed.

Suppressed findings are listed in the console and JSON output, but not in SARIF or GitLab SAST. Suppressions are trusted input: anyone who can add one can hide a finding, so review new ones in code review.

## Baselines

Accept today's findings and fail only on new ones:

```
vendor/bin/semantic-sec baseline --project-root=/path/to/laravel-app      # same as analyze --generate-baseline
vendor/bin/semantic-sec analyze --project-root=/path/to/laravel-app       # uses semantic-sec-baseline.json if present
vendor/bin/semantic-sec analyze --baseline=ci/baseline.json               # or an explicit file (must exist)
```

Generating runs the full analysis and writes the fingerprint of every finding, including non-failing and below-`--level` ones (not suppressed ones), to `semantic-sec-baseline.json` in the project root. It exits 0 whatever it found, unless every request failed or `--strict` trips; then it exits 2 and writes nothing. An explicit `--baseline` path is relative to the cwd, like any CLI path. The file is sorted and pretty-printed, so commit it and review its diffs. Later runs list matching findings as baselined instead of reporting them. A fingerprint covers the file, symbol, category and the symbol's code, so editing a baselined method brings its finding back. A malformed baseline file is exit 2. `--no-baseline` reads no baseline at all, not even the default file.

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

## CI

Two ready-to-copy examples:

- [`examples/github-actions.yml`](examples/github-actions.yml) uploads SARIF to GitHub code scanning.
- [`examples/gitlab-ci.yml`](examples/gitlab-ci.yml) publishes a GitLab SAST report.

Both run a full scan on the default branch and a `--since` scan on pull or merge requests. Both install with Composer by default, and switch to the PHAR with one variable (`SEMANTIC_SEC_INSTALL: phar`) for projects on PHP 7.4–8.1. Both read the API key from a secret or masked variable.

**What the GitHub workflow does:**

1. **Checkout** with `fetch-depth: 0`, so git has the merge base for `--since`.
2. **Install** PHP 8.2 and semantic-sec.
3. **Trusted inputs** (PRs only). Read `semantic-sec.yaml` and `semantic-sec-baseline.json` from the base branch with `git show`. A missing config becomes an empty file (the defaults); a missing baseline becomes `--no-baseline`.
4. **Scan.** On `main`: a full scan. On a PR: `--since`, `--no-cache` and the trusted config and baseline. Both use `--strict` and write SARIF. The step records its exit code.
5. **Upload** the SARIF only when the run completed: exit 0 (clean) or 1 (findings). On exit 2 (tool error, every request failed, or `--strict` tripped) or 3 (budget exceeded), the SARIF is partial, and uploading it would close existing alerts for routes it never checked.

A `--since` SARIF holds only the affected routes, so it goes up under its own category (`semantic-sec-pr`), and the full scan on `main` under `semantic-sec`. Code scanning matches analyses by category, so a PR's partial run never closes alerts the full run raised on unchanged code. The `Scan` step still fails the job on exit 1, 2 or 3. If the project lives in a subdirectory, prefix the `git show` paths and pass `--project-root`.

The workflow is for **pull requests from branches of the same repository only**: fork PRs get no secrets, so the job skips them. **Never switch it to `pull_request_target`.** That trigger gives the job your secrets while it checks out and runs the PR's code (`composer install`, `vendor/bin`), so any fork could steal the API key.

The GitLab job works the same way: it takes the config and baseline from `$CI_MERGE_REQUEST_DIFF_BASE_SHA` (the merge base on the target branch), scans with `--since` against it, and keeps the report only on exit 0 or 1.

## Privacy: what leaves your machine

`map` and `analyze --dry-run` make no network calls. A real `analyze` sends requests only to the provider you configured (its default API URL, or your `base_url`). There is no telemetry.

**What is sent** is exactly what `--dry-run` writes to `.semantic-sec/dry-run/`, so you can read it before you send anything:

- the system prompt: fixed instructions, framework notes and your `rulesets`
- one or more payloads per candidate route, each with:
  - a context block: the route's method, URI, middleware, bound parameters and authorization checks; the FormRequest's rule keys and `authorize()` summary; `$fillable`/`$guarded` of the models involved; and the text of unresolved calls
  - the code of the methods on the route's execution path (to `max_depth`) and the policy methods it relies on, with comments removed, line-tagged, under their project-relative file paths

Only candidate routes are sent. Code that no candidate reaches is parsed locally and never leaves the machine. Only PHP files are parsed, plus `composer.json` and `composer.lock` to detect Laravel; `.env` files are never read.

**Redaction.** Before anything is sent or written, string literals that look like secrets are replaced with `'<redacted>'`: AWS access keys (`AKIA…`), `sk-…` and `sk_live_…` keys, GitHub tokens (`ghp_…`), JWTs, PEM blocks, and any literal of 20 or more characters with high entropy. Redaction is pattern-based. It cannot know that an ordinary-looking string is sensitive, so check the dry-run output if that matters to you.

**Your API key** is read from an environment variable and used only in the request header to your provider. It is never read from or written to the config file, the cache, reports or logs, and error messages name the variable, never its value.

**The cache** (`.semantic-sec/cache/`) stays on your machine. It holds the validated answers, not the payloads.

## Security caveats

**Prompt injection.** The payload is your source code, and code can contain text written to steer the model, such as a comment claiming "this route is safe". semantic-sec fences the code as untrusted data, tells the model to ignore such claims, removes comments, and checks every finding against the lines that were sent. Still, treat LLM output as advisory: an attacker who can change the code under review may be able to hide a finding or plant a misleading one. Run semantic-sec on trusted branches, or review its output as you would any review comment.

**Trust boundary.** `semantic-sec.yaml`, `@semantic-sec-ignore` comments, the baseline file and `.semantic-sec/cache/` are all trusted input. Anyone who can change them can hide a finding. In CI on pull requests you don't fully trust:

- run with `--no-cache`, because a committed cache entry can hide a finding
- use only a config and baseline you control (read from the base branch, as the examples do) or `--no-baseline`, because the PR can edit `semantic-sec-baseline.json`
- review new suppression comments, which still apply in the PR's own code

Under `on: pull_request`, the workflow file, `composer.json` and `composer.lock` (and so the `semantic-sec` binary that runs) all come from the PR. Reading the config and baseline from the base branch stops *accidental* hiding, such as a PR that regenerates the baseline or loosens `semantic-sec.yaml`. It does not stop a PR author who sets out to hide a finding. If PR authors aren't fully trusted, protect `.github/workflows/**`, `composer.json` and `composer.lock` with CODEOWNERS review, or run the scan as a required workflow defined outside the repository. The same applies to `.gitlab-ci.yml` on GitLab.

## Accuracy

Measured on the benchmark corpus in [`benchmark/`](benchmark/). Full results are in [`docs/benchmark-results.md`](docs/benchmark-results.md).

**The corpus.** 31 cases across three Laravel apps, each with a vulnerable and a safe variant, plus 2 public-by-design routes. A real Laravel 12 feature test proves every case: the attack succeeds on the vulnerable variant and is blocked on the safe one, which still works for its owner. The cases come in three sets:

- **existing** (15): written alongside the scanner
- **blind** (10): written by an author who had read only the corpus and the spec's scope and quality-bar sections. The scanner was tuned once after their first measurement
- **holdout** (6): written after tuning was finished and never tuned on. This is the honest number for unseen code.

The scanner ran on a disguised copy of the corpus, with the vulnerable and safe names randomised, using the default Anthropic model at the time (named in the results).

**Results.** A case counts as found when a finding of the right category lands on the right method.

| | existing | blind | holdout | all |
|---|---|---|---|---|
| Vulnerable variants found | 15/15 | 9/10 | 5/6 | 29/31 (93.5%) |
| Found with a failing finding (confidence ≥ medium) | 15/15 | 9/10 | 4/6 | 28/31 (90.3%) |
| Safe variants flagged, any confidence | 0/15 | 1/10 | 2/6 | 3/31 (9.7%) |
| Safe variants flagged, failing findings only | 0/15 | 0/10 | 0/6 | 0/31 |
| Public-by-design routes flagged | 0/1 | 0/1 | none | 0/2 |

All three safe-variant flags are low-confidence `workflow_bypass` notes saying a pause, approve or publish action has no status guard. They are reported as not failing and never fail CI. Measured against our own release bar (SPEC §15), the existing and blind sets pass, and the holdout fails: 2 of 6 safe variants flagged at any confidence, and 10 of its 12 expected authorization checks matched by `map` (60 of 62 across the corpus).

**Compared with Anthropic's `claude-code-security-review`.** It ran with the same model on the same disguised copy, as one pull request, and was scored by the same scorer. It wasn't run on the holdout.

| existing + blind (25 cases) | semantic-sec | claude-code-security-review |
|---|---|---|
| Vulnerable variants found | 24/25 (96%) | 21/25 (84%) |
| Safe variants flagged, any confidence | 1/25 | 0/25 |
| Safe variants flagged, failing findings only | 0/25 | 0/25 |

Its misses were both workflow cases and two authorization cases; it found the one case semantic-sec missed. The comparison has asymmetries, listed in the results. Most of them favour the other tool: its free-text categories are scored leniently, and here it saw the whole corpus at once, while on a real PR it sees only the diff.

**Known gaps:**

- `validated()` input is not treated as mass input, even when the validation rules accept a sensitive field. The holdout's mass-assignment case was missed this way: it was never sent to the LLM.
- A list endpoint is selected only when the model it reads looks user-owned (an owner key such as `user_id`, or a relation to the user model). A list of records owned some other way is not sent.
- Expect occasional low-confidence notes on safe routes, like the `workflow_bypass` notes above. They don't fail CI at the default `--min-confidence`.
- The corpus is small. In the 6-case holdout, one case moves a rate by about 17 points.

## Limitations

- Laravel 8–13 only. Other frameworks and plain PHP projects exit 2 with "No supported framework detected".
- Five categories only (see [How it works](#how-it-works)); not a general SAST tool.
- The analysis is static. Authorization that happens outside the code it can see, such as in a gateway, a package or the database, is invisible to it. Routes registered at runtime may be missed.
- v0.1 is pre-1.0: options, output formats and fingerprints may change before 1.0, and a fingerprint change would make a baseline show old findings again.

## Contributing

There is no host PHP requirement; everything runs in the repo's Docker image.

```
docker compose run --rm php composer install
docker compose run --rm php vendor/bin/phpunit
docker compose run --rm php vendor/bin/phpstan analyse --memory-limit=512M
docker compose run --rm php vendor/bin/pint --test
```

The benchmark has two checks:

```
docker compose run --rm php sh benchmark/verify/run.sh laravel12-app   # prove each case on real Laravel 12 (also laravel11-app, laravel10-app)
docker compose run --rm php php bin/benchmark                          # replay the recorded benchmark run and score it; free, no key
```

A change to the default model, `SecurityPrompt`, the payload format or a benchmark app's map needs the benchmark recordings re-made; see [`docs/SPEC.md`](docs/SPEC.md) §15. The full design is in `docs/SPEC.md`.

## License

MIT. See [LICENSE](LICENSE).
