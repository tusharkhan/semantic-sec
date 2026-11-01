# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-01

First public release. semantic-sec finds authorization flaws in Laravel 8–13 applications with an LLM of your choice. It is pre-1.0, so options, output and fingerprints may still change.

### Added

- `map`: the authorization map of every route and the checks that protect it, with no LLM and no API key.
- `analyze`: candidate selection, pruned and redacted payloads, one structured LLM request per payload, schema validation and grounding against the lines sent.
- Five categories: `idor`, `missing_authorization`, `mass_assignment`, `insecure_deserialization` and `workflow_bypass`.
- Providers: Anthropic (default), OpenAI and OpenAI-compatible APIs such as Groq, and Ollama.
- Output formats: `console`, `json`, `sarif` (GitHub code scanning) and `gitlab-sast` (GitLab SAST report 15.2.5).
- `--dry-run`, which writes exactly what would be sent and makes no network calls.
- `@semantic-sec-ignore` suppressions, fingerprint baselines (`baseline`, `--baseline`, `--no-baseline`) and `--since` to scan only the routes a change can affect.
- `--level`, `--min-confidence`, `--strict`, `--budget`, `--deep`, `--no-cache` and `--output`.
- `semantic-sec.yaml` configuration, including your own authorization middleware, helpers and prompt rulesets.
- A PHAR on each GitHub release with its SHA-256, so projects on PHP 7.4–8.1 can be scanned with PHP 8.2+.
- Example CI files for GitHub Actions and GitLab CI.

### Accuracy

On the 31-case benchmark corpus, 29 vulnerable variants were found (28 with a failing finding), and no safe variant got a failing finding. On the 6-case holdout written after tuning, 5 were found, and 2 safe variants got low-confidence notes. See `docs/benchmark-results.md`.

### Known gaps

- `validated()` input is not treated as mass input, even when the rules accept a sensitive field.
- A list endpoint whose model doesn't look user-owned is not selected.
