# Open Questions: Semantic Security & Vulnerability Analyzer

Questions raised while reviewing `semantic_security_vulnerability_analyzer_spec.md`. Each one needs an answer before (or during) implementation.

---

## 1. Call Graph Resolution

1. How should calls be resolved when PHP's dynamic typing hides which class a method belongs to? Examples:
   - `$this->service->charge()` where `$service` comes from constructor injection
   - Laravel facades (`Payment::charge()`)
   - Container resolution (`app(PaymentService::class)`, `resolve()`)
   - Magic methods (`__call`, `__callStatic`) and dynamic calls (`$obj->$method()`)
2. Should resolution use constructor type hints, property types, and docblock `@var` / `@return` annotations? Or should we rely on PHPStan/Psalm type inference?
3. How deep should call tracing go (max depth)? What happens with recursion or cycles?
4. Should vendor code (`vendor/`) ever be traced into, or treated as a black box?
5. How large can a merged payload get before it has to be split, and how do we split it without losing context?

## 2. Framework Context Outside the Scanned Path

6. When the user scans only `app/Http/Controllers/`, should the tool also load the context that decides whether a flaw is real? This includes:
   - Route definitions (`routes/*.php`): middleware, route model binding, `can:` middleware
   - Policies / Gates (`app/Policies`, `AuthServiceProvider`)
   - `FormRequest::authorize()` and `rules()`
   - Model `$fillable` / `$guarded` / global scopes
   - Symfony security voters, `security.yaml` access_control, `#[IsGranted]` attributes
7. If yes, is that context auto-discovered or configured explicitly (e.g. a config file listing paths)?
8. Without that context, how do we keep false positives low (e.g. "no auth check" when middleware already enforces it)?

## 3. Pruning Rules

9. What exactly counts as "low-risk" code that can be stripped? Is there a defined list?
10. How do we make sure pruning never removes security-relevant code? Examples:
    - `$this->authorize(...)`, `Gate::allows(...)`, `abort_if/abort_unless`
    - Ownership checks inside a getter or helper method
    - Custom validation or sanitization helpers
11. Should docblocks be kept when they carry type information needed for call resolution?

## 4. LLM Provider & Data Privacy

12. Is OpenAI the only provider for v1, or should `ClientInterface` ship with others (Anthropic Claude, Azure OpenAI, local models via Ollama)?
13. Many teams cannot send proprietary source code to a third-party API. Do we need:
    - A local or self-hosted model option?
    - A redaction step (secrets, credentials, string literals) before sending?
    - A `--dry-run` that shows exactly what would be sent?
14. How are API keys supplied (env var, config file, CLI flag)?
15. Which model(s) are we targeting, and is the JSON Schema enforcement tied to OpenAI Structured Outputs, or provider-agnostic?

## 5. Cost, Performance & Caching

16. Is there a token or cost budget per run? What happens when it is exceeded (abort, truncate, warn)?
17. Should results be cached by file/payload content hash so unchanged code is not re-analyzed?
18. Should there be a diff-only mode (`--since=<git-ref>`) for CI that scans only changed files and their call-graph neighbours?
19. Should requests run in parallel? What concurrency and rate-limit handling is needed?
20. How should retries and backoff work for API failures and timeouts?

## 6. Result Reliability & Noise Control

21. LLM output is non-deterministic. How do we handle the same code producing different findings across runs? (temperature 0, seed, multiple passes, voting?)
22. Should each finding include a confidence score, and should `--level` or another flag filter on it?
23. How do we validate that the reported file and line number actually exist and point at the relevant code (to catch hallucinated locations)?
24. Do we need a baseline file (like PHPStan's baseline) so existing findings can be accepted and only new ones fail CI?
25. Do we need inline suppression (e.g. `// @semantic-sec-ignore IDOR`) and/or an ignore config file?
26. How are duplicate findings merged when the same flaw appears in several execution paths?

## 7. CLI Behaviour

27. What does `--level` mean exactly: a minimum severity filter (`low|medium|high|critical`), or analysis depth?
28. What are the exit codes? (e.g. `0` = clean, `1` = findings at/above threshold, `2` = tool error.) Should there be a `--fail-on=<severity>` flag?
29. Is `--framework` required, or should it be auto-detected (from `composer.json`: `laravel/framework`, `symfony/framework-bundle`)?
30. Should there be a config file (`semantic-sec.yaml` / `.php`) for paths, excludes, framework, provider, and budget?
31. What output formats are in scope for v1: `console`, `json`, `sarif`. Any others (e.g. Markdown for PR comments, JUnit XML)?

## 8. Vulnerability Model & SARIF

32. What fields does `Vulnerability` carry? Proposed: title, category (CWE / OWASP ID), severity, confidence, file, start/end line, context, flaw, suggested fix (diff), execution path.
33. Should findings map to CWE IDs and OWASP Top 10 categories so SARIF `ruleId`s are stable?
34. Should the SARIF output include `codeFlows` showing the execution path across files (useful for IDOR traced through services)?
35. Should the suggested fix be a real applicable patch, or descriptive text only?

## 9. Scope & Rulesets

36. Which PHP versions must the parser support (target code) and which PHP versions must the tool itself run on?
37. Which vulnerability classes are in scope for v1? (IDOR, mass assignment, missing auth, insecure deserialization, command/SQL injection, SSRF, business-logic state transitions, ...)
38. Should classic taint issues (SQLi, XSS) be left to existing tools, with this tool focused only on logic flaws?
39. Are Laravel and Symfony the only frameworks for v1? What about plain PHP, CodeIgniter, Slim, WordPress?
40. How are rulesets extended: can users add their own context classes or prompt fragments?

## 10. Testing & Quality

41. How do we measure accuracy? Do we need a benchmark corpus of known-vulnerable and known-safe PHP apps (e.g. DVWA, deliberately vulnerable Laravel apps) with expected findings?
42. How do we unit-test the LLM layer: recorded fixture responses, a fake client, or both?
43. What false-positive and false-negative rates count as acceptable for release?

## 11. Packaging & Distribution

44. Package name and namespace (e.g. `vendor/semantic-sec`, `SemanticSec\`)?
45. Distribute via Composer only, or also as a PHAR / Docker image for CI?
46. Licence (MIT, Apache-2.0, proprietary)?
47. Should we ship ready-made GitHub Actions and GitLab CI templates?
