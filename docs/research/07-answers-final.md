# Architectural Decisions & Answers: Semantic Security & Vulnerability Analyzer (Finalized)

## 1. Call Graph Resolution & Payload Construction

**1. Dynamic Typing Resolution:** Degrade gracefully. Use constructor type hints, property types, and `@var`/`@return` docblocks parsed via `phpstan/phpdoc-parser`. For framework-specific magic, rely on mapping rules defined in `LaravelContext.php`. Treat unresolvable types as black boxes.
**2. Line Numbers (Fix):** The parser must inject the original line number as a short tag (e.g., `L45|`) next to every line in the final LLM payload. This minimizes token usage (estimated 10-20% overhead, accounted for in the budget) while allowing the hallucination check to verify findings against the original boundaries.
**3. Max Depth:** Limit call tracing to a max depth of 3. Break immediately upon detecting circular references.
**4. Vendor Code:** Treat `vendor/` as a completely black box. Do not attempt to trace it.
**5. Payload Size & Splitting (Fix):** Merge up to ~8,000 tokens per prompt. If an execution path exceeds this, split the analysis. The tool programmatically extracts a summary of the Controller's validated input AND all upstream authorization checks (middleware, controller gates). It passes this structural auth/validation summary to the LLM alongside the Service class, avoiding false positives about "missing checks".

## 2. Framework Context Outside the Scanned Path

**6. Loading External Context (Fix):** Context extraction strictly uses AST parsing (and a YAML parser for Symfony). It covers:
   - **Laravel 8-10:** `app/Http/Kernel.php` (middleware).
   - **Laravel 11+:** `bootstrap/app.php` (middleware).
   - **Routes:** `routes/web.php`, `routes/api.php`, including route groups, `Route::resource`, and route model bindings.
   - **Internal Controller Middleware:** `$this->middleware()` (Laravel <= 10) and `HasMiddleware` (Laravel 11+).
   - **Symfony:** `#[IsGranted]` attributes and `security.yaml` `access_control` blocks.
**7. Discovery:** Auto-discover based on standard framework conventions, allowing overrides via `semantic-sec.yaml`.
**8. Missing Context:** If external context is unresolvable, the system prompt explicitly instructs the LLM: *"Assume authentication and basic authorization may be handled externally."*

## 3. Pruning Rules & Suppressions

**9. Low-Risk Code:** Strip empty constructors, basic getters/setters, simple array mapping, and debug statements (`dd()`, `var_dump`).
**10. Security Code Protection:** Maintain a default whitelist in the `Pruner` (`$this->authorize()`, `Gate::*`, `abort_if()`, `Auth::*`, `authorizeResource()`, `->can()`, `denyAccessUnlessGranted()`). Users can append custom security helpers in `semantic-sec.yaml`.
**11. Suppressions (Fix):** Inline suppressions (e.g., `// @semantic-sec-ignore IDOR: Handled by API gateway`) are collected before pruning. A suppression covers the immediately following method or line, and a reason string is highly recommended. They filter the final LLM findings.

## 4. LLM Provider & Data Privacy

**12. Providers & Models:** Support OpenAI, Anthropic, and local models. Default models are configurable in `semantic-sec.yaml`.
**13. Privacy & Local Models:** Include a `--dry-run` flag. Support Ollama, with explicit documentation warning that smaller local models struggle with long-context JSON. Implement basic redaction for string literals.
**14. API Keys:** Loaded via environment variables (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`).
**15. JSON Schemas:** Target provider-agnostic schemas. Use native Structured Outputs for OpenAI. For Anthropic, enforce JSON via a required Tool Call.

## 5. Cost, Performance & Caching

**16. Budgets (Fix):** Configurable token budget per run. If exceeded, abort with Exit Code 3. Any findings collected *before* the budget runs out are still outputted to the console and saved to the SARIF file.
**17. Caching (Fix):** Cache results using a compound SHA-256 hash of: the compiled AST payload, the LLM model version, the system prompt, active rulesets, **and all resolved external context** (routes, middleware, policies) applied to that path.
**18. CI Integration (Fix):** A `--since=<git-ref>` diff-only mode. The AST must parse the entire project to build the call graph, but only sends affected paths to the LLM. A changed route, middleware, or policy file will invalidate and re-check all controllers depending on it.
**19. Concurrency & Retries:** Run requests in parallel using Guzzle's async promises, capped at a concurrency of 5. Use Guzzle's native retry middleware for 429/5xx errors.

## 6. Result Reliability & Noise Control

**20. Non-Determinism:** Utilize `seed` and `temperature=0` as a best-effort baseline.
**21. Confidence Scores:** Every finding includes a `confidence` field (High, Medium, Low).
**22. Hallucination Checks:** Cross-reference returned file/line numbers against the original parsed AST map.
**23. Baselines & Deduplication (Fix):** Implement `--generate-baseline`. Findings are deduplicated and fingerprinted using `File + Method Name + CWE ID + Hash of the relevant AST nodes (ignoring whitespace/comments)`. This maps to SARIF `partialFingerprints` and prevents baseline churn when unrelated lines are edited.

## 7. CLI Behaviour

**24. Flags:** `--framework` acts as an explicit override.
**25. Exit Codes (Fix):**
    - `0` = Clean (or only baseline/suppressed findings).
    - `1` = Findings discovered at or above the `--level` threshold (this flag controls both what is reported and what fails the build).
    - `2` = Execution/Tool error.
    - `3` = Budget exceeded (partial results saved).
**26. Configuration:** Use a `semantic-sec.yaml` file in the project root.
**27. Formats:** `console` (human-readable), `json`, and `sarif`.

## 8. Vulnerability Model & SARIF

**28. Vulnerability Object:** Contains `title`, `cwe_id`, `severity`, `confidence`, `file`, `line`, `context_description`, `flaw_description`, `suggested_patch` (diff), and `execution_path`.
**29. Mapping & Flows:** Findings map to standard CWE IDs. Include `codeFlows` in the SARIF output to trace execution paths across files.

## 9. Scope & Rulesets

**30. Target Constraints:** The target codebase can be PHP 7.4+, but the Analyzer requires PHP 8.1+.
**31. Scope for v1:** Focus entirely on business logic flaws (IDOR, missing authorization, mass assignment, insecure deserialization, and state transition abuse). Ignore basic SQLi and XSS.
**32. Frameworks:** Laravel, Symfony, and plain PHP as a fallback.
**33. Custom Rulesets:** Allow users to define custom prompt rulesets in `semantic-sec.yaml` to teach the LLM about internal company conventions.

## 10. Testing & Quality

**34. Benchmarks:** The benchmark suite (`laravel-dvwa`) must include both deliberately vulnerable cases AND their patched, safe equivalents.
**35. False Positives:** Prioritize a low False Positive rate over a low False Negative rate for v1 to ensure developer trust.
**36. LLM Testing:** Use the VCR pattern (JSON fixtures) to unit test the orchestrator.

## 11. Packaging & Distribution

**37. Namespace:** `tusharkhan/semantic-sec` with a root namespace of `TusharKhan\SemanticSec\`.
**38. Distribution:** Distribute via Composer as a `require-dev` dependency for PHP 8.1+ projects. Provide a compiled PHAR file for PHP 7.4 projects and standalone execution. Document this clearly.
**39. Licence:** MIT License.
**40. Templates:** Ship with `github-actions.example.yml` and `.gitlab-ci.example.yml`.