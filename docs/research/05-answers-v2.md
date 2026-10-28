# Architectural Decisions & Answers: Semantic Security & Vulnerability Analyzer (Revised)

## 1. Call Graph Resolution & Payload Construction

**1. Dynamic Typing Resolution:** Degrade gracefully. Use constructor type hints, property types, and `@var`/`@return` docblocks parsed via `phpstan/phpdoc-parser` (to avoid writing a custom docblock parser). For framework-specific magic, rely on mapping rules defined in `LaravelContext.php`. Treat unresolvable types as black boxes.
**2. Line Numbers (Fix):** Because the Pruner modifies the AST, the parser must inject the original `file:line` as a comment or metadata tag next to every line in the final LLM payload. The hallucination check will only accept findings if the returned line number falls within the reported method's original boundary.
**3. Max Depth:** Limit call tracing to a max depth of 3. Break immediately upon detecting circular references.
**4. Vendor Code:** Treat `vendor/` as a completely black box. Do not attempt to trace it or cross-reference vulnerability databases (leave that to `composer audit`).
**5. Payload Size & Splitting (Fix):** Merge up to ~8,000 tokens per prompt. If an execution path exceeds this, split the analysis. The tool will programmatically extract a summary of the Controller's validated input (e.g., by parsing `FormRequest::rules()` via the AST) and pass that structural summary to the LLM alongside the Service class, avoiding extra LLM calls.

## 2. Framework Context Outside the Scanned Path

**6. Loading External Context (Fix):** Context extraction strictly uses AST parsing to avoid unsafe code execution (no `php artisan route:list`). The parser handles modern framework structures, including Laravel 11's `bootstrap/app.php` (middleware), `routes/web.php`, `routes/api.php`, FormRequests, and Symfony's `#[IsGranted]` attributes.
**7. Discovery:** Auto-discover based on standard framework conventions, allowing overrides via `semantic-sec.yaml`.
**8. Missing Context:** If external context is unresolvable, the system prompt explicitly instructs the LLM: *"Assume authentication and basic authorization may be handled externally. Only flag missing checks if the business logic inherently demands localized validation."*

## 3. Pruning Rules & Suppressions

**9. Low-Risk Code:** Strip empty constructors, basic getters/setters with no logic, simple array mapping, and debug statements (`dd()`, `var_dump`).
**10. Security Code Protection (Fix):** Maintain a default whitelist in the `Pruner` for methods like `$this->authorize()`, `Gate::*`, `abort_if()`, `Auth::*`, `authorizeResource()`, `->can()`, and Symfony's `denyAccessUnlessGranted()`. Users can append custom security helpers (e.g., `$user->ownsOrFail()`) to this whitelist in `semantic-sec.yaml`.
**11. Suppressions (Fix):** Inline suppressions (e.g., `// @semantic-sec-ignore IDOR`) are collected during the initial parsing phase *before* the Pruner strips comments. They are stored in memory and applied to filter the final LLM findings.

## 4. LLM Provider & Data Privacy

**12. Providers & Models (Fix):** Support OpenAI, Anthropic, and local models. Default models are configurable in `semantic-sec.yaml` rather than hardcoded, ensuring future-proofing.
**13. Privacy & Local Models (Fix):** Include a `--dry-run` flag. Support Ollama for local execution, with explicit documentation warning that smaller local models struggle with long-context JSON and will yield lower-quality results. Implement basic redaction for string literals resembling secrets.
**14. API Keys:** Loaded via environment variables (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`).
**15. JSON Schemas (Fix):** Target provider-agnostic JSON schemas. Use native Structured Outputs for OpenAI. For Anthropic, enforce JSON by defining a required Tool Call with the strict input schema, which is more reliable than XML tags.

## 5. Cost, Performance & Caching

**16. Budgets (Fix):** Implement a configurable token budget per run. If exceeded, the tool aborts with Exit Code 3.
**17. Caching (Fix):** Cache results using a compound SHA-256 hash of the compiled AST payload, the LLM model version, the system prompt version, and the active rulesets. 
**18. CI Integration:** A `--since=<git-ref>` diff-only mode parses only changed files and their immediate call-graph neighbors.
**19. Concurrency & Retries (Fix):** Run requests in parallel utilizing Guzzle's asynchronous promises and Guzzle's native retry middleware for 429/5xx errors (abandoning PSR-18 compatibility for the async HTTP layer, as PSR-18 is strictly synchronous).

## 6. Result Reliability & Noise Control

**20. Non-Determinism (Fix):** Utilize `seed` and `temperature=0` configurations as a best-effort baseline, acknowledging that some modern models ignore or loosely interpret these parameters.
**21. Confidence Scores:** Every finding must include a `confidence` field (High, Medium, Low). 
**22. Hallucination Checks:** Cross-reference the LLM's returned file/line numbers against the original parsed AST map.
**23. Baselines (Fix):** Implement a `--generate-baseline` command. Findings are fingerprinted using `File + Method Name + CWE ID + Hash of the relevant code block` (mapped to SARIF `partialFingerprints`) so that adding unrelated lines above a vulnerability does not break the baseline. 

## 7. CLI Behaviour

**24. Flags:** `--level` defines the minimum severity. `--framework` acts as an explicit override (crucial for monorepos where auto-detection fails).
**25. Exit Codes (Fix):** `0` = Clean, `1` = Findings at or above threshold, `2` = Execution error, `3` = Budget exceeded/aborted.
**26. Configuration:** Use a `semantic-sec.yaml` file in the project root.
**27. Formats:** `console` (human-readable), `json`, and `sarif`.

## 8. Vulnerability Model & SARIF

**28. Mapping & Flows:** Findings must map to standard CWE IDs. Include `codeFlows` in the SARIF output to trace execution paths across files.
**29. Fixes:** Include a descriptive explanation and a concrete code patch diff.

## 9. Scope & Rulesets

**30. Target Constraints (Fix):** The target codebase can be PHP 7.4+, but the Analyzer requires PHP 8.1+. The documentation and CI templates must explicitly instruct PHP 7.4 projects to run the tool via the compiled PHAR rather than installing it as a Composer dev dependency.
**31. Scope for v1:** Focus entirely on business logic flaws (IDOR, missing authorization, mass assignment). Ignore basic SQLi and XSS (leave to traditional SAST).

## 10. Testing & Quality

**32. Benchmarks (Fix):** The benchmark suite (`laravel-dvwa`) must include both deliberately vulnerable cases AND their patched, safe equivalents to accurately measure and minimize the False Positive rate.
**33. LLM Testing:** Use the VCR pattern (JSON fixtures) to unit test the orchestrator without hitting the API.