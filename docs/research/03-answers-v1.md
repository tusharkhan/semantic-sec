# Architectural Decisions & Answers: Semantic Security & Vulnerability Analyzer

## 1. Call Graph Resolution
**1. Dynamic Typing Resolution:** Degrade gracefully. Use constructor type hints, property types, and `@var`/`@return` docblocks. For framework-specific magic (like Laravel Facades or `app(Service::class)`), rely on mapping rules defined in `LaravelContext.php`. If a type cannot be resolved, treat it as a black box and omit it from the payload rather than guessing.
**2. Type Inference:** Do not bundle a heavy engine like PHPStan. Rely on basic AST resolution via `nikic/php-parser` and docblock parsing. 
**3. Max Depth:** Limit call tracing to a max depth of 3. Break immediately upon detecting circular references (recursion) to prevent infinite loops.
**4. Vendor Code:** Treat `vendor/` as a black box. Never trace into vendor code; assume third-party library methods execute securely unless explicitly flagged in a vulnerability database.
**5. Payload Size:** Merge up to ~8,000 tokens per prompt. If an execution path exceeds this, split the analysis by isolating the Controller logic first, then analyzing the Service class independently, passing the LLM a summary of the Controller's validated input.

## 2. Framework Context Outside the Scanned Path
**6. Loading External Context:** Yes, this is critical. If a Controller has no auth checks because a route middleware handles it, the LLM will hallucinate an IDOR vulnerability. The tool must parse route middleware and FormRequests.
**7. Discovery:** Auto-discover based on standard framework conventions (e.g., reading `routes/web.php` and `app/Http/Kernel.php` for Laravel). Allow overrides via a `semantic-sec.yaml` config file.
**8. Missing Context:** If external context is disabled or unresolvable, the system prompt must explicitly state: *"Assume authentication and basic authorization may be handled externally. Only flag missing checks if the business logic inherently demands localized validation."*

## 3. Pruning Rules
**9. Low-Risk Code:** Strip empty constructors, basic getters/setters with no logic, simple array mapping formatting methods, and debug statements (`dd()`, `var_dump`).
**10. Security Code Protection:** Maintain a hardcoded whitelist in the `Pruner` for methods like `$this->authorize()`, `Gate::*`, `abort_if()`, and `Auth::*`.
**11. Docblocks:** Keep type-hinting docblocks (`@param`, `@return`, `@var`). Strip descriptive text, `@author`, and `@since` to save tokens.

## 4. LLM Provider & Data Privacy
**12. Providers in v1:** Ship with support for OpenAI (GPT-4o) and Anthropic (Claude 3.5 Sonnet, which excels at code). 
**13. Privacy & Local Models:** Data privacy is paramount for SAST tools. Include a `--dry-run` flag that outputs the exact prompt to a local file. Support local models via Ollama for teams that cannot send proprietary code to the cloud. Implement a basic redaction pass for string literals that look like secrets/credentials.
**14. API Keys:** Loaded via environment variables (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`) to align with CI/CD best practices.
**15. Models & Schemas:** Target provider-agnostic JSON schema prompting. When using OpenAI, utilize their native Structured Outputs for guaranteed schema adherence; for Anthropic/Ollama, use strict system prompting with XML tags or JSON repair fallback.

## 5. Cost, Performance & Caching
**16. Budgets:** Implement a configurable token budget per run in the config file. Abort with a warning code when the budget is exceeded.
**17. Caching:** Cache results by creating a SHA-256 hash of the compiled AST payload. If the code and its dependencies haven't changed, reuse the previous LLM response.
**18. CI Integration:** A `--since=<git-ref>` diff-only mode is essential. In CI, it should only parse changed files and their immediate call-graph neighbors.
**19. Concurrency:** Run requests in parallel using Guzzle's asynchronous promises. Cap concurrency at 5 to avoid immediate rate-limiting from API providers.
**20. Retries:** Implement exponential backoff for HTTP 429 (Rate Limit) and 5xx errors via a PSR-18 middleware.

## 6. Result Reliability & Noise Control
**21. Non-Determinism:** Set `temperature` to 0 and utilize `seed` parameters where supported to guarantee as much consistency as possible between runs.
**22. Confidence Scores:** Every finding must include a `confidence` field (High, Medium, Low). 
**23. Hallucination Checks:** The `ResponseValidator` must cross-reference the LLM's returned file and line numbers against the original parsed AST. If the line doesn't exist or doesn't match the context, drop the finding.
**24. Baselines:** Implement a `--generate-baseline` command. Subsequent runs will ignore existing flaws and only fail on net-new vulnerabilities.
**25. Suppression:** Support inline comments like `// @semantic-sec-ignore IDOR: Handled by external microservice`. 
**26. Merging:** Deduplicate findings by hashing `File + Line Number + CWE ID`. 

## 7. CLI Behaviour
**27. Level Flag:** `--level` defines the minimum severity to report (e.g., `--level=high` reports High and Critical).
**28. Exit Codes:** `0` = Clean (or only suppressed/baseline findings), `1` = Findings discovered at or above the `--fail-on` threshold, `2` = Tool execution error.
**29. Framework Flag:** Auto-detect via `composer.json` dependencies.
**30. Configuration:** Use a `semantic-sec.yaml` file in the project root for paths, exclusions, API routing, and budgets.
**31. Formats:** `console` (human-readable), `json`, and `sarif` for GitHub/GitLab integration.

## 8. Vulnerability Model & SARIF
**32. Vulnerability Object:** `title`, `cwe_id`, `severity`, `confidence`, `file`, `line`, `context_description`, `flaw_description`, `suggested_patch` (diff format).
**33. CWE Mapping:** Findings must map to standard CWE IDs (e.g., CWE-284 for Improper Access Control) to integrate seamlessly with SARIF viewers.
**34. Code Flows:** Include `codeFlows` in the SARIF output. If a Controller calls a Service that contains the flaw, the SARIF UI should let the developer click through the execution path.
**35. Suggested Fixes:** Include a descriptive explanation AND a concrete code patch.

## 9. Scope & Rulesets
**36. PHP Versions:** Target codebase can be PHP 7.4+. The Analyzer itself requires PHP 8.1+ to run natively.
**37. Scope for v1:** Focus entirely on business logic flaws: IDOR, missing authorization, mass assignment, state transition abuse, and insecure deserialization.
**38. Taint Analysis:** Ignore basic SQLi and XSS. Let tools like Psalm or static SAST handle those. Focus purely on contextual logic.
**39. Frameworks:** Laravel and Symfony for v1. Plain PHP as a fallback (with reduced context awareness).
**40. Extensibility:** Allow users to define custom prompt rulesets in `semantic-sec.yaml` to teach the LLM about internal company conventions.

## 10. Testing & Quality
**41. Benchmarks:** Create a small, deliberately vulnerable Laravel test suite (e.g., `laravel-dvwa`) to measure accuracy.
**42. LLM Testing:** Use the VCR pattern (recording real API responses to JSON fixtures) to unit test the orchestrator without hitting the API on every test run.
**43. Thresholds:** Prioritize a low False Positive rate over a low False Negative rate for v1. High noise causes developers to uninstall security tools.

## 11. Packaging & Distribution
**44. Namespace:** `tusharkhan/semantic-sec` with a root namespace of `TusharKhan\SemanticSec\`.
**45. Distribution:** Distribute via Composer as a `require-dev` dependency, and provide a compiled PHAR file for standalone execution in CI/CD pipelines.
**46. Licence:** MIT License for maximum adoption.
**47. Templates:** Ship with `github-actions.example.yml` and `.gitlab-ci.example.yml` to make onboarding frictionless.