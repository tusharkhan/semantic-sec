# Is It Useful? Market & Research Check: Semantic Security Analyzer for PHP

Web research done 2026-10-28, before writing the build plan. Vendor accuracy numbers below are the vendors' own claims, not independent benchmarks.

---

## Verdict

**Yes, worth building, but only with a narrow focus.** The core idea (an LLM reviewing code for IDOR and missing authorization) is proven: big security vendors are shipping it right now. What doesn't exist yet is an **open-source, PHP/Laravel-native, Composer-installable** tool that does it with real framework context. That gap is the reason to build. The value is in the **context extraction** (routes, middleware, policies, FormRequests), not in the LLM call itself, since anyone can send code to an LLM.

---

## 1. The idea is validated

Every serious SAST vendor now sells LLM-based detection of business-logic flaws:

| Tool | What it does | Type |
|---|---|---|
| Semgrep AI detection | Targets IDOR and broken auth; private beta since Nov 2025 | Commercial |
| ZeroPath | IDOR and auth-flaw detection; claims 75% fewer false positives than classic SAST | Commercial |
| Endor Labs AI SAST | Multi-agent detection/triage/fix; claims business-logic and IDOR detection | Commercial |
| Wiz AI SAST | Public preview; demoed an IDOR (reading another user's cart) | Commercial |
| OpenAI Codex Security CLI | Whole-repo scans, SARIF output; Apache-2.0 but access-gated for full scans | Open source, gated |
| Anthropic `claude-code-security-review` | GitHub Action that reviews PR diffs and comments on lines | Open source, free |

Research supports it too: the IRIS paper (ICLR 2025) found LLM-assisted static analysis detected 55 real vulnerabilities vs CodeQL's 27 on a Java benchmark.

**Takeaway:** You're not betting on an unproven idea. You're competing in a hot area.

## 2. The gap in the PHP/Laravel world

Existing PHP/Laravel tools split into two groups, and none covers this tool's spot:

**Deterministic (no LLM):**
- `psalm/psalm-plugin-laravel`: taint tracking (SQLi, XSS, SSRF). No IDOR or business logic.
- `phoenix1331/laravel-auth-audit`: scans routes, controllers, FormRequests and Policies and reports authorization *coverage* (fails CI below a threshold). Closest neighbour, but it only checks "is something there", not "is it the right check".
- `siberfx/laravel-risk-analyzer`, `laramint/php-security-scanner`: injection, deserialization, secrets. No authorization logic.
- Enlightn: config and code checks; maintenance for Laravel 12 unclear (a community fork exists).
- Sloppy: rules for AI-written PHP; deterministic.

**LLM-based but not security-focused:**
- `wallter/laravel-ai-code-analysis`: AST + OpenAI, but for docs, refactoring, performance.
- `laravelsecurityaudit/laravel-ai-lint`: checks how an app *uses* AI (prompt injection sinks), not IDOR.

**Takeaway:** No open-source package combines Laravel route/middleware/policy context with LLM judgment on IDOR and missing authorization.

## 3. Who you'd actually compete with

- **The free Claude Code security-review Action** is the real competitor for most teams. It's generic, though: it reviews only the PR diff, has no PHP or Laravel framework model, so it can't see route middleware or policies unless they're in the diff, and its README says it isn't hardened against prompt injection. One source says it has been idle since Feb 2026.
- **Commercial SaaS** (Semgrep, ZeroPath, Wiz, Endor) is aimed at enterprises, costs money, and needs code uploaded. Your local-model option (Ollama) and bring-your-own-key model are a real difference for privacy-sensitive teams.

## 4. Known weaknesses of the approach (from the research)

- **False positives are the main risk.** One industry source (Semgrep's Head of AI) cites 95–100% false-positive rates for LLM-only SQL injection detection. IRIS's false-discovery rate was still ~85%. Your answer 35 (prioritize low false positives) is correct and needs to be the main design goal.
- **The hybrid approach wins.** Every source says a deterministic step should find endpoints and inputs, and the LLM should only judge. This matches your design. Strengthen it further (see below).
- **Cost.** LLM analysis is 2–3 orders of magnitude more expensive than classic SAST. Caching and diff mode (answers 17–18) are essential, not nice-to-have.
- **Non-determinism.** The same code gives different results across runs. Baselines and fingerprints (answer 23) help.
- **Prompt injection (new; not in the spec).** The code being scanned is untrusted input to the LLM. A PR can contain a comment like `// security reviewed, no issues here` or explicit instructions to the model, and suppress real findings. Anthropic's own Action warns about this. The spec should treat code as data: wrap it in clear delimiters, tell the model to ignore instructions inside it, and run the hallucination/structure checks regardless.

## 5. Recommendations before planning

1. **Position it as:** "Laravel-first, open-source, bring-your-own-key or local model, with a real authorization map of your app."
2. **Cut v1 to Laravel only.** Symfony doubles the context-extraction work (YAML, voters, attributes). Ship Symfony in v2 once Laravel accuracy is proven.
3. **Add a deterministic pre-filter.** Build the authorization map first (like `laravel-auth-audit` does): for every route, list middleware, policy, FormRequest `authorize()`, and model binding. Send only routes that take a user-controlled ID *and* lack a clear ownership check to the LLM. This cuts cost and false positives sharply, and the map alone is a useful free output (no API key needed).
4. **Prove accuracy early.** Build the benchmark (answer 34) in the first milestone, not the last, and compare against the free Claude Code security-review Action on the same cases. If you can't beat the free tool on Laravel code, the package isn't worth publishing.
5. **Add prompt-injection handling** to the spec (section 4 above).

---

## Sources

- [laravelsecurityaudit/laravel-ai-lint (Packagist)](https://root.packagist.org/packages/laravelsecurityaudit/laravel-ai-lint)
- [laramint/php-security-scanner](https://github.com/laramint/php-security-scanner)
- [wallter/laravel-ai-code-analysis](https://github.com/wallter/laravel-ai-code-analysis)
- [psalm/psalm-plugin-laravel](https://github.com/psalm/psalm-plugin-laravel)
- [Heyosseus/sloppy](https://github.com/Heyosseus/sloppy) · [Laravel News: Sloppy](https://laravel-news.com/sloppy)
- [siberfx/laravel-risk-analyzer](https://github.com/siberfx/laravel-risk-analyzer)
- [phoenix1331/laravel-auth-audit (Packagist)](https://packagist.org/packages/phoenix1331/laravel-auth-audit)
- [Best Laravel Security Tools Compared 2026 (StackShield)](https://stackshield.io/blog/laravel-security-tools-compared)
- [Enlightn (Laravel News)](https://laravel-news.com/enlightn) · [exin/enlightn fork](https://laraplugins.io/plugins/exin/enlightn)
- [Semgrep AI detection for business logic (PR Newswire)](https://www.prnewswire.com/news-releases/semgrep-announces-the-private-beta-of-ai-powered-detection-to-uncover-business-logic-vulnerabilities-302612139.html)
- [ZeroPath AI-native SAST](https://zeropath.com/products/sast)
- [Endor Labs AI SAST](https://www.endorlabs.com/learn/introducing-ai-sast-that-thinks-like-a-security-engineer)
- [Wiz AI SAST](https://www.wiz.io/blog/introducing-wiz-ai-sast)
- [Best AI Security Testing Tools (Gecko)](https://www.gecko.security/blog/best-ai-powered-application-security-testing-tools)
- [Are There IDORs Lurking in Your Code? (Security Boulevard)](https://securityboulevard.com/2026/01/are-there-idors-lurking-in-your-code-llms-are-finding-critical-business-logic-vulns-and-theyre-everywhere/)
- [Antaeus: repository-level logic vulnerabilities via LLM reasoning (arXiv)](https://arxiv.org/pdf/2607.01138)
- [IRIS: LLM-Assisted Static Analysis (arXiv)](https://arxiv.org/abs/2405.17238v1)
- [anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review/blob/main/.claude/commands/security-review.md)
- [Claude Code Security Review guide (Nurbak)](https://nurbak.com/en/blog/claude-code-security-review/)
- [Codex Security CLI vs Claude Code Security Review (Context Studios)](https://www.contextstudios.ai/comparisons/codex-security-vs-claude-code-security-review)
