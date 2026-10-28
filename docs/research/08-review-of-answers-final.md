# Review Findings: Architectural Decisions (Finalized)

Review of `architectural_decisions_answers (2).md`. Every finding from `architectural_decisions_revised_review_findings.md` is resolved. The document is ready to build from. The items below are small and can be settled while writing the build plan.

---

## Remaining gaps

### 1. Policies and FormRequest `authorize()` are never parsed (answer 6)
Answers 17 and 18 cache and re-check on "routes, middleware, policies", but the extraction list in answer 6 has no policies (`app/Policies`, `AuthServiceProvider` / auto-discovery) and no `FormRequest::authorize()`. The first version listed FormRequests; this one doesn't. A controller protected only by a policy or `FormRequest::authorize()` would be reported as missing authorization.
**Fix:** Add both to answer 6.

### 2. Fingerprint assumes every finding is inside a method (answer 23)
Mass assignment usually shows up at class level (`protected $guarded = [];` on a model), where there is no method name.
**Fix:** Fall back to the property or class name when there is no method.

### 3. Exit code when the budget runs out and findings exist (answer 25)
If the run hits the budget after finding issues at or above `--level`, it's unclear whether it exits with `1` or `3`.
**Decision needed:** Pick which wins (suggest `1`, since real findings matter more than an incomplete scan; CI fails either way).

### 4. No default for `--level` (answers 24–25)
Since `--level` now also decides what fails the build, its default matters. If it defaults to `low`, every finding breaks CI on the first run.
**Decision needed:** Set a default (suggest `high`).

---

## Minor

- **Low-confidence findings and the build (answers 21 and 35).** Given the low-false-positive priority, consider not failing the build on `Low` confidence findings (still report them), or add a `--min-confidence` option.
- **Suppression scope wording (answer 11).** "The immediately following method or line" is clear in practice, but state the rule: above a method signature it covers the whole method, otherwise the next statement.
