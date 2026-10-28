# Review Findings: Architectural Decisions (Revised)

Review of `architectural_decisions_answers (1).md`. The revision fixes all 18 findings from `architectural_decisions_review_findings.md`, and the tradeoffs chosen (AST parsing instead of `artisan`, exit code 3, Guzzle without PSR-18) are reasonable. It introduces one contradiction, and a few things went missing between versions.

---

## Contradiction

### 1. Older Laravel isn't covered (answers 6 and 30)
Answer 30 supports PHP 7.4 codebases, which means Laravel 8–10. Those versions register middleware in `app/Http/Kernel.php`, but answer 6 lists only Laravel 11's `bootstrap/app.php`.
**Fix:** Parse both.

---

## Gaps that will cause false positives

### 2. The cache can return a stale "safe" result (answer 17)
If someone removes `auth` middleware from a route, the controller's code hasn't changed. Unless the hashed payload includes the route, middleware and policy context, the cache hands back the old result.
**Fix:** State explicitly that this context is part of the hashed payload.

### 3. Splitting a long path drops the auth checks (answer 5)
The Service is analysed with only the FormRequest validation summary. The controller's `authorize()` calls and the route middleware are left out, so the LLM reports "no ownership check".
**Fix:** Pass the upstream auth checks along with the validation summary.

### 4. Route parsing is still thin (answer 6)
It needs to cover:
- route groups that apply middleware
- `Route::resource`
- route model binding
- middleware set inside controllers (`$this->middleware()` up to Laravel 10, `HasMiddleware` in 11+)
- Symfony's `security.yaml` `access_control`, which is YAML rather than PHP, so the PHP syntax tree won't see it

### 5. Diff mode needs callers as well as callees (answer 18)
Finding who calls a changed Service method means parsing the whole project; only the LLM calls can be limited to the diff. A changed route, middleware or policy file should also re-check the controllers that depend on it.

---

## Left out of the revision

### 6. Items from the first version that are now missing
Say whether each was dropped on purpose:
- the `Vulnerability` field list, which the ResponseValidator schema depends on
- deduplication rules
- **Section 11 (packaging):** namespace, PHAR, licence and CI templates, even though answer 30 still mentions the PHAR and the CI templates
- custom prompt rulesets
- framework list (Laravel, Symfony, plain PHP)
- "low false positives over low false negatives"
- the concurrency cap of 5
- insecure deserialization and state transitions in the v1 scope

### 7. The threshold for exit code 1 is undefined (answer 25)
It says "at or above threshold", but `--fail-on` is gone.
**Decision needed:** Does `--level` control both what's shown and what fails the build?

### 8. Exit code 3 output isn't defined
When the budget runs out mid-scan, say whether the findings collected so far still go to the output and SARIF file.

---

## Minor

- **Suppression scope (answer 11).** Define what a suppression comment covers (the next line, the method or the file), and consider requiring a reason.
- **Baseline fingerprint (answer 23).** Editing any line inside the vulnerable method changes the code hash and re-flags the finding. Hash the code with whitespace and comments removed to reduce churn.
- **Line tags cost tokens (answer 2).** Tagging every line adds roughly 10–20% to each payload. Use a short form like `L45|` and include it in the 8,000-token budget.
