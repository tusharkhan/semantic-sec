# Review Findings: Architectural Decisions

Review of `architectural_decisions_answers.md`. The answers hold together and settle almost every question. These are the remaining problems, roughly most important first.

---

## Will break if built as written

### 1. Line numbers after pruning (answers 9–11 and 23)
The Pruner removes code and the call tracer merges several files into one payload, so the LLM never sees the original line numbers. The hallucination check in answer 23 will then drop real findings or keep wrong ones.
**Fix:** Put the original `file:line` next to every line in the payload, and only accept a finding if its line falls inside the method it names.

### 2. Suppression comments get stripped (answers 25 and 11)
The Pruner removes comments before the LLM sees the code, so `// @semantic-sec-ignore` has to be read *before* pruning, in the parsing step.
**Fix:** State the order explicitly — collect suppressions during parsing, apply them after findings return.

### 3. Baseline breaks on any edit (answers 24 and 26)
Matching findings by `File + Line + CWE` means adding one line above a known finding makes it look new, and CI fails.
**Fix:** Match on `file + method name + CWE + hash of the relevant code` instead, and output it as SARIF `partialFingerprints` so GitHub tracks findings the same way.

### 4. Two HTTP approaches that don't fit together (answers 19 and 20)
PSR-18 is a synchronous interface, so Guzzle's async promises can't run through it.
**Fix:** Use Guzzle's own retry middleware and skip PSR-18.

### 5. PHP 7.4 projects can't install the package (answer 36)
Composer won't install a dev dependency that requires PHP 8.1 into a 7.4 project. Those users must use the PHAR.
**Fix:** Say so in the docs and CI templates.

### 6. Cache key is too narrow (answer 17)
Hashing only the code payload means changing the model, the system prompt, or a ruleset still returns old cached answers.
**Fix:** Include model, system prompt, and ruleset versions in the key.

---

## Underspecified

### 7. Laravel routes (answer 7)
`app/Http/Kernel.php` no longer exists in Laravel 11+; middleware moved to `bootstrap/app.php`, and routes also live in `routes/api.php`. Reading routes from the syntax tree also has to handle route groups, `Route::resource`, middleware set inside controllers, and Symfony's `#[IsGranted]` attributes. The alternative is `php artisan route:list --json`, which is accurate but needs a working copy of the app.
**Decision needed:** pick AST parsing or artisan.

### 8. Who writes the summary in answer 5?
Splitting a long path needs "a summary of the Controller's validated input". Say whether the tool builds that from the code (FormRequest rules) or makes an extra LLM call for it.

### 9. The auth whitelist is fixed in code (answer 10)
Real apps use their own helpers (`$user->ownsOrFail()`, traits, policy scopes). If one gets pruned, you get false IDOR reports, which goes against answer 43's "low noise first".
**Fix:** Let users add to the whitelist in `semantic-sec.yaml`, and include `authorizeResource`, `->can()`, and Symfony's `denyAccessUnlessGranted`/`isGranted`.

### 10. Budget exceeded has no exit code (answer 16)
Answer 28 defines only 0, 1, and 2.
**Fix:** Either use 2 or add 3 for an aborted scan.

### 11. "Vulnerability database" for vendor code (answer 4) isn't defined
**Fix:** Either drop it or point it at `composer audit`.

---

## Smaller points

- **Model names (answer 12).** GPT-4o and Claude 3.5 Sonnet are old. Make the model a config setting with current defaults.
- **JSON from Anthropic (answer 15).** Forcing a tool call with an input schema is more reliable than XML tags plus repairing broken JSON.
- **Determinism (answer 21).** `seed` only exists on OpenAI, and some newer models refuse `temperature`, so treat both as best-effort.
- **Local models (answer 13).** Ollama models do noticeably worse at long-context JSON. Document that results will be lower quality.
- **Keep `--framework` (answer 29)** as an override even with auto-detection, because detection fails on monorepos.
- **Benchmark (answer 41).** Add safe versions of each vulnerable case. Without them you can't measure the false-positive rate that answer 43 puts first.
- **Docblock parsing (answer 2).** `phpstan/phpdoc-parser` is a small library for this and avoids writing your own parser.
