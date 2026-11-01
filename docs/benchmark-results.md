# Benchmark results

Mode: replay of recorded cassettes · Model: claude-opus-5-5 · Prompt v2 · Date: 2026-11-01

Apps: laravel10-app, laravel11-app, laravel12-app. Scored at `--level low` with every confidence; "failing" means confidence medium or high.

## Gate

| Criterion | Threshold | existing | blind | all |
|---|---|---|---|---|
| Vulnerable variants found at the right symbol | ≥ 70% | 100.0% (15/15) PASS | 80.0% (8/10) PASS | 92.0% (23/25) PASS |
| Found, strict (no post-hoc accepts) | ≥ 70% | 86.7% (13/15) | 80.0% (8/10) | 84.0% (21/25) |
| Safe variants flagged | ≤ 10% | 0.0% (0/15) PASS | 10.0% (1/10) PASS | 4.0% (1/25) PASS |
| Findings in safe code that no case accounts for | 0 | 0 PASS | 0 PASS | 0 PASS |
| Findings on public-by-design routes | 0 | 0/1 routes hit PASS | 0/1 routes hit PASS | 0/2 routes hit PASS |
| Expected authorization checks in the map | 100% | 100.0% (30/30) PASS | 95.0% (19/20) FAIL | 98.0% (49/50) FAIL |
| **Gate** | | **PASS** | **FAIL** | **FAIL** |

## Gate, failing findings only

| Criterion | Threshold | existing | blind | all |
|---|---|---|---|---|
| Vulnerable variants found at the right symbol | ≥ 70% | 100.0% (15/15) PASS | 80.0% (8/10) PASS | 92.0% (23/25) PASS |
| Found, strict (no post-hoc accepts) | ≥ 70% | 86.7% (13/15) | 80.0% (8/10) | 84.0% (21/25) |
| Safe variants flagged | ≤ 10% | 0.0% (0/15) PASS | 0.0% (0/10) PASS | 0.0% (0/25) PASS |
| Findings in safe code that no case accounts for | 0 | 0 PASS | 0 PASS | 0 PASS |
| Findings on public-by-design routes | 0 | 0/1 routes hit PASS | 0/1 routes hit PASS | 0/2 routes hit PASS |
| Expected authorization checks in the map | 100% | 100.0% (30/30) PASS | 95.0% (19/20) FAIL | 98.0% (49/50) FAIL |
| **Gate** | | **PASS** | **FAIL** | **FAIL** |

## Selection stage

Whether each route reached the LLM for the case's category. A missed vulnerable case whose route was not selected was never sent to the LLM; one that was selected is an LLM miss.

| Case | Set | Variant | Route | Expected | Actual |
|---|---|---|---|---|---|
| idor-tenant-list-unscoped | blind | vulnerable | `GET /vuln/tickets` | selected for idor | not selected |
| idor-policy-wrong-attribute | blind | safe | `POST /safe/withdrawals/{withdrawal}/approve` | not selected (candidate: false) | selected for idor, workflow_bypass |

## Per app

### laravel10-app

| Set | Cases | Found | Found (failing) | Safe flagged | Safe flagged (failing) | Unattributed safe-code findings | Public violations | Map mismatches |
|---|---|---|---|---|---|---|---|---|
| existing | 2 | 2 | 2 | 0 | 0 | 0 | 0/0 | 0/4 |
| all | 2 | 2 | 2 | 0 | 0 | 0 | 0/0 | 0/4 |

### laravel11-app

| Set | Cases | Found | Found (failing) | Safe flagged | Safe flagged (failing) | Unattributed safe-code findings | Public violations | Map mismatches |
|---|---|---|---|---|---|---|---|---|
| existing | 13 | 13 | 13 | 0 | 0 | 0 | 0/1 | 0/26 |
| all | 13 | 13 | 13 | 0 | 0 | 0 | 0/1 | 0/26 |

### laravel12-app

| Set | Cases | Found | Found (failing) | Safe flagged | Safe flagged (failing) | Unattributed safe-code findings | Public violations | Map mismatches |
|---|---|---|---|---|---|---|---|---|
| blind | 10 | 8 | 8 | 1 | 0 | 0 | 0/1 | 1/20 |
| all | 10 | 8 | 8 | 1 | 0 | 0 | 0/1 | 1/20 |

## Cases

| Case | Set | App | Category | Vulnerable | Deciding finding | Safe | Deciding finding | Map | Selected |
|---|---|---|---|---|---|---|---|---|---|
| idor-find-by-id | existing | laravel11-app | idor | found | idor high · `app/Http/Controllers/Vuln/InvoiceController.php:19` · `App\Http\Controllers\Vuln\InvoiceController::show` · IDOR: any authenticated user can read any invoice by ID | clean |  | ok | vulnerable: selected for idor; safe: not selected |
| idor-binding-authorize | existing | laravel11-app | idor | found | idor high · `app/Http/Controllers/Vuln/InvoiceController.php:26` · `App\Http\Controllers\Vuln\InvoiceController::update` · Any authenticated user can update any invoice via route-bound {invoice} with no ownership check | clean |  | ok | vulnerable: selected for idor, missing_authorization; safe: not selected |
| idor-route-can-middleware | existing | laravel11-app | idor | found | idor high · `app/Http/Controllers/Vuln/InvoiceController.php:33` · `App\Http\Controllers\Vuln\InvoiceController::pdf` · Invoice PDF download via route-bound {invoice} with no ownership or policy check | clean |  | ok | vulnerable: selected for idor; safe: not selected |
| idor-form-request | existing | laravel11-app | idor | found | idor high · `app/Http/Controllers/Vuln/ProjectController.php:14` · `App\Http\Controllers\Vuln\ProjectController::update` · IDOR: any authenticated user can update any Project via route-bound {project} | clean |  | ok | vulnerable: selected for idor, missing_authorization; safe: not selected |
| idor-trivial-policy | existing | laravel11-app | idor | found (post-hoc accept) | idor high · `app/Policies/CommentPolicy.php:12` · `App\Policies\CommentPolicy::delete` · CommentPolicy::delete always returns true, letting any logged-in user delete any comment | clean |  | ok | vulnerable: selected for idor, missing_authorization; safe: not selected |
| idor-has-middleware | existing | laravel11-app | idor | found | idor high · `app/Http/Controllers/Vuln/DocumentController.php:22` · `App\Http\Controllers\Vuln\DocumentController::show` · IDOR: any authenticated user can read any Document via route model binding | clean |  | ok | vulnerable: selected for idor; safe: not selected |
| idor-service-layer | existing | laravel11-app | idor | found (post-hoc accept) | idor high · `app/Services/DownloadService.php:11` · `App\Services\DownloadService::find` · IDOR: any authenticated user can download any Download record by id | clean |  | ok | vulnerable: selected for idor; safe: not selected |
| mass-assign-guarded-empty | existing | laravel11-app | mass_assignment | found | mass_assignment high · `app/Http/Controllers/Vuln/AccountController.php:14` · `App\Http\Controllers\Vuln\AccountController::update` · Mass assignment: unvalidated $request->all() written to Account, which has $guarded = [] | clean |  | ok | vulnerable: selected for mass_assignment; safe: not selected |
| mass-assign-sensitive-fillable | existing | laravel11-app | mass_assignment | found | mass_assignment high · `app/Http/Controllers/Vuln/TeamController.php:14` · `App\Http\Controllers\Vuln\TeamController::store` · Mass assignment of owner_id in Team::create via $request->all() | clean |  | ok | vulnerable: selected for missing_authorization, mass_assignment; safe: not selected |
| insecure-deserialization-cookie | existing | laravel11-app | insecure_deserialization | found | insecure_deserialization high · `app/Http/Controllers/Vuln/CartController.php:13` · `App\Http\Controllers\Vuln\CartController::restore` · unserialize() on client-controlled 'cart' cookie enables PHP object injection | clean |  | ok | vulnerable: selected for insecure_deserialization; safe: not selected |
| workflow-refund-any-status | existing | laravel11-app | workflow_bypass | found | workflow_bypass high · `app/Http/Controllers/Vuln/OrderController.php:18` · `App\Http\Controllers\Vuln\OrderController::refund` · Order refund applies without checking the order's current status (unpaid, shipped or already refunded) | clean |  | ok | vulnerable: selected for workflow_bypass; safe: not selected |
| prompt-injection-comment | existing | laravel11-app | idor | found | idor high · `app/Http/Controllers/Vuln/ReceiptController.php:18` · `App\Http\Controllers\Vuln\ReceiptController::show` · IDOR: any authenticated user can read any receipt via unscoped Receipt::findOrFail($id) | clean |  | ok | vulnerable: selected for idor; safe: not selected |
| suppressed-idor | existing | laravel11-app | idor | found (suppressed) | idor high · `app/Http/Controllers/Vuln/SharedInvoiceController.php:15` · `App\Http\Controllers\Vuln\SharedInvoiceController::show` · IDOR: any authenticated user can read any invoice via Invoice::findOrFail($id) (suppressed) | clean |  | ok | vulnerable: selected for idor; safe: not selected |
| idor-l10-ctor-middleware | existing | laravel10-app | idor | found | idor high · `app/Http/Controllers/Vuln/ReportController.php:18` · `App\Http\Controllers\Vuln\ReportController::show` · IDOR: any authenticated user can read any Report via route model binding | clean |  | ok | vulnerable: selected for idor; safe: not selected |
| idor-l10-resource | existing | laravel10-app | idor | found | idor high · `app/Http/Controllers/Vuln/NoteController.php:29` · `App\Http\Controllers\Vuln\NoteController::show` · IDOR: any authenticated user can read any note via unscoped Note::find($id) | clean |  | ok | vulnerable: selected for idor; safe: not selected |
| idor-role-only-middleware | blind | laravel12-app | idor | found | idor high · `app/Http/Controllers/Vuln/PayoutController.php:13` · `App\Http\Controllers\Vuln\PayoutController::index` · Any merchant can list another store's payouts (amounts, IBANs) via route-bound {store} | clean |  | ok | vulnerable: selected for idor; safe: selected for idor |
| idor-nested-unscoped-binding | blind | laravel12-app | idor | found | idor high · `app/Http/Controllers/Vuln/TeamProjectController.php:17` · `App\Http\Controllers\Vuln\TeamProjectController::show` · Nested project fetched without checking it belongs to the authorized team (IDOR) | clean |  | safe: expected [authentication, controller_ability], got [authentication, controller_ability, query_scope] | vulnerable: selected for idor; safe: not selected |
| idor-tenant-list-unscoped | blind | laravel12-app | idor | missed: never sent to the LLM |  | clean |  | ok | vulnerable: not selected; safe: not selected |
| idor-with-trashed-restore | blind | laravel12-app | idor | found | idor high · `app/Http/Controllers/Vuln/ContactController.php:14` · `App\Http\Controllers\Vuln\ContactController::restore` · IDOR: any authenticated user can restore any soft-deleted Contact by id | clean |  | ok | vulnerable: selected for idor, missing_authorization; safe: not selected |
| idor-polymorphic-parent-check | blind | laravel12-app | idor | found | idor medium · `app/Http/Controllers/Vuln/ReviewController.php:17` · `App\Http\Controllers\Vuln\ReviewController::update` · Review update authorizes against the parent reviewable instead of the review, allowing edits to others' reviews | clean |  | ok | vulnerable: selected for idor; safe: not selected |
| idor-update-unscoped-relation | blind | laravel12-app | idor | found | idor high · `app/Http/Controllers/Vuln/AddressController.php:20` · `App\Http\Controllers\Vuln\AddressController::update` · IDOR: any authenticated user can update any Address by id | clean |  | ok | vulnerable: selected for idor, missing_authorization; safe: not selected |
| idor-policy-wrong-attribute | blind | laravel12-app | idor | missed: LLM missed it |  | flagged (low confidence) | workflow_bypass low · `app/Http/Controllers/Safe/WithdrawalController.php:16` · `App\Http\Controllers\Safe\WithdrawalController::approve` · Withdrawal approval has no status guard: rejected, cancelled or already-approved withdrawals can be re-approved | ok | vulnerable: selected for idor, workflow_bypass; safe: selected for idor, workflow_bypass |
| mass-assign-force-fill | blind | laravel12-app | mass_assignment | found | mass_assignment high · `app/Http/Controllers/Vuln/ProfileController.php:18` · `App\Http\Controllers\Vuln\ProfileController::update` · Profile update forceFills all request input except password onto User, allowing role/admin escalation | clean |  | ok | vulnerable: selected for missing_authorization, mass_assignment; safe: not selected |
| workflow-cancel-shipped-service | blind | laravel12-app | workflow_bypass | found | workflow_bypass high · `app/Services/OrderService.php:11` · `App\Services\OrderService::cancel` · Order can be cancelled in any state (e.g. shipped/delivered/already cancelled) – no status guard | clean |  | ok | vulnerable: selected for workflow_bypass; safe: selected for workflow_bypass |
| idor-query-string-user-id | blind | laravel12-app | idor | found | idor high · `app/Http/Controllers/Vuln/StatementController.php:16` · `App\Http\Controllers\Vuln\StatementController::index` · Statements of any user readable via user-supplied user_id query parameter | clean |  | ok | vulnerable: selected for idor; safe: not selected |

## Unattributed safe-code findings

Findings under a `Safe/` path or a `\Safe\` namespace that no case or public route accounts for. Each one is a false positive and fails the gate. An app whose cases span both sets counts them under "all" only.

None.

## Public routes

| App | Set | Route | Symbol | Result | Deciding finding |
|---|---|---|---|---|---|
| laravel11-app | existing | `GET /posts/{post:slug}` | `App\Http\Controllers\PostController::show` | clean |  |
| laravel12-app | blind | `GET /stores/{store:slug}` | `App\Http\Controllers\StorefrontController::show` | clean |  |

## Run cost

Tokens as the provider reported them in the recorded responses. A replay re-reads the recording, so these are the cost of the live run that made it.

| Requests | Input | Cache write | Cache read | Output | Estimated $ |
|---|---|---|---|---|---|
| 31 | 18,463 | 10,272 | 69,336 | 22,139 | $0.58 |

Priced as claude-opus-5-5: $4.00/M input, $20.00/M output, $0.20/M cache read, $5.00/M cache write (1.25x input).

## Competitive check

_Not run yet._ M8 Task 5 scores Anthropic's `claude-code-security-review` on the same code with this scorer and records its numbers and every asymmetry here.
