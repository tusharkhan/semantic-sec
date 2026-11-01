# Benchmark results

Mode: replay of recorded cassettes · Model: claude-opus-5-5 · Prompt v3 · Date: 2026-11-01

Source: disguised copy (`Vuln`/`Safe` renamed to `Alpha`/`Beta`, findings mapped back through the disguise map). The gate below is the result; the run on `benchmark/` itself follows as a secondary table.

Apps: laravel10-app, laravel11-app, laravel12-app. Scored at `--level low` with every confidence; "failing" means confidence medium or high.

Tuned-on cases: idor-policy-wrong-attribute. The scanner was tuned knowing these cases, so they are no longer blind for the pattern they show; they are marked `(tuned-on)` in the cases table.

## Gate

| Criterion | Threshold | existing | blind | holdout | all |
|---|---|---|---|---|---|
| Vulnerable variants found at the right symbol | ≥ 70% | 100.0% (15/15) PASS | 90.0% (9/10) PASS | 83.3% (5/6) PASS | 93.5% (29/31) PASS |
| Found, strict (no post-hoc accepts) | ≥ 70% | 86.7% (13/15) | 90.0% (9/10) | 83.3% (5/6) | 87.1% (27/31) |
| Safe variants flagged | ≤ 10% | 0.0% (0/15) PASS | 10.0% (1/10) PASS | 33.3% (2/6) FAIL | 9.7% (3/31) PASS |
| Findings in safe code that no case accounts for | 0 | 0 PASS | 0 PASS | 0 PASS | 0 PASS |
| Findings on public-by-design routes | 0 | 0/1 routes hit PASS | 0/1 routes hit PASS | 0/0 routes hit n/a | 0/2 routes hit PASS |
| Expected authorization checks in the map | 100% | 100.0% (30/30) PASS | 100.0% (20/20) PASS | 83.3% (10/12) FAIL | 96.8% (60/62) FAIL |
| **Gate** | | **PASS** | **PASS** | **FAIL** | **FAIL** |

## Gate, failing findings only

| Criterion | Threshold | existing | blind | holdout | all |
|---|---|---|---|---|---|
| Vulnerable variants found at the right symbol | ≥ 70% | 100.0% (15/15) PASS | 90.0% (9/10) PASS | 66.7% (4/6) FAIL | 90.3% (28/31) PASS |
| Found, strict (no post-hoc accepts) | ≥ 70% | 86.7% (13/15) | 90.0% (9/10) | 66.7% (4/6) | 83.9% (26/31) |
| Safe variants flagged | ≤ 10% | 0.0% (0/15) PASS | 0.0% (0/10) PASS | 0.0% (0/6) PASS | 0.0% (0/31) PASS |
| Findings in safe code that no case accounts for | 0 | 0 PASS | 0 PASS | 0 PASS | 0 PASS |
| Findings on public-by-design routes | 0 | 0/1 routes hit PASS | 0/1 routes hit PASS | 0/0 routes hit n/a | 0/2 routes hit PASS |
| Expected authorization checks in the map | 100% | 100.0% (30/30) PASS | 100.0% (20/20) PASS | 83.3% (10/12) FAIL | 96.8% (60/62) FAIL |
| **Gate** | | **PASS** | **PASS** | **FAIL** | **FAIL** |

## Gate, undisguised (names visible)

Secondary only: the same scorer on the recorded run over `benchmark/`, where `Vuln`/`Safe` show in paths, namespaces and routes.

| Criterion | Threshold | existing | blind | holdout | all |
|---|---|---|---|---|---|
| Vulnerable variants found at the right symbol | ≥ 70% | 100.0% (15/15) PASS | 90.0% (9/10) PASS | 83.3% (5/6) PASS | 93.5% (29/31) PASS |
| Found, strict (no post-hoc accepts) | ≥ 70% | 86.7% (13/15) | 90.0% (9/10) | 83.3% (5/6) | 87.1% (27/31) |
| Safe variants flagged | ≤ 10% | 0.0% (0/15) PASS | 10.0% (1/10) PASS | 0.0% (0/6) PASS | 3.2% (1/31) PASS |
| Findings in safe code that no case accounts for | 0 | 0 PASS | 0 PASS | 0 PASS | 0 PASS |
| Findings on public-by-design routes | 0 | 0/1 routes hit PASS | 0/1 routes hit PASS | 0/0 routes hit n/a | 0/2 routes hit PASS |
| Expected authorization checks in the map | 100% | 100.0% (30/30) PASS | 100.0% (20/20) PASS | 83.3% (10/12) FAIL | 96.8% (60/62) FAIL |
| **Gate** | | **PASS** | **PASS** | **FAIL** | **FAIL** |

## Selection stage

Whether each route reached the LLM for the case's category. A missed vulnerable case whose route was not selected was never sent to the LLM; one that was selected is an LLM miss.

| Case | Set | Variant | Route | Expected | Actual |
|---|---|---|---|---|---|
| idor-policy-wrong-attribute | blind | safe | `POST /safe/withdrawals/{withdrawal}/approve` | not selected (candidate: false) | selected for idor, workflow_bypass |
| idor-bulk-ids-unscoped | holdout | vulnerable | `PATCH /vuln/messages/archive` | selected for idor | selected for missing_authorization |
| idor-bulk-ids-unscoped | holdout | safe | `PATCH /safe/messages/archive` | not selected (candidate: false) | selected for missing_authorization |
| idor-gate-closure-ignores-model | holdout | safe | `POST /safe/subscriptions/{subscription}/pause` | not selected (candidate: false) | selected for idor, workflow_bypass |
| mass-assign-validated-sensitive-rule | holdout | vulnerable | `PATCH /vuln/listings/{listing}` | selected for mass_assignment | not selected |
| workflow-publish-skips-approval | holdout | safe | `POST /safe/articles/{article}/publish` | not selected (candidate: false) | selected for idor, workflow_bypass |

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
| blind | 10 | 9 | 9 | 1 | 0 | 0 | 0/1 | 0/20 |
| holdout | 6 | 5 | 4 | 2 | 0 | 0 | 0/0 | 2/12 |
| all | 16 | 14 | 13 | 3 | 0 | 0 | 0/1 | 2/32 |

## Cases

| Case | Set | App | Category | Vulnerable | Deciding finding | Safe | Deciding finding | Map | Selected |
|---|---|---|---|---|---|---|---|---|---|
| idor-find-by-id | existing | laravel11-app | idor | found | idor high · `app/Http/Controllers/Vuln/InvoiceController.php:19` · `App\Http\Controllers\Vuln\InvoiceController::show` · IDOR: any authenticated user can read any invoice by ID via unscoped findOrFail | clean |  | ok | vulnerable: selected for idor; safe: not selected |
| idor-binding-authorize | existing | laravel11-app | idor | found | idor high · `app/Http/Controllers/Vuln/InvoiceController.php:26` · `App\Http\Controllers\Vuln\InvoiceController::update` · IDOR: any authenticated user can update any invoice via PUT /beta/invoices/{invoice} | clean |  | ok | vulnerable: selected for idor, missing_authorization; safe: not selected |
| idor-route-can-middleware | existing | laravel11-app | idor | found | idor high · `app/Http/Controllers/Vuln/InvoiceController.php:33` · `App\Http\Controllers\Vuln\InvoiceController::pdf` · Invoice PDF downloadable by any authenticated user via route-bound {invoice} without ownership check | clean |  | ok | vulnerable: selected for idor; safe: not selected |
| idor-form-request | existing | laravel11-app | idor | found | idor high · `app/Http/Controllers/Vuln/ProjectController.php:14` · `App\Http\Controllers\Vuln\ProjectController::update` · Any authenticated user can update any project via route-bound {project} with no ownership check | clean |  | ok | vulnerable: selected for idor, missing_authorization; safe: not selected |
| idor-trivial-policy | existing | laravel11-app | idor | found (post-hoc accept) | idor high · `app/Policies/CommentPolicy.php:12` · `App\Policies\CommentPolicy::delete` · Any authenticated user can delete any comment: CommentPolicy::delete always returns true | clean |  | ok | vulnerable: selected for idor, missing_authorization; safe: not selected |
| idor-has-middleware | existing | laravel11-app | idor | found | idor high · `app/Http/Controllers/Vuln/DocumentController.php:22` · `App\Http\Controllers\Vuln\DocumentController::show` · Any authenticated user can read any Document via route model binding without ownership check | clean |  | ok | vulnerable: selected for idor; safe: not selected |
| idor-service-layer | existing | laravel11-app | idor | found (post-hoc accept) | idor medium · `app/Services/DownloadService.php:11` · `App\Services\DownloadService::find` · Any logged-in user can download any Download file by id with no ownership or permission check | clean |  | ok | vulnerable: selected for idor; safe: not selected |
| mass-assign-guarded-empty | existing | laravel11-app | mass_assignment | found | mass_assignment high · `app/Http/Controllers/Vuln/AccountController.php:14` · `App\Http\Controllers\Vuln\AccountController::update` · Mass assignment: $request->all() written to Account, whose $guarded = [] leaves every column open | clean |  | ok | vulnerable: selected for mass_assignment; safe: not selected |
| mass-assign-sensitive-fillable | existing | laravel11-app | mass_assignment | found | mass_assignment high · `app/Http/Controllers/Vuln/TeamController.php:14` · `App\Http\Controllers\Vuln\TeamController::store` · Team::create($request->all()) lets caller set owner_id on new team | clean |  | ok | vulnerable: selected for missing_authorization, mass_assignment; safe: not selected |
| insecure-deserialization-cookie | existing | laravel11-app | insecure_deserialization | found | insecure_deserialization high · `app/Http/Controllers/Vuln/CartController.php:13` · `App\Http\Controllers\Vuln\CartController::restore` · unserialize() on client-supplied 'cart' cookie in CartController::restore | clean |  | ok | vulnerable: selected for insecure_deserialization; safe: not selected |
| workflow-refund-any-status | existing | laravel11-app | workflow_bypass | found | workflow_bypass high · `app/Http/Controllers/Vuln/OrderController.php:18` · `App\Http\Controllers\Vuln\OrderController::refund` · Order refund sets status to 'refunded' without checking the order's current state | clean |  | ok | vulnerable: selected for workflow_bypass; safe: not selected |
| prompt-injection-comment | existing | laravel11-app | idor | found | idor high · `app/Http/Controllers/Vuln/ReceiptController.php:18` · `App\Http\Controllers\Vuln\ReceiptController::show` · IDOR: any authenticated user can read any receipt by id via Receipt::findOrFail | clean |  | ok | vulnerable: selected for idor; safe: not selected |
| suppressed-idor | existing | laravel11-app | idor | found (suppressed) | idor high · `app/Http/Controllers/Vuln/SharedInvoiceController.php:15` · `App\Http\Controllers\Vuln\SharedInvoiceController::show` · IDOR: any authenticated user can read any invoice by id via unscoped findOrFail (suppressed) | clean |  | ok | vulnerable: selected for idor; safe: not selected |
| idor-l10-ctor-middleware | existing | laravel10-app | idor | found | idor high · `app/Http/Controllers/Vuln/ReportController.php:18` · `App\Http\Controllers\Vuln\ReportController::show` · Report returned via route model binding without ownership/policy check (IDOR) | clean |  | ok | vulnerable: selected for idor; safe: not selected |
| idor-l10-resource | existing | laravel10-app | idor | found | idor high · `app/Http/Controllers/Vuln/NoteController.php:29` · `App\Http\Controllers\Vuln\NoteController::show` · IDOR: any authenticated user can read any note by id via Note::find | clean |  | ok | vulnerable: selected for idor; safe: not selected |
| idor-role-only-middleware | blind | laravel12-app | idor | found | idor high · `app/Http/Controllers/Vuln/PayoutController.php:13` · `App\Http\Controllers\Vuln\PayoutController::index` · Any merchant can list payouts (amounts, IBANs) of any store via {store} binding | clean |  | ok | vulnerable: selected for idor; safe: selected for idor |
| idor-nested-unscoped-binding | blind | laravel12-app | idor | found | idor high · `app/Http/Controllers/Vuln/TeamProjectController.php:17` · `App\Http\Controllers\Vuln\TeamProjectController::show` · Project read via team route without checking the project belongs to the authorized team | clean |  | ok | vulnerable: selected for idor; safe: not selected |
| idor-tenant-list-unscoped | blind | laravel12-app | idor | found | idor high · `app/Http/Controllers/Vuln/TicketController.php:14` · `App\Http\Controllers\Vuln\TicketController::index` · Ticket index returns all users' tickets without scoping to current user | clean |  | ok | vulnerable: selected for idor; safe: not selected |
| idor-with-trashed-restore | blind | laravel12-app | idor | found | idor high · `app/Http/Controllers/Vuln/ContactController.php:14` · `App\Http\Controllers\Vuln\ContactController::restore` · Unscoped soft-deleted Contact lookup lets any logged-in user restore another user's contact | clean |  | ok | vulnerable: selected for idor, missing_authorization; safe: not selected |
| idor-polymorphic-parent-check | blind | laravel12-app | idor | found | idor medium · `app/Http/Controllers/Vuln/ReviewController.php:17` · `App\Http\Controllers\Vuln\ReviewController::update` · Review update authorizes the parent reviewable instead of the review, allowing edits of other users' reviews | clean |  | ok | vulnerable: selected for idor; safe: not selected |
| idor-update-unscoped-relation | blind | laravel12-app | idor | found | idor high · `app/Http/Controllers/Vuln/AddressController.php:20` · `App\Http\Controllers\Vuln\AddressController::update` · Any authenticated user can update any address by ID (unscoped findOrFail) | clean |  | ok | vulnerable: selected for idor, missing_authorization; safe: not selected |
| idor-policy-wrong-attribute | blind (tuned-on) | laravel12-app | idor | missed: LLM missed it |  | flagged (low confidence) | workflow_bypass low · `app/Http/Controllers/Safe/WithdrawalController.php:16` · `App\Http\Controllers\Safe\WithdrawalController::approve` · Withdrawal approval sets status to 'approved' without checking the current status | ok | vulnerable: selected for idor, workflow_bypass; safe: selected for idor, workflow_bypass |
| mass-assign-force-fill | blind | laravel12-app | mass_assignment | found | mass_assignment high · `app/Http/Controllers/Vuln/ProfileController.php:18` · `App\Http\Controllers\Vuln\ProfileController::update` · Profile update forceFills all request input onto the User, allowing self-escalation (role/admin flags) | clean |  | ok | vulnerable: selected for missing_authorization, mass_assignment; safe: not selected |
| workflow-cancel-shipped-service | blind | laravel12-app | workflow_bypass | found | workflow_bypass high · `app/Services/OrderService.php:11` · `App\Services\OrderService::cancel` · Order cancellation sets status to 'cancelled' without checking the order's current state | clean |  | ok | vulnerable: selected for workflow_bypass; safe: selected for workflow_bypass |
| idor-query-string-user-id | blind | laravel12-app | idor | found | idor high · `app/Http/Controllers/Vuln/StatementController.php:16` · `App\Http\Controllers\Vuln\StatementController::index` · Statements of any user listed via client-supplied user_id query parameter | clean |  | ok | vulnerable: selected for idor; safe: not selected |
| idor-bulk-ids-unscoped | holdout | laravel12-app | idor | found | idor high · `app/Http/Controllers/Vuln/MessageController.php:19` · `App\Http\Controllers\Vuln\MessageController::archive` · Bulk archive updates arbitrary messages by user-supplied IDs without ownership scoping | clean |  | ok | vulnerable: selected for missing_authorization; safe: selected for missing_authorization |
| missing-authz-admin-suspend | holdout | laravel12-app | missing_authorization | found | missing_authorization high · `app/Http/Controllers/Vuln/UserController.php:13` · `App\Http\Controllers\Vuln\UserController::suspend` · Any logged-in user can suspend any account: no authorization on POST /beta/users/{user}/suspend | clean |  | ok | vulnerable: selected for idor, missing_authorization; safe: not selected |
| idor-gate-closure-ignores-model | holdout | laravel12-app | idor | found | idor high · `app/Http/Controllers/Vuln/SubscriptionController.php:19` · `App\Http\Controllers\Vuln\SubscriptionController::pause` · pause-subscription gate never checks ownership, so any user can pause another user's subscription | flagged (low confidence) | workflow_bypass low · `app/Http/Controllers/Safe/SubscriptionController.php:19` · `App\Http\Controllers\Safe\SubscriptionController::pause` · Subscription can be paused from any status (cancelled, expired, already paused) with no state guard | ok | vulnerable: selected for idor, workflow_bypass; safe: selected for idor, workflow_bypass |
| mass-assign-validated-sensitive-rule | holdout | laravel12-app | mass_assignment | missed: never sent to the LLM |  | clean |  | ok | vulnerable: not selected; safe: not selected |
| workflow-publish-skips-approval | holdout | laravel12-app | workflow_bypass | found (low confidence) | workflow_bypass low · `app/Http/Controllers/Vuln/ArticleController.php:16` · `App\Http\Controllers\Vuln\ArticleController::publish` · Article published from any state: no status guard before status transition | flagged (low confidence) | workflow_bypass low · `app/Http/Controllers/Safe/ArticleController.php:16` · `App\Http\Controllers\Safe\ArticleController::publish` · Article publish transition has no status guard; any state (archived, already published) can be re-published | ok | vulnerable: selected for idor, workflow_bypass; safe: selected for idor, workflow_bypass |
| insecure-deserialization-request-checkpoint | holdout | laravel12-app | insecure_deserialization | found | insecure_deserialization high · `app/Http/Controllers/Vuln/ImportController.php:15` · `App\Http\Controllers\Vuln\ImportController::resume` · unserialize() on client-supplied checkpoint enables PHP object injection | clean |  | vulnerable: expected [authentication], got [authentication, query_scope]; safe: expected [authentication], got [authentication, query_scope] | vulnerable: selected for insecure_deserialization; safe: selected for insecure_deserialization |

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
| 41 | 26,090 | 25,110 | 89,280 | 31,938 | $0.89 |

Priced as claude-opus-5-5: $4.00/M input, $20.00/M output, $0.20/M cache read, $5.00/M cache write (1.25x input).

## Competitive check

Anthropic's `claude-code-security-review` at commit `0c6a49f1fa56a1d472575da86a94dbc1edb78eda` ran with model `claude-opus-5-5` on tusharkhan/acme-portal#1, a pull request that adds the disguised copy of the three apps. Its findings were mapped to symbols with our `SymbolTable` and scored by the same scorer as above: 23 findings, 23 inside a benchmark app, 0 outside. Runtime 68 s.

Their findings were mapped back with `disguise-map.v1.json`, the map of the copy they reviewed. 6 cases were not in the copy they reviewed (idor-bulk-ids-unscoped, missing-authz-admin-suspend, idor-gate-closure-ignores-model, mass-assign-validated-sensitive-rule, workflow-publish-skips-approval, insecure-deserialization-request-checkpoint) and are shown as not run, not as misses.

Cost: 2 input, 65,663 cache write, 0 cache read, 7,636 output tokens over 1 agent turns; $0.48 at the prices above ($0.48 as the Claude Code CLI reported it).

Recall is the share of vulnerable variants found at the right symbol with a matching category. Precision is found / (found + safe variants flagged + public routes hit + unattributed safe-code findings). Each term is a case-level verdict, so repeated findings on one symbol count once. Findings at every confidence count for both tools.

| Set | Metric | semantic-sec | claude-code-security-review |
|---|---|---|---|
| existing | Recall (found) | 100.0% (15/15) | 80.0% (12/15) |
| existing | Precision | 100.0% (15/15) | 100.0% (12/12) |
| existing | Safe variants flagged | 0.0% (0/15) | 0.0% (0/15) |
| existing | Public routes hit | 0/1 | 0/1 |
| existing | Unattributed safe-code findings | 0 | 0 |
| blind | Recall (found) | 90.0% (9/10) | 90.0% (9/10) |
| blind | Precision | 90.0% (9/10) | 100.0% (9/9) |
| blind | Safe variants flagged | 10.0% (1/10) | 0.0% (0/10) |
| blind | Public routes hit | 0/1 | 0/1 |
| blind | Unattributed safe-code findings | 0 | 0 |
| holdout | Recall (found) | 83.3% (5/6) | n/a |
| holdout | Precision | 71.4% (5/7) | n/a |
| holdout | Safe variants flagged | 33.3% (2/6) | n/a |
| holdout | Public routes hit | 0/0 | 0/0 |
| holdout | Unattributed safe-code findings | 0 | 0 |
| all | Recall (found) | 93.5% (29/31) | 84.0% (21/25) |
| all | Precision | 90.6% (29/32) | 100.0% (21/21) |
| all | Safe variants flagged | 9.7% (3/31) | 0.0% (0/25) |
| all | Public routes hit | 0/2 | 0/2 |
| all | Unattributed safe-code findings | 0 | 0 |

### Verdicts per case

| Case | Set | Category | semantic-sec | claude-code-security-review | Their deciding finding |
|---|---|---|---|---|---|
| idor-find-by-id | existing | idor | found; safe clean | found; safe clean | idor high · `app/Http/Controllers/Vuln/InvoiceController.php:19` · `App\Http\Controllers\Vuln\InvoiceController::show` · idor: Beta invoice endpoints have no ownership checks. show() uses Invoice::findOrFail, update() never calls authorize and UpdateInvoiceRequest::authorize re... |
| idor-binding-authorize | existing | idor | found; safe clean | missed; safe clean |  |
| idor-route-can-middleware | existing | idor | found; safe clean | missed; safe clean |  |
| idor-form-request | existing | idor | found; safe clean | found; safe clean | idor high · `app/Http/Controllers/Vuln/ProjectController.php:14` · `App\Http\Controllers\Vuln\ProjectController::update` · authorization_bypass: The Beta controller uses Alpha\UpdateProjectRequest, whose authorize() returns true. ProjectPolicy::update is never checked, so any use... |
| idor-trivial-policy | existing | idor | found; safe clean | found; safe clean | idor|missing_authorization high · `app/Policies/CommentPolicy.php:12` · `App\Policies\CommentPolicy::delete` · authorization_bypass: CommentPolicy::delete always returns true, so the authorize() call in Beta\CommentController::destroy does nothing. |
| idor-has-middleware | existing | idor | found; safe clean | found; safe clean | idor high · `app/Http/Controllers/Vuln/DocumentController.php:22` · `App\Http\Controllers\Vuln\DocumentController::show` · idor: Only the auth middleware is applied. The DocumentPolicy view check is never enforced, so any user can view any document. |
| idor-service-layer | existing | idor | found; safe clean | found; safe clean | idor high · `app/Http/Controllers/Vuln/DownloadController.php:17` · `App\Http\Controllers\Vuln\DownloadController::show` · idor: DownloadService::find() uses Download::findOrFail($id) with no owner_id scope, so any authenticated user can download any stored file. |
| mass-assign-guarded-empty | existing | mass_assignment | found; safe clean | found; safe clean | mass_assignment high · `app/Http/Controllers/Vuln/AccountController.php:14` · `App\Http\Controllers\Vuln\AccountController::update` · mass_assignment_privilege_escalation: $account->update($request->all()) passes every request field to the Account model, which has $guarded = []. The FormReq... |
| mass-assign-sensitive-fillable | existing | mass_assignment | found; safe clean | found; safe clean | mass_assignment medium · `app/Http/Controllers/Vuln/TeamController.php:14` · `App\Http\Controllers\Vuln\TeamController::store` · mass_assignment: Team::create($request->all()) bypasses the validated subset. owner_id is fillable, so the client chooses the team owner. |
| insecure-deserialization-cookie | existing | insecure_deserialization | found; safe clean | found; safe clean | insecure_deserialization high · `app/Http/Controllers/Vuln/CartController.php:13` · `App\Http\Controllers\Vuln\CartController::restore` · insecure_deserialization: The 'cart' cookie is passed straight to PHP unserialize(). The route is in routes/api.php, which uses the 'api' middleware group. T... |
| workflow-refund-any-status | existing | workflow_bypass | found; safe clean | missed; safe clean |  |
| prompt-injection-comment | existing | idor | found; safe clean | found; safe clean | idor high · `app/Http/Controllers/Vuln/ReceiptController.php:18` · `App\Http\Controllers\Vuln\ReceiptController::show` · idor: Receipt::findOrFail($id) fetches any receipt with no ownership scope. The 'SECURITY REVIEWED / API gateway' comment is not backed by anything: the rout... |
| suppressed-idor | existing | idor | found; safe clean | found; safe clean | idor medium · `app/Http/Controllers/Vuln/SharedInvoiceController.php:15` · `App\Http\Controllers\Vuln\SharedInvoiceController::show` · idor: Invoice::findOrFail($id) returns any invoice by sequential ID. The ignore comment says shared invoices are 'public by contract', but there is no share ... |
| idor-l10-ctor-middleware | existing | idor | found; safe clean | found; safe clean | idor high · `app/Http/Controllers/Vuln/ReportController.php:18` · `App\Http\Controllers\Vuln\ReportController::show` · idor: Only auth middleware is applied. ReportPolicy::view is never enforced, so any user can read any report. |
| idor-l10-resource | existing | idor | found; safe clean | found; safe clean | idor high · `app/Http/Controllers/Vuln/NoteController.php:29` · `App\Http\Controllers\Vuln\NoteController::show` · idor: show() uses Note::find($id) with no ownership scope or policy check. update and destroy are scoped correctly. |
| idor-role-only-middleware | blind | idor | found; safe clean | found; safe clean | idor high · `app/Http/Controllers/Vuln/PayoutController.php:13` · `App\Http\Controllers\Vuln\PayoutController::index` · idor: The route only checks role:merchant. Nothing checks that the bound Store belongs to the requester, so any merchant can list any store's payouts, includ... |
| idor-nested-unscoped-binding | blind | idor | found; safe clean | found; safe clean | idor high · `app/Http/Controllers/Vuln/TeamProjectController.php:15` · `App\Http\Controllers\Vuln\TeamProjectController::show` · idor: Authorization checks membership of {team}, but the route has no scopeBindings(), so {project} is resolved globally and never checked against that team. |
| idor-tenant-list-unscoped | blind | idor | found; safe clean | found; safe clean | idor high · `app/Http/Controllers/Vuln/TicketController.php:14` · `App\Http\Controllers\Vuln\TicketController::index` · idor: Ticket::query() returns tickets from every organization. There is no tenant scoping. |
| idor-with-trashed-restore | blind | idor | found; safe clean | found; safe clean | idor high · `app/Http/Controllers/Vuln/ContactController.php:14` · `App\Http\Controllers\Vuln\ContactController::restore` · idor: Contact::withTrashed()->findOrFail($id) lets any user restore any soft-deleted contact and returns its data in the response. |
| idor-polymorphic-parent-check | blind | idor | found; safe clean | found; safe clean | idor|missing_authorization medium · `app/Http/Controllers/Vuln/ReviewController.php:15` · `App\Http\Controllers\Vuln\ReviewController::update` · authorization_bypass: Authorization runs against the reviewable (product) instead of the review. ProductPolicy::update allows the product owner, so a seller ... |
| idor-update-unscoped-relation | blind | idor | found; safe clean | found; safe clean | idor high · `app/Http/Controllers/Vuln/AddressController.php:20` · `App\Http\Controllers\Vuln\AddressController::update` · idor: Address::findOrFail($id) loads and updates any user's address without an ownership check. |
| idor-policy-wrong-attribute | blind | idor | missed; safe flagged | found; safe clean | idor|missing_authorization medium · `app/Policies/TransferPolicy.php:12` · `App\Policies\TransferPolicy::approve` · authorization_bypass: The approve check only allows the user who created the transfer (created_by === user). This lets the maker approve their own transfer a... |
| mass-assign-force-fill | blind | mass_assignment | found; safe clean | found; safe clean | mass_assignment high · `app/Http/Controllers/Vuln/ProfileController.php:18` · `App\Http\Controllers\Vuln\ProfileController::update` · mass_assignment_privilege_escalation: forceFill($request->except('password')) skips $fillable and writes every request attribute except password onto the Use... |
| workflow-cancel-shipped-service | blind | workflow_bypass | found; safe clean | missed; safe clean |  |
| idor-query-string-user-id | blind | idor | found; safe clean | found; safe clean | idor high · `app/Http/Controllers/Vuln/StatementController.php:14` · `App\Http\Controllers\Vuln\StatementController::index` · idor: The user_id request parameter decides which user's statements are returned, and nothing checks that it matches the logged-in user. |
| idor-bulk-ids-unscoped | holdout | idor | found; safe clean | not run | |
| missing-authz-admin-suspend | holdout | missing_authorization | found; safe clean | not run | |
| idor-gate-closure-ignores-model | holdout | idor | found; safe flagged | not run | |
| mass-assign-validated-sensitive-rule | holdout | mass_assignment | missed; safe clean | not run | |
| workflow-publish-skips-approval | holdout | workflow_bypass | found; safe flagged | not run | |
| insecure-deserialization-request-checkpoint | holdout | insecure_deserialization | found; safe clean | not run | |

### Their findings and how each was mapped

| # | Reported at (original path) | Their category | Scored as | Rule | Symbol | Located by |
|---|---|---|---|---|---|---|
| 1 | `laravel11-app/app/Http/Controllers/Vuln/CartController.php:13` | insecure_deserialization | insecure_deserialization | category-field | `App\Http\Controllers\Vuln\CartController::restore` | method |
| 2 | `laravel11-app/app/Http/Controllers/Vuln/AccountController.php:14` | mass_assignment_privilege_escalation | mass_assignment | keyword:mass_assignment | `App\Http\Controllers\Vuln\AccountController::update` | method |
| 3 | `laravel12-app/app/Http/Controllers/Vuln/ProfileController.php:18` | mass_assignment_privilege_escalation | mass_assignment | keyword:mass_assignment | `App\Http\Controllers\Vuln\ProfileController::update` | method |
| 4 | `laravel12-app/app/Http/Controllers/Vuln/StatementController.php:14` | idor | idor | category-field | `App\Http\Controllers\Vuln\StatementController::index` | method |
| 5 | `laravel12-app/app/Http/Controllers/Vuln/TicketController.php:14` | idor | idor | category-field | `App\Http\Controllers\Vuln\TicketController::index` | method |
| 6 | `laravel12-app/app/Http/Controllers/Vuln/PayoutController.php:13` | idor | idor | category-field | `App\Http\Controllers\Vuln\PayoutController::index` | method |
| 7 | `laravel12-app/app/Http/Controllers/Vuln/TeamProjectController.php:15` | idor | idor | category-field | `App\Http\Controllers\Vuln\TeamProjectController::show` | method |
| 8 | `laravel11-app/app/Http/Controllers/Vuln/InvoiceController.php:19` | idor | idor | category-field | `App\Http\Controllers\Vuln\InvoiceController::show` | method |
| 9 | `laravel11-app/app/Http/Controllers/Vuln/ReceiptController.php:18` | idor | idor | category-field | `App\Http\Controllers\Vuln\ReceiptController::show` | method |
| 10 | `laravel11-app/app/Http/Controllers/Vuln/DownloadController.php:17` | idor | idor | category-field | `App\Http\Controllers\Vuln\DownloadController::show` | method |
| 11 | `laravel11-app/app/Http/Controllers/Vuln/DocumentController.php:22` | idor | idor | category-field | `App\Http\Controllers\Vuln\DocumentController::show` | method |
| 12 | `laravel11-app/app/Http/Controllers/Vuln/ProjectController.php:14` | authorization_bypass | idor | exploit:idor | `App\Http\Controllers\Vuln\ProjectController::update` | method |
| 13 | `laravel11-app/app/Policies/CommentPolicy.php:12` | authorization_bypass | idor\|missing_authorization | access-control | `App\Policies\CommentPolicy::delete` | method |
| 14 | `laravel12-app/app/Http/Controllers/Vuln/AddressController.php:20` | idor | idor | category-field | `App\Http\Controllers\Vuln\AddressController::update` | method |
| 15 | `laravel12-app/app/Http/Controllers/Vuln/ContactController.php:14` | idor | idor | category-field | `App\Http\Controllers\Vuln\ContactController::restore` | method |
| 16 | `laravel10-app/app/Http/Controllers/Vuln/NoteController.php:29` | idor | idor | category-field | `App\Http\Controllers\Vuln\NoteController::show` | method |
| 17 | `laravel10-app/app/Http/Controllers/Vuln/ReportController.php:18` | idor | idor | category-field | `App\Http\Controllers\Vuln\ReportController::show` | method |
| 18 | `laravel11-app/app/Http/Controllers/Vuln/SharedInvoiceController.php:15` | idor | idor | category-field | `App\Http\Controllers\Vuln\SharedInvoiceController::show` | method |
| 19 | `laravel12-app/app/Http/Controllers/Vuln/ReviewController.php:15` | authorization_bypass | idor\|missing_authorization | access-control | `App\Http\Controllers\Vuln\ReviewController::update` | method |
| 20 | `laravel11-app/app/Http/Controllers/Vuln/TeamController.php:14` | mass_assignment | mass_assignment | category-field | `App\Http\Controllers\Vuln\TeamController::store` | method |
| 21 | `laravel12-app/app/Policies/TransferPolicy.php:12` | authorization_bypass | idor\|missing_authorization | access-control | `App\Policies\TransferPolicy::approve` | method |
| 22 | `laravel12-app/app/Policies/WithdrawalPolicy.php:12` | authorization_bypass | workflow_bypass | keyword:workflow_bypass | `App\Policies\WithdrawalPolicy::approve` | method |
| 23 | `laravel10-app/app/Http/Kernel.php:16` | csrf | * | none | `App\Http\Kernel` | class |

### Category inference

Their findings carry a free-text `category` and no CWE field, while our scorer needs one of five categories. The first rule that matches decides: a CWE id anywhere in the finding, then our own category name as theirs, then keywords in category and description (`keyword:`), then keywords in the exploit scenario (`exploit:`). Generic authorization wording scores as either `idor` or `missing_authorization` (`access-control`). A finding with nothing to go on (`none`) scores as **any category** for the found check, so they are not penalised for vocabulary. Our findings must match the case category exactly, so this favours them.

| Rule | Findings |
|---|---|
| category-field | 15 |
| keyword:mass_assignment | 2 |
| keyword:workflow_bypass | 1 |
| exploit:idor | 1 |
| access-control | 3 |
| none | 1 |

### Asymmetries

- Input. They review a PR diff of the three apps plus whatever the agent chooses to open in the checkout; we analyze each app as a whole project, with routes, middleware and policies resolved before the LLM sees a candidate. Their prompt lists only the first 100 changed files (one GitHub API page), although the diff itself is complete.
- Disguise. They ran on the disguised copy (`Vuln`/`Safe` renamed to `Alpha`/`Beta` at random per class pair, routes regrouped to match, line numbers kept outside route files). Our gate numbers above come from the same disguised copy, mapped back to the original names for scoring; the undisguised table is shown only for reference.
- Category. Their category is inferred (see above) and may be "any category"; ours must match exactly.
- Location. A finding counts only at the case symbol or an accepted one. Their file and line become the enclosing method through our `SymbolTable`; a line in a route file becomes that route's controller action. Findings on models, form requests or class bodies land on no case, for both tools.
- Model and method. Theirs: `claude-opus-5-5` in one agentic Claude Code session with file tools; ours: `claude-opus-5-5`, one structured call per selected route and category.
- Suppression. They do not honour `@semantic-sec-ignore`; we report the annotated case as suppressed, and both count as found for `suppressed-idor`.
- Filtering. Their eval mode applies only the hard-coded exclusion rules; the GitHub Action also runs a second Claude false-positive filter, which this run did not use.
- Confidence. Their 0 to 1 confidence maps to high (0.9 and up), medium (0.7 and up) or low; their prompt drops findings under 0.7. Cost guard: at most 1 Claude Code calls, 60 turns and $4 each.

