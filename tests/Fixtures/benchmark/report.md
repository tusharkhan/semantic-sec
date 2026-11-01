# Benchmark results

Mode: replay of recorded cassettes · Model: claude-opus-5-5 · Prompt v2 · Date: 2026-11-01

Apps: app-a, app-b. Scored at `--level low` with every confidence; "failing" means confidence medium or high.

## Gate

| Criterion | Threshold | existing | blind | all |
|---|---|---|---|---|
| Vulnerable variants found at the right symbol | ≥ 70% | 100% (2/2) PASS | 100% (1/1) PASS | 100% (3/3) PASS |
| Safe variants flagged | ≤ 10% | 0% (0/2) PASS | 100% (1/1) FAIL | 33% (1/3) FAIL |
| Findings on public-by-design routes | 0 | 1/1 routes hit FAIL | 0/1 routes hit PASS | 1/2 routes hit FAIL |
| Expected authorization checks in the map | 100% | 75% (3/4) FAIL | 100% (2/2) PASS | 83% (5/6) FAIL |
| **Gate** | | **FAIL** | **FAIL** | **FAIL** |

## Gate, failing findings only

| Criterion | Threshold | existing | blind | all |
|---|---|---|---|---|
| Vulnerable variants found at the right symbol | ≥ 70% | 100% (2/2) PASS | 0% (0/1) FAIL | 67% (2/3) FAIL |
| Safe variants flagged | ≤ 10% | 0% (0/2) PASS | 100% (1/1) FAIL | 33% (1/3) FAIL |
| Findings on public-by-design routes | 0 | 0/1 routes hit PASS | 0/1 routes hit PASS | 0/2 routes hit PASS |
| Expected authorization checks in the map | 100% | 75% (3/4) FAIL | 100% (2/2) PASS | 83% (5/6) FAIL |
| **Gate** | | **FAIL** | **FAIL** | **FAIL** |

## Selection stage

Whether each route reached the LLM for the case's category. A missed vulnerable case whose route was not selected was never sent to the LLM; one that was selected is an LLM miss.

| Case | Set | Variant | Route | Expected | Actual |
|---|---|---|---|---|---|
| policy-accept | blind | vulnerable | `POST /vuln/transfers/{transfer}/approve` | selected for idor | not selected |
| policy-accept | blind | safe | `POST /safe/withdrawals/{withdrawal}/approve` | not selected (candidate: false) | selected for idor, workflow_bypass |

## Per app

### app-a

| Set | Cases | Found | Found (failing) | Safe flagged | Safe flagged (failing) | Public violations | Map mismatches |
|---|---|---|---|---|---|---|---|
| existing | 1 | 1 | 1 | 0 | 0 | 1/1 | 1/2 |
| blind | 1 | 1 | 0 | 1 | 1 | 0/0 | 0/2 |
| all | 2 | 2 | 1 | 1 | 1 | 1/1 | 1/4 |

### app-b

| Set | Cases | Found | Found (failing) | Safe flagged | Safe flagged (failing) | Public violations | Map mismatches |
|---|---|---|---|---|---|---|---|
| existing | 1 | 1 | 1 | 0 | 0 | 0/0 | 0/2 |
| blind | 0 | 0 | 0 | 0 | 0 | 0/1 | 0/0 |
| all | 1 | 1 | 1 | 0 | 0 | 0/1 | 0/2 |

## Cases

| Case | Set | App | Category | Vulnerable | Deciding finding | Safe | Deciding finding | Map | Selected |
|---|---|---|---|---|---|---|---|---|---|
| plain-idor | existing | app-a | idor | found | idor high · `app/Http/Controllers/Vuln/ItemController.php:10` · `App\Http\Controllers\Vuln\ItemController::show` · Finding on App\Http\Controllers\Vuln\ItemController::show | clean |  | safe: expected [authentication, query_scope], got [authentication] | vulnerable: selected for idor; safe: not selected |
| policy-accept | blind | app-a | idor | found (low confidence) | idor low · `app/Policies/TransferPolicy.php:10` · `App\Policies\TransferPolicy::approve` · Finding on App\Policies\TransferPolicy::approve | flagged | workflow_bypass medium · `app/Http/Controllers/Safe/WithdrawalController.php:10` · `App\Http\Controllers\Safe\WithdrawalController::approve` · Finding on App\Http\Controllers\Safe\WithdrawalController::approve | ok | vulnerable: not selected; safe: selected for idor, workflow_bypass |
| suppressed-idor | existing | app-b | idor | found (suppressed) | idor high · `app/Http/Controllers/Vuln/SharedController.php:10` · `App\Http\Controllers\Vuln\SharedController::show` · Finding on App\Http\Controllers\Vuln\SharedController::show (suppressed) | clean |  | ok | vulnerable: selected for idor; safe: not selected |

## Public routes

| App | Set | Route | Symbol | Result | Deciding finding |
|---|---|---|---|---|---|
| app-a | existing | `GET /posts/{post:slug}` | `App\Http\Controllers\PostController::show` | violation (low confidence) | idor low · `app/Http/Controllers/PostController.php:10` · `App\Http\Controllers\PostController::show` · Finding on App\Http\Controllers\PostController::show |
| app-b | blind | `GET /stores/{store:slug}` | `App\Http\Controllers\StorefrontController::show` | clean |  |

## Run cost

Tokens as the provider reported them in the recorded responses. A replay re-reads the recording, so these are the cost of the live run that made it.

| Requests | Input | Cache write | Cache read | Output | Estimated $ |
|---|---|---|---|---|---|
| 7 | 1,000,000 | 50,000 | 1,000,000 | 100,000 | $6.45 |

Priced as claude-opus-5-5: $4.00/M input, $20.00/M output, $0.20/M cache read, $5.00/M cache write (1.25x input).

## Competitive check

_Not run yet._ M8 Task 5 scores Anthropic's `claude-code-security-review` on the same code with this scorer and records its numbers and every asymmetry here.
