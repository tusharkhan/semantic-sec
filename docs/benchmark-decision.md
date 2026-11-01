# M8 accuracy gate: decision brief (2026-11-01, after tuning round 1)

The numbers below are summarised from `docs/benchmark-results.md`, which `bin/benchmark` generates. This page sets out the decision that SPEC §15 leaves to the maintainer.

## Corpus and method

There are **31 vulnerable/safe pairs and 2 public-by-design routes**, spread over three Laravel apps.

| Set | Pairs | Written | Tuned against? |
|---|---|---|---|
| existing | 15 | with the scanner (M1) | yes, by design |
| blind | 10 | blind, by an agent that read only `benchmark/` and SPEC §3 and §15 | after the first measurement, by tuning round 1. `idor-policy-wrong-attribute` is marked `tuned_on`. |
| holdout | 6 | blind, by a fresh agent **after** tuning | **never** |

- Every case is proven by real Laravel 12 feature tests: the attacker succeeds on the vulnerable variant and is blocked on the safe one, and the owner still works.
- Both tools ran on a **disguised copy**, with `Vuln`/`Safe` names randomised per class pair.
- Both used `claude-opus-5-5`, and the same scorer scored both.
- **The holdout is the honest number for unseen code.** It is small, so one case moves it by about 17 points.

## Tuning round 1 (user decisions)

- List endpoints that read owned records without user scoping are now IDOR candidates.
- `scopeBindings()` counts as a query scope.
- A general prompt rule now says an authorization check only counts if it compares the user to the attribute that represents ownership or permission over *this* resource.
- `SecurityPrompt` is at v3.

## Our gate (SPEC §15), all findings at every confidence

| Criterion | Bar | existing | blind | holdout | all |
|---|---|---|---|---|---|
| Vulnerable found | ≥ 70% | 100% | 90% | 83.3% | 93.5% |
| Safe flagged | ≤ 10% | 0% | 10% | **33.3%** | 9.7% |
| Public routes hit | 0 | 0 | 0 | n/a | 0 |
| `map` matches | 100% | 100% | 100% | **83.3%** | **96.8%** |

**Counting only findings that fail a build** (confidence ≥ medium, the default `--min-confidence`):

| Set | Safe flagged | Found |
|---|---|---|
| existing | 0 | 100% |
| blind | 0 | 90% |
| holdout | 0 | **66.7%** |

- **Every safe flag is a low-confidence `workflow_bypass`** saying that pause, approve or publish has "no status guard". There are three of them: one in blind and two in holdout. In each case the safe variant really does lack a status check, but that isn't the flaw the case tests. These flags are reported, but never fail CI.
- **Holdout misses.** `mass-assign-validated-sensitive-rule` was never sent to the LLM: by design, `validated()` doesn't count as mass input, even when the rules accept a sensitive field. `workflow-publish-skips-approval` was found, but only at low confidence.
- **Holdout `map` mismatch.** The scanner records a `query_scope` on both variants of `insecure-deserialization-request-checkpoint`; the author didn't. This is the same kind of vocabulary question as `scopeBindings`.

## Head-to-head with Anthropic's `claude-code-security-review`

This compares the existing and blind sets. The competitor wasn't re-run on the holdout because the scratch repo was due for deletion, so its holdout is "not run".

| | semantic-sec | claude-code-security-review |
|---|---|---|
| Recall, existing + blind (25) | **96% (24/25)** | 84% (21/25) |
| Safe flagged, all confidences | 1/25 | 0/25 |
| Safe flagged, failing findings only | 0/25 | 0/25 |
| Precision, all confidences | 96% | 100% |
| Cost of one run | about $0.55–0.61 | $0.48 |

- **Anthropic's tool missed** both workflow cases and two authorization cases.
- **The asymmetries still favour Anthropic's tool here.** Its category is inferred and may count as "any". The whole corpus fits in one prompt, whereas on a real PR it sees only the diff.

## The SPEC §15 publish rule

> Publish only if semantic-sec beats it on precision without losing recall by more than 10 points.

- **At all confidences:** precision is 96% vs 100%, so **not met**. The only difference is one low-confidence finding.
- **At failing confidence**, which is what CI acts on: precision is 100% vs 100%, so **met on equal terms**, with recall 12 points higher.
- **Our own gate fails on the holdout:** safe flagged is 33% at all confidences, and `map` is 83%.

## Decisions for the maintainer

1. **Go, tune again or stop?** Options:
   - **(a) Publish**, documenting the comparison and the holdout honestly.
   - **(b) A second tuning round.** Candidate targets:
     - don't report `workflow_bypass` without a concrete reachable bad state, or keep it at low confidence only, which it already is
     - treat sensitive fields in validation rules as a mass-assignment risk
     - settle the `query_scope` vocabulary

     A second round needs a **new holdout** to stay honest.
   - **(c) Stop.**
2. **Which confidence level does the publish rule use?** All findings, or only the failing ones that CI acts on?
3. **Should `validated()` with sensitive rule keys count as mass input?**
4. **Holdout `map` vocabulary:** should the deserialization case record `query_scope`?

**M8 spend: about $3.75 of the $15 cap.**

- our runs: $0.58, $0.61, $0.60, $0.55, $0.52 and $0.41
- competitor: $0.48

The private scratch repo `tusharkhan/acme-portal` is still to be deleted. That needs the `delete_repo` scope; run `gh auth refresh -h github.com -s delete_repo`.

## Decision (maintainer, 2026-11-01)

**Go to M9 (release).** The publish rule is judged on **failing findings** (confidence ≥ medium). On that basis:

| | Recall (existing + blind) | Safe flagged (failing findings) |
|---|---|---|
| semantic-sec | 96% | 0 |
| claude-code-security-review | 84% | 0 |

The rule is met. SPEC §15 is updated to match.

Carried into the release notes:
- the holdout result: 5 of 6 found, with 2 low-confidence notes on safe routes
- the open gaps:
  - `validated()` with sensitive rule keys is not treated as mass input
  - a list endpoint with no user-owned model is not selected
