# Benchmark verification (real Laravel 12)

Proves the answers in `benchmark/expected.yaml` by running them. Each vulnerable
variant must be exploitable; each safe variant must block the attacker yet still
work for its owner. A throwaway Laravel 12 project is built on demand, the
benchmark app is overlaid on it, and `php artisan test` runs the feature tests
kept here.

## Run

    docker compose run --rm php sh benchmark/verify/run.sh laravel11-app

`build.sh <app> <target>` builds into an absolute path outside the repo (it refuses
anything inside). Nothing from the Laravel install is committed.

## Rules

- Laravel 12 only. Never install Laravel 10 or 11, and never disable Composer's
  security-advisory blocking. If create-project fails on an advisory, raise the
  skeleton version instead.
- Corpus apps are edited only to fix a real bug that verification exposes.

## Vocabulary

- exploited: an authenticated attacker gets 2xx and the effect is asserted.
- blocked: the authenticated attacker gets exactly the stated status (403, 404 or 422) and no effect.
- owner works: the legitimate owner gets 2xx on the safe route.

## Findings so far

- Laravel's test client drops cookies on JSON requests unless `withCredentials()` is used.
- Laravel 12's `route:list` expands `can:` to `Illuminate\Auth\Middleware\Authorize:...` for `bootstrap/app.php` apps, but shows aliases for legacy-Kernel apps.
- The User models were missing traits needed to run the apps (HasFactory on both, HasApiTokens on laravel11-app).
- The route check also binds each expected route to its controller action (`route:list` action must equal the `expected.yaml` symbol), so a route cannot silently point at a different method.
- `CaseCoverageTest` (in both apps) fails if any expected case lacks a `test<Case>Vulnerable`/`test<Case>Safe` method or a public route lacks `testPublicRoute<Method>`; `run.sh` feeds it `expected.yaml` as JSON.
