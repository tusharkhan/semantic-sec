# Benchmark corpus

Fake Laravel apps (source files only, no `vendor/`) that the scanner is scored against.
`expected.yaml` is the ground truth; `tests/Integration/Benchmark/CorpusIntegrityTest.php` keeps it honest.

## Conventions

- `laravel11-app/`: requires `laravel/framework ^11.0`, has a minimal `composer.lock` (v11.31.0), `bootstrap/app.php` with `withRouting` / `withMiddleware`.
- `laravel10-app/`: requires `laravel/framework ^10.48`, **no lock file** (tests the fallback), `app/Http/Kernel.php`, `RouteServiceProvider::$namespace`, `AuthServiceProvider::$policies`.
- Vulnerable controllers: `App\Http\Controllers\Vuln\`, routes under `/vuln`. Safe ones: `App\Http\Controllers\Safe\`, under `/safe`. Shared models and policies: `App\Models\`, `App\Policies\`.
- Everything sits inside an `auth` middleware group unless the case says otherwise. Routes in `api.php` gain the `/api` prefix.
- Realistic Laravel only: no hint comments such as `// vulnerable`. Explanations go in the `description` field of `expected.yaml`.
- Route keys: `"<METHOD> /<full uri>"`, e.g. `GET /vuln/invoices/{id}`.

## Expectation semantics

- `map`: the depth-0 auth checks with strength above none, compared as sets.
- `candidate: false`: the variant must not be selected for any category.
- Scoring is at symbol level (file + symbol + category). For IDOR cases, a finding categorised `missing_authorization` on the same symbol also counts.
- Route keys are printed as declared, including binding fields (`GET /posts/{post:slug}`).

## Adding a case

1. Write the vulnerable and safe variants and register their routes.
2. Add an entry to `expected.yaml` (`id`, `app`, `category`, `description`, `vulnerable` with `route`/`symbol`/`line`/`map`, `safe` with `route`/`symbol`/`map`). Optional: `suppressed`, `candidate`.
3. Run `vendor/bin/phpunit tests/Integration/Benchmark`.

Public routes that must produce no findings go under `public_routes` (`app`, `route`, `symbol`).
