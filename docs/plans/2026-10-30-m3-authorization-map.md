# semantic-sec M3 (Laravel Authorization Map + `map` command) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build, from the AST alone, the authorization map of a Laravel app. That means every route, its action, its middleware and its parameters, plus every authorization check that protects it, each with a strength. Ship it as `semantic-sec map`, which needs no LLM and no API key. The gate: every `map:` expectation in `benchmark/expected.yaml` must match, on both apps.

**Architecture:** This is a set of small, single-purpose readers under `Framework\Laravel\`. Each one reads the shared `ParseResult` and `SymbolTable` from M2:
- `ConstantEvaluator` turns static PHP expressions into strings or paths.
- `MiddlewareRegistry` holds aliases and groups.
- `RouteFileLocator` finds which route files load, and with what prefix, middleware and namespace.
- `RouteCollector` interprets `Route::` fluent chains into `RouteEntry`s.
- `ControllerMiddlewareReader` reads middleware declared inside controllers.
- `PolicyRegistry` maps models to policies.
- `AuthCheckExtractor` produces `AuthCheck`s.

`LaravelContext` wires all of them, and `MapCommand` prints the result. Nothing ever runs the app's code.

**Tech Stack:** nikic/php-parser 5, symfony/console, plus a **new** dependency `doctrine/inflector ^2.0`. Laravel itself uses it for `Str::singular`; we need it for resource parameter names.

**Spec:** `docs/SPEC.md` §6, the binding source for every rule. Also `benchmark/README.md` "Expectation semantics", and the M2.5 finding that middleware appears both as aliases (`can:`) and as classes (`Illuminate\Auth\Middleware\Authorize:`).

## Global Constraints

- Code goes in namespace `TusharKhan\SemanticSec\Framework\Laravel\` under `src/Framework/Laravel/`, and tests in `tests/Unit/Framework/Laravel/` and `tests/Integration/Framework/Laravel/`.
- PHP ^8.2, `declare(strict_types=1)`, `final` classes, `final readonly` value objects, PHPStan level 8, Pint, and agentic-php test style (`testCamelCase`, `self::assert*`).
- **AST only.** Never `require`, `include` or `eval` project code, and never run artisan.
- **Never crash on real projects.** An unsupported or dynamic construct becomes a warning `"<file>:<line>: <message>"` collected into `AuthorizationMap::$warnings`, and processing continues.
- **Never guess.** If a value can't be resolved statically, it's `null` plus a warning, never a made-up string.
- Commands: `docker compose run --rm php <cmd>`. Before each commit, all of these pass: phpunit, `phpstan analyse --memory-limit=512M`, `pint --test`.
- Commits as Tushar Khan with no AI trailer. Branch `m3-auth-map` (stacked on `m2.5-benchmark-verify`). PR 5 targets `main` after PR 4 is merged. One PR, then stop.
- **The benchmark is the oracle.** Never edit `benchmark/` to make the map pass. A disagreement means the code is wrong, unless SPEC §6 literally says otherwise. In that case stop and report.

## Shared types (binding names; Task 1 creates them)

```php
enum AuthStrength: string { case None = 'none'; case Authentication = 'authentication'; case Authorization = 'authorization'; }

final readonly class AuthCheck {
    public function __construct(public AuthCheckKind $kind, public AuthStrength $strength, public string $source, public string $file, public int $line) {}
}
final readonly class RouteParameter {
    public function __construct(public string $name, public ?string $field, public bool $optional, public ?string $boundModel = null) {}
}
final readonly class RouteAction {
    public function __construct(public ?string $class, public ?string $method, public ?\PhpParser\Node\Expr $closure = null) {}
    public function isClosure(): bool;            // closure !== null
    public function symbol(): ?string;            // "Class::method" or null for closures
}
final readonly class RouteEntry {
    /** @param list<string> $methods upper-case as declared (no implicit HEAD) @param list<string> $middleware declared + group/inherited, raw-resolved strings @param list<string> $withoutMiddleware @param list<RouteParameter> $parameters @param list<AuthCheck> $checks */
    public function __construct(public array $methods, public string $uri /* leading "/", as declared incl. {p:field} */, public ?string $name, public RouteAction $action, public array $middleware, public array $withoutMiddleware, public array $parameters, public ?bool $scopeBindings /* null = default, true = scopeBindings(), false = withoutScopedBindings() */, public string $file, public int $line, public array $checks = []) {}
    /** @return list<string> e.g. ["GET /vuln/invoices/{id}"] */
    public function keys(): array;
    public function withChecks(array $checks): self;
    public function withParameters(array $parameters): self;
}
final readonly class AuthorizationMap {
    /** @param list<RouteEntry> $routes @param list<string> $warnings */
    public function __construct(public array $routes, public array $warnings) {}
    public function find(string $key): ?RouteEntry;   // exact key match
}
interface \TusharKhan\SemanticSec\Framework\FrameworkContext {
    public function name(): string;
    public function buildAuthorizationMap(ParseResult $parsed, SymbolTable $symbols, Config $config, DetectedFramework $framework): AuthorizationMap;
}
```

`AuthCheckKind` already exists (M0). Its cases are `authentication`, `route_ability`, `controller_ability`, `form_request`, `abort_guard`, `query_scope` and `custom_helper`.

## Review Focus

1. **Real route files use constructs we don't model:** `if` blocks, `foreach` loops over arrays of routes, `Route::fallback`, `Route::view`/`redirect`, `$router->get`, macros. Each must produce a warning and be skipped, never an exception. Pinned in Task 4 (`testUnsupportedConstructsWarnAndContinue`).
2. **Middleware written as classes rather than aliases**, e.g. `->middleware(Authenticate::class)` or `Authorize::class.':view,post'`, or an app subclass such as `App\Http\Middleware\Authenticate`. These must classify the same as `auth` and `can:`. Pinned in Task 2 (`testClassAndSubclassMiddlewareNormaliseToAliases`).
3. **A route file referenced but missing, or a provider that loads routes from a computed path.** That gives a warning, and the defaults are still used. Pinned in Task 3 (`testMissingRouteFileWarns`, `testUnresolvablePathWarns`).
4. **A policy method that is missing (Laravel denies) versus one that is trivially `return true;` (allows).** Only the second has strength `None`. Pinned in Task 7 (`testMissingPolicyMethodIsNotTrivial`).
5. **The same check appearing twice**, e.g. `auth` in both the group and `HasMiddleware`. Maps are compared as sets, so duplicates must not break the benchmark gate or confuse output. Pinned in Task 9 (the gate compares sets) and Task 10 (output de-duplicates by kind and source).

---

### Task 1: Hygiene, shared types, `ConstantEvaluator`

**Files:**
- Modify: `tests/Unit/Parsing/ProjectParserTest.php`. This fixes the parked M2 item: the `ssboom` stream wrapper is unregistered and `ExplodingStream::$files` is reset in `tearDown`.
- Create: the shared types above (`AuthStrength`, `AuthCheck`, `RouteParameter`, `RouteAction`, `RouteEntry`, `AuthorizationMap`, `Framework/FrameworkContext`), and `src/Framework/Laravel/ConstantEvaluator.php`.
- Test: `tests/Unit/Framework/Laravel/RouteEntryTest.php`, `ConstantEvaluatorTest.php`

**Interfaces (produces):**
- `final class ConstantEvaluator`:
  - `public function string(Node\Expr $expr, string $file, ?ClassSymbol $class = null): ?string`
  - `public function path(Node\Expr $expr, string $file, ?ClassSymbol $class = null): ?string`
  - `public static function normalisePath(string $path): ?string`
- `string()` supports:
  - `String_`
  - interpolated strings without variables
  - `Concat`
  - `ClassConstFetch` `X::class`, giving the FQN without a leading `\`
  - `MagicConst\Dir` (the dirname of `$file`, project-relative)
  - `PropertyFetch` `$this->prop`, which returns `$class->properties[prop]->default` if that is itself evaluable
  - `ClassConstFetch` `self::X`/`static::X`, read from `$class->node`
- Anything else returns `null`.
- `path()` additionally supports `base_path(x?)`, `app_path(x?)`, `dirname(x[, n])`, `__DIR__`. It returns a project-relative path normalised by `normalisePath`: `.` and `..` segments are resolved, duplicate `/` collapsed, and a leading `/` removed. It returns `null` if the path escapes the project root.

- [ ] **Step 1: Failing tests.**
  - `RouteEntryTest`:
    - `keys()` for `['GET']` / `/vuln/invoices/{id}` gives `['GET /vuln/invoices/{id}']`.
    - `['PUT','PATCH']` gives two keys.
    - `withChecks` returns a new instance, leaving the original's `checks` unchanged.
    - `AuthorizationMap::find` gives a hit and a miss.
    - `RouteAction` `symbol()` is `App\X::show` for a class action, and `null` with `isClosure()` true for a closure action.
  - `ConstantEvaluatorTest` (parse snippets through `AstGenerator`):
    - `'a'.'b'` → `ab`
    - `Foo::class` with `use App\Foo` → `App\Foo`
    - `__DIR__.'/../routes/web.php'` in `bootstrap/app.php` → path `routes/web.php`
    - `base_path('routes/api.php')` → `routes/api.php`
    - `dirname(__DIR__)` in `bootstrap/app.php` → `''` (the project root)
    - `$this->namespace` with a property default `'App\\Http\\Controllers'` → `App\Http\Controllers`
    - `$var` → `null`
    - `__DIR__.'/../../x'` from `bootstrap/app.php` → `null` (it escapes the root)
  - `ProjectParserTest`: after `tearDown`, `in_array('ssboom', stream_get_wrappers(), true)` is false.
- [ ] **Step 2:** Run them and confirm they fail. **Step 3:** Implement. **Step 4:** Run them and confirm they pass, plus the checks.
- [ ] **Step 5: Commit** `feat: add authorization map types and constant evaluator`.

### Task 2: `MiddlewareRegistry`

**Files:** Create `src/Framework/Laravel/MiddlewareRegistry.php` and `MiddlewareKind.php`. Test: `tests/Unit/Framework/Laravel/MiddlewareRegistryTest.php`.

**Interfaces (produces):**
- `enum MiddlewareKind: string { case Authentication = 'authentication'; case Ability = 'ability'; case Other = 'other'; }`
- `final class MiddlewareRegistry`:
  - `public const DEFAULT_ALIASES`: Laravel 12's `Middleware::defaultAliases()`. `auth` → `Illuminate\Auth\Middleware\Authenticate`, `auth.basic` → `…\AuthenticateWithBasicAuth`, `auth.session` → `Illuminate\Session\Middleware\AuthenticateSession`, `can` → `Illuminate\Auth\Middleware\Authorize`, `guest` → `…\RedirectIfAuthenticated`, `password.confirm` → `…\RequirePassword`, `signed` → `Illuminate\Routing\Middleware\ValidateSignature`, `throttle` → `Illuminate\Routing\Middleware\ThrottleRequests`, `verified` → `Illuminate\Auth\Middleware\EnsureEmailIsVerified`, `cache.headers`, `precognitive`, `subscribed`.
  - `public const DEFAULT_GROUPS = ['web' => [], 'api' => []]`. The framework's group members are never auth-relevant, so we keep only the names.
  - `public function __construct(array $aliases, array $groups, SymbolTable $symbols)`
  - `public static function fromProject(ParseResult $parsed, SymbolTable $symbols, DetectedFramework $fw, ConstantEvaluator $eval): array{0: self, 1: list<string>}` returns the registry and its warnings.
  - `public function canonical(string $middleware): string` returns `alias[:params]`. A class name that is an alias target becomes that alias. A class whose parent chain (via `SymbolTable`) reaches an alias target also becomes that alias. A string with no match is returned unchanged.
  - `public function expand(array $middleware): array` returns the canonical list with groups expanded recursively. It is cycle-safe, de-duplicated and keeps order.
  - `public function kind(string $canonical): MiddlewareKind`. These are `Authentication`: `auth`, `auth:*`, `auth.basic`, `auth.session`, `verified`, `signed`. These are `Ability`: `can:*`. Everything else is `Other`.
  - `public function ability(string $canonical): ?array` returns `array{ability: string, arguments: list<string>}` for `can:`.
- **Sources:**
  - **Kernel (L≤10)**: the class whose parent chain includes `Illuminate\Foundation\Http\Kernel`. Read the defaults of `$middlewareAliases`, `$routeMiddleware` and `$middlewareGroups` (`Array_` with string or class-const values, evaluated via `ConstantEvaluator`).
  - **bootstrap/app.php (L11+)**: inside the `withMiddleware(function (Middleware $m) {...})` closure, read `$m->alias([...])`, `->web(append: [...] | prepend:)`, `->api(...)`, `->group('name', [...])`, `->appendToGroup('name', x)` and `->prependToGroup`.
  - **Both** start from the defaults. App entries override.

- [ ] **Step 1: Failing tests**:
  - `testDefaultAliasesCanonicaliseClassForms`: `Illuminate\Auth\Middleware\Authorize:view,invoice` → `can:view,invoice`; `Illuminate\Auth\Middleware\Authenticate` → `auth`.
  - `testClassAndSubclassMiddlewareNormaliseToAliases`: a snippet `class Authenticate extends \Illuminate\Auth\Middleware\Authenticate {}` in `App\Http\Middleware` → `canonical('App\Http\Middleware\Authenticate:sanctum')` is `auth:sanctum`.
  - `testKernelAliasesAndGroupsAreRead`: the laravel10-app benchmark has `can` → `Illuminate\Auth\Middleware\Authorize`, and groups `web` and `api` exist.
  - `testBootstrapWithMiddlewareIsRead`: a snippet with `$middleware->alias(['owner' => \App\Http\Middleware\EnsureOwner::class]); $middleware->group('admin', ['auth', 'can:admin']);` → `expand(['admin'])` is `['auth', 'can:admin']`.
  - `testExpandIsCycleSafe`: groups `a → [b]`, `b → [a, auth]` → `['auth']`.
  - `testKindAndAbility`: `auth:sanctum` → `Authentication`; `verified` → `Authentication`; `can:update,post` → `Ability` with `['ability' => 'update', 'arguments' => ['post']]`; `throttle:60,1` → `Other`.
- [ ] **Steps 2–4:** fail, then implement, then pass and run the checks. **Step 5: Commit** `feat: resolve Laravel middleware aliases and groups`.

### Task 3: `RouteFileLocator`

**Files:** Create `src/Framework/Laravel/RouteFile.php` and `RouteFileLocator.php`. Test: `tests/Unit/Framework/Laravel/RouteFileLocatorTest.php`.

**Interfaces (produces):**
- `final readonly class RouteFile { public function __construct(public string $path, public string $prefix, public array $middleware, public ?string $namespace) {} }` (`middleware`: `list<string>`)
- `final class RouteFileLocator { public function locate(ParseResult $parsed, SymbolTable $symbols, DetectedFramework $fw, Config $config, ConstantEvaluator $eval): array{0: list<RouteFile>, 1: list<string>} }`
- **Rules:**
  - **L11+ (`bootstrap/app.php` exists and calls `withRouting`):**
    - named arg `web:` → `RouteFile(path, '', ['web'], null)`
    - `api:` → `RouteFile(path, apiPrefix ?? 'api', ['api'], null)`. Honour a named `apiPrefix:` arg.
    - `commands:`, `health:` and `channels:` are ignored.
    - a `then:` closure → warning `then: routes are not analysed`
  - **L≤10:** in classes whose parent chain includes `Illuminate\Foundation\Support\Providers\RouteServiceProvider`, walk `boot()` and any `map*()` method, including inside `$this->routes(function () {...})`. Each `Route::…->group(<path expr>)` chain gives a `RouteFile` with that chain's `prefix`, `middleware` and `namespace` (a `namespace($this->namespace)` is evaluated against the provider's property).
  - **Fallback:** if nothing was found, use `routes/web.php` (web) and `routes/api.php` (`api` prefix plus `api` middleware), for whichever exist.
  - **Config:** `Config::$laravelRouteFiles` entries are appended as `RouteFile(path, '', [], null)`.
  - **Warnings:**
    - a path that is referenced but not in `ParseResult` → `route file <path> not found`
    - an unevaluable path → `<file>:<line>: route file path could not be resolved`
  - The result is de-duplicated by path, first wins.

- [ ] **Step 1: Failing tests**:
  - `testLaravel11WithRouting`: the laravel11-app benchmark gives `routes/web.php` (`''`, `['web']`) and `routes/api.php` (`'api'`, `['api']`).
  - `testLaravel10RouteServiceProvider`: the laravel10-app benchmark gives `routes/api.php` (`'api'`, `['api']`, `App\Http\Controllers`) and `routes/web.php` (`''`, `['web']`, `App\Http\Controllers`).
  - `testApiPrefixArgument`: `apiPrefix: 'v1'` gives prefix `v1`.
  - `testFallbackDefaults`: a temp project with only route files gives both defaults.
  - `testConfigRouteFilesAppended`.
  - `testMissingRouteFileWarns`.
  - `testUnresolvablePathWarns`: `->group($path)` with a variable.
- [ ] **Steps 2–4**, then **Step 5: Commit** `feat: locate Laravel route files`.

### Task 4: `RouteCollector` I (verbs, actions, groups)

**Files:** Create `src/Framework/Laravel/RouteCollector.php` and `RouteContext.php` (immutable group state). Test: `tests/Unit/Framework/Laravel/RouteCollectorTest.php`.

**Interfaces (produces):**
- `final class RouteCollector`:
  - `public function __construct(ParseResult $parsed, ConstantEvaluator $eval)`
  - `public function collect(RouteFile $file): array{0: list<RouteEntry>, 1: list<string>}`
- **Rules:**
  - **Recognising route chains:** interpret expression statements whose call chain is rooted at a static call on the `Route` facade (`Illuminate\Support\Facades\Route`, or a name that resolves to it).
  - **Flattening:** flatten each chain into `(method, args)` steps from the root.
  - **Attribute steps** (before a verb or group) accumulate into `RouteContext`:
    - `prefix`, `name`, `middleware` (string or array), `withoutMiddleware`, `controller`, `namespace`, `scopeBindings`, `can(ability, model)` (which becomes middleware `can:ability,model`), `domain` (ignored)
  - **Verbs:**
    - `get|post|put|patch|delete|options`
    - `any` → `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`
    - `match([...], uri, action)`
  - **Steps after a verb** (applied to that route only): `middleware`, `withoutMiddleware`, `name`, `can`, `scopeBindings`. Ignore `where*` and `whereNumber`.
  - **Groups:**
    - `group(Closure|ArrowFunction)` recurses into the body statements with the merged context.
    - `group(<path expr>)` loads that file from `ParseResult` with the merged context.
    - Array style `Route::group(['prefix'=>…,'middleware'=>…,'namespace'=>…,'as'=>…], fn)` is equivalent.
  - **Prefixes** join with `/`, trimmed. The URI gets a leading `/`, and the file's prefix comes first.
  - **Actions:**
    - `[X::class, 'm']` → `(X, m)`
    - `'Ctrl@m'` → (namespace-prefixed `Ctrl` unless it starts with `\`, `m`)
    - `X::class` alone → `(X, '__invoke')`
    - `Closure`/`ArrowFunction` → a closure action
    - with `controller(X::class)` in the context, a string action `'m'` → `(X, m)`
  - **Parameters:** parsed from the URI as `{name}`, `{name?}` and `{name:field}`.
  - **Middleware** on each entry is the file's middleware, then the group's, then the route's. These are raw strings; canonicalisation happens later. `withoutMiddleware` is kept separately.
  - **Warnings, then skip:** any other statement inside a group body (`if`, `foreach` and so on), any unknown chain step, and any non-`Route` call (`$router->get`).
  - `Route::view`, `redirect`, `fallback` and `permanentRedirect` give warning `<file>:<line>: Route::<m> is not analysed`.
  - `file` and `line` are those of the verb call.

- [ ] **Step 1: Failing tests**, using inline route snippets written to a temp project, plus the benchmark:
  - `testBenchmarkLaravel11WebRoutes`:
    - `GET /vuln/invoices/{id}` exists with action `App\Http\Controllers\Vuln\InvoiceController::show` and middleware `['web','auth']`.
    - `GET /safe/invoices/{invoice}/pdf` includes `can:view,invoice`.
    - `GET /posts/{post:slug}` has middleware `['web']` and parameter `post` with field `slug`.
  - `testBenchmarkLaravel11ApiRoutes`: `PUT /api/vuln/cart` has middleware `['api','auth:sanctum']`.
  - `testStringActionsUseNamespace`: laravel10-app `GET /vuln/reports/{report}` → `App\Http\Controllers\Vuln\ReportController::show`.
  - `testMatchAnyAndInvokable`.
  - `testArrayGroupSyntax`.
  - `testControllerGroupWithMethodNames`.
  - `testRouteLevelCanAndScopeBindings`.
  - `testClosureActionIsKept`: `isClosure()` is true and `symbol()` is null.
  - `testUnsupportedConstructsWarnAndContinue`: an `if` block, a `foreach` and `Route::fallback` each give one warning, and the route after them is still collected.
- [ ] **Steps 2–4**, then **Step 5: Commit** `feat: collect Laravel routes from route files`.

### Task 5: `RouteCollector` II (resources)

**Files:** Modify `RouteCollector.php`. Add `doctrine/inflector ^2.0` to `composer.json` `require` and commit the lock. Test: `tests/Unit/Framework/Laravel/RouteCollectorResourceTest.php`.

**Rules (Laravel's `ResourceRegistrar`):**
- **`Route::resource(name, controller)`:**
  - `index` → GET `/{name}`
  - `create` → GET `/{name}/create`
  - `store` → POST `/{name}`
  - `show` → GET `/{name}/{p}`
  - `edit` → GET `/{name}/{p}/edit`
  - `update` → PUT, PATCH `/{name}/{p}`
  - `destroy` → DELETE `/{name}/{p}`
- `apiResource` drops `create` and `edit`.
- **Parameter name `{p}`:** the singular of the name's **last** `/`-segment, via `InflectorFactory::create()->build()->singularize()`, with `-` replaced by `_`.
- **Dotted names (nested):** `photos.comments` → `/photos/{photo}/comments/{comment}`, where the parent parameter is the singular of the parent segment.
- **Modifiers:** `only([...])`, `except([...])`, `names(...)` (string prefix or array), `parameters([...])`, `middleware(...)`, `scopeBindings()`.
- A string controller gets the group namespace.

- [ ] **Step 1: Failing tests**:
  - `testResourceExpandsSevenActions`.
  - `testApiResource`.
  - `testOnlyExcept`.
  - `testBenchmarkLaravel10NotesResource`: `GET /vuln/notes/{note}` → `App\Http\Controllers\Vuln\NoteController::show`, and there is no `create`/`edit` route.
  - `testNestedResource`.
  - `testIrregularSingular`: `people` → `{person}`, `categories` → `{category}`.
  - `testParametersOverride`.
- [ ] **Steps 2–4**, then **Step 5: Commit** `feat: expand Laravel resource routes`.

### Task 6: `ControllerMiddlewareReader`

**Files:** Create `src/Framework/Laravel/ControllerMiddlewareReader.php`. Test: `tests/Unit/Framework/Laravel/ControllerMiddlewareReaderTest.php`.

**Interfaces:**
- `final class ControllerMiddlewareReader`:
  - `public function __construct(SymbolTable $symbols, ConstantEvaluator $eval)`
  - `public function forAction(string $class, string $method): array{0: list<string>, 1: list<string>}` returns the middleware and the warnings.
- **Rules:**
  - **L≤10:** in `__construct` (walking the parent chain while the class is in `SymbolTable`), handle `$this->middleware(<x>)` with an optional `->only(<x>)`/`->except(<x>)`. `<x>` is a string, an array of strings, or a class-const concatenation.
  - **L11+:** if the class implements `Illuminate\Routing\Controllers\HasMiddleware`, read the static `middleware()` return `Array_` items:
    - a string or class-const → applies to all methods
    - `new Middleware(<x>, only: [...], except: [...])` (named or positional args) → as written
    - a closure → warning
  - `only`/`except` are matched case-insensitively against the method name.

- [ ] **Step 1: Failing tests**:
  - `testConstructorMiddlewareOnlyExcept`: laravel10-app `Safe\ReportController::show` gives `['auth','can:view,report']`, and a method not in `only` gives `['auth']`.
  - `testHasMiddleware`: laravel11-app `Safe\DocumentController::show` gives `['auth','can:view,document']`.
  - `testInheritedConstructorMiddleware`.
  - `testClosureMiddlewareWarns`.
  - `testUnknownClassReturnsEmpty`.
- [ ] **Steps 2–4**, then **Step 5: Commit** `feat: read controller-declared middleware`.

### Task 7: `PolicyRegistry`

**Files:** Create `src/Framework/Laravel/PolicyRegistry.php`. Test: `tests/Unit/Framework/Laravel/PolicyRegistryTest.php`.

**Interfaces:**
- `final class PolicyRegistry`:
  - `public static function fromProject(SymbolTable $symbols, ConstantEvaluator $eval): array{0: self, 1: list<string>}`
  - `public function policyFor(string $model): ?string`
  - `public function isTrivial(string $policy, string $ability): bool`
  - `public function abilityHolder(string $policy, string $ability): ?MethodSymbol`
- **Rules:**
  - **Registered `$policies`:** read the `$policies` property defaults of classes whose parent chain includes `Illuminate\Foundation\Support\Providers\AuthServiceProvider`.
  - **`Gate::policy(A::class, B::class)`** calls found anywhere in methods of classes whose parent chain includes `Illuminate\Support\ServiceProvider`.
  - **Auto-discovery:** for model `App\Models\X`, use `App\Policies\XPolicy`. For `App\X`, also `App\Policies\XPolicy`. Only if that class exists in `SymbolTable`.
  - **Precedence:** registration wins over discovery.
  - **`isTrivial`:** true only when the ability method exists (via `SymbolTable::findMethod`) and its body is exactly one `Return_` of `true` (`ConstFetch true`). A missing method gives false, because Laravel denies.

- [ ] **Step 1: Failing tests**:
  - `testGatePolicyRegistration`: laravel11-app `App\Models\Reply` → `App\Policies\ReplyOwnershipPolicy`, which is non-trivial for `delete`.
  - `testTrivialPolicy`: `App\Models\Comment` → `CommentPolicy`, trivial for `delete`.
  - `testPoliciesProperty`: laravel10-app `App\Models\Note` → `App\Policies\NoteAccessPolicy`.
  - `testAutoDiscovery`: laravel11-app `App\Models\Invoice` → `App\Policies\InvoicePolicy`.
  - `testMissingPolicyMethodIsNotTrivial`.
  - `testNoPolicyReturnsNull`.
- [ ] **Steps 2–4**, then **Step 5: Commit** `feat: map models to policies`.

### Task 8: `AuthCheckExtractor`

**Files:** Create `src/Framework/Laravel/AuthCheckExtractor.php` and `AuthExpressions.php` (helpers that recognise the authenticated user, the auth id, and query reads). Test: `tests/Unit/Framework/Laravel/AuthCheckExtractorTest.php`. Its snippets are built as small temp projects, so the extractor runs on real parsed code.

**Interfaces:**
- `final class AuthCheckExtractor`:
  - `public function __construct(SymbolTable $symbols, MiddlewareRegistry $middleware, PolicyRegistry $policies, ControllerMiddlewareReader $controllerMiddleware, array $authHelpers)`
  - `public function extract(RouteEntry $route): array{0: RouteEntry, 1: list<string>}` returns the route with `parameters` (bound models filled) and `checks` set, plus warnings.

**Rules (SPEC §6, exact):**
1. **Bound models.** For each route parameter, if the action method has a parameter of the same name whose type is a class in `SymbolTable` (or any class not in a scalar list), set `boundModel`.
2. **Middleware.** Expand the route middleware plus the controller middleware, minus `withoutMiddleware`, through `MiddlewareRegistry`.
   - `Authentication` kind → `AuthCheck(Authentication, Authentication, "middleware <m>")`
   - `can:ability,arg` → `AuthCheck(RouteAbility, …)`. The strength is `None` when `arg` names a route parameter whose bound model's policy `isTrivial(ability)`, or when `arg` is a class whose policy is trivial. Otherwise it's `Authorization`.
3. **Scoped bindings.** `scopeBindings` true → `QueryScope`, `Authorization`.
4. **`authorizeResource`.** `authorizeResource(Model::class, 'param')` in the controller constructor (parent chain included) maps the action to an ability: `index`→`viewAny`, `show`→`view`, `create`/`store`→`create`, `edit`/`update`→`update`, `destroy`→`delete`. That gives `ControllerAbility`. It's `None` if trivial; an unmapped method gives nothing.
5. **Action body.** The action method body, or the closure body, at depth 0 only:
   - **Ability calls** → `ControllerAbility`:
     - `$this->authorize('ab', $x)` and `authorizeForUser`
     - `Gate::authorize|allows|denies|check|any|none|inspect('ab', $x)`
     - `->can|cannot|cant('ab', $x)` on an authenticated-user expression or on a `$user` param

     The strength is `None` if `$x`'s model (a param type, or `X::class`) has a trivial policy for `ab`; otherwise it's `Authorization`.
   - **Guard calls** → `AbortGuard`: `abort_if|abort_unless|throw_if|throw_unless`, when the first argument's subtree contains an authenticated-user or auth-id expression. Any other condition gives nothing.
   - **`QueryScope`**, either form:
     - (a) a method-call chain rooted at an authenticated-user expression, where the first call after the root is a method call (a relation) and some later call is a read (`find`, `findOrFail`, `findMany`, `first`, `firstOrFail`, `sole`, `get`, `paginate`, `simplePaginate`, `cursor`, `exists`, `count`, `pluck`, `value`, `where*`). A `PropertyFetch` relation (`->account`), or only writes (`create`, `update`, `updateOrCreate`, `firstOrCreate`, `firstOrNew`, `save`, `delete`), gives nothing.
     - (b) any `where|orWhere(<col>, [<op>,] <auth-id expr>)` or `whereBelongsTo(<auth-user expr>)`.
   - **Custom helpers** → `CustomHelper`: a call whose method name, or `Class::method` FQN, is in `authHelpers`.
6. **FormRequest.** An action parameter whose type's parent chain includes `Illuminate\Foundation\Http\FormRequest` → `FormRequest`. The strength is `Authorization` unless `authorize()` is missing (Laravel allows) or is exactly `return true;`, in which case it's `None`.
7. **Expressions.**
   - **Authenticated-user expressions:** `auth()->user()`, `Auth::user()`, `$request->user()`, `request()->user()`, `$this->user()` (FormRequest), `Auth::guard(..)->user()`.
   - **Auth-id expressions:** `auth()->id()`, `Auth::id()`, and `<auth-user expr>->id` / `->getKey()`.
8. **Source strings** are short and human, e.g. `middleware can:view,invoice`, `$this->authorize('update', $invoice)`, `CommentPolicy::delete returns true`, `FormRequest UpdateInvoiceRequest::authorize returns true`.
9. **Unresolved action.** An action class or method not found in `SymbolTable` gives warning `<file>:<line>: action <symbol> not found` and only the middleware checks.

- [ ] **Step 1: Failing tests**, one per rule, at least:
  - `testAuthMiddlewareIsAuthentication`.
  - `testRouteCanWithTrivialPolicyIsNone`.
  - `testHasMiddlewareCanIsRouteAbility`.
  - `testAuthorizeResourceMapsShowToView`.
  - `testThisAuthorizeIsControllerAbility`.
  - `testTrivialPolicyAuthorizeIsNone`.
  - `testGateAndUserCanForms`.
  - `testAbortGuardOnlyWithAuthExpression`: `abort_unless($order->status === 'paid')` gives nothing; `abort_if($post->user_id !== auth()->id(), 403)` gives `AbortGuard`.
  - `testQueryScopeRelationRead`.
  - `testRelationWriteIsNotScope`: `->account->update`, `->workspaces()->create`.
  - `testWhereAuthIdIsScope`.
  - `testWhereBelongsTo`.
  - `testCustomHelper`.
  - `testFormRequestTrivialIsNone`.
  - `testFormRequestWithLogicIsAuthorization`.
  - `testMissingFormRequestAuthorizeIsNone`.
  - `testClosureActionBodyAnalysed`.
  - `testWithoutMiddlewareRemovesAuth`.
  - `testUnknownActionWarns`.
- [ ] **Steps 2–4**, then **Step 5: Commit** `feat: extract authorization checks for routes`.

### Task 9: `LaravelContext` and the benchmark gate

**Files:** Create `src/Framework/Laravel/LaravelContext.php`. Test: `tests/Integration/Framework/Laravel/BenchmarkMapTest.php`.

**Interfaces:** `final class LaravelContext implements FrameworkContext`, with `name()` returning `laravel` and `buildAuthorizationMap(...)` wiring Tasks 1–8:
1. evaluator
2. registry
3. locator
4. collector per file
5. controller middleware
6. policies
7. extractor per route

Warnings from every stage are concatenated in that order. Routes are kept in collection order.

- [ ] **Step 1: Failing tests**:
  - `BenchmarkMapTest::testEveryExpectedMapMatches`, for both apps:
    - parse the project with `ProjectParser`, build `SymbolTable`, load `Config` (defaults) and run `FrameworkDetector`
    - for every case variant, `find(route)` must not be null
    - the set of `checks` kinds with `strength !== None` must equal the `map` set
    - the failure message lists the case id, variant, expected set and actual set
  - `testPublicRoutesHaveNoChecks`: every `public_routes` entry is found, with no check whose strength is not `None`.
  - `testEveryExpectedRoutePointsAtItsSymbol`: `action->symbol()` equals the expected `symbol`.
  - `testNoUnexpectedWarningsOnBenchmark`: the warnings list for each app is empty, or a list fixed in the test with the reason for each.
- [ ] **Step 2:** Run and see the failures. **Step 3:** Implement and fix the earlier components where the gate reveals gaps, without changing `benchmark/`. **Step 4:** All pass.
- [ ] **Step 5: Commit** `feat: build the Laravel authorization map`.

### Task 10: `semantic-sec map` command

**Files:** Create `src/Console/Commands/MapCommand.php` and `src/Console/ExitCode.php`. Modify `src/Console/Application.php` to register the command. Test: `tests/Integration/Console/MapCommandTest.php`.

**Interfaces:**
- `final class ExitCode { public const OK = 0; public const FINDINGS = 1; public const ERROR = 2; public const BUDGET = 3; }` (SPEC §13)
- `map` options:
  - `--project-root` (default `getcwd()`)
  - `--config`
  - `--framework`
  - `--format=console|json` (default `console`)
- **Pipeline:** `ConfigLoader` → `FrameworkDetector` → `ProjectParser` (with `Config::$exclude`) → `SymbolTableBuilder` → `LaravelContext`.
- **Console format:** a Symfony `Table` with columns `Method`, `URI`, `Action`, `Checks`.
  - Checks show as `kind` for authorization strength, `kind (auth only)` for authentication, and `kind (none: <source>)` for `None`.
  - Duplicates are collapsed by kind and source.
  - Next comes a summary line: `<n> routes: <a> with authorization, <b> authentication only, <c> unprotected`.
  - Then a `Warnings` section listing parse failures, symbol duplicates and failures, and map warnings.
- **JSON format:** `{"framework":{"name","major"},"routes":[{"methods","uri","name","action","middleware","parameters":[{"name","field","optional","boundModel"}],"checks":[{"kind","strength","source","file","line"}]}],"warnings":[...]}`, pretty-printed with unescaped slashes.
- **Exit codes:** `0`. A `ConfigException` or `FrameworkNotDetected` gives `2`, with the message on stderr.

- [ ] **Step 1: Failing tests** (`CommandTester`):
  - `testConsoleOutputOnBenchmark`: laravel11-app shows `/vuln/invoices/{id}` and a summary line matching `/\d+ routes: \d+ with authorization/`.
  - `testJsonOutputShape`: decode the output; `routes[*].checks[*].kind` values are valid `AuthCheckKind`s, and `framework.major` is 11.
  - `testNoFrameworkExitsTwo`: an empty temp dir gives 2 and stderr containing `--framework`.
  - `testDuplicateChecksCollapsedInConsole`.
- [ ] **Steps 2–4.** Also run `docker compose run --rm php bin/semantic-sec map --project-root=benchmark/laravel10-app` by hand and paste the output into the report.
- [ ] **Step 5: Commit** `feat: add semantic-sec map command`.
- [ ] **Step 6:** In the roadmap, mark M3 tasks 14–20 as done, with "see `docs/plans/2026-10-30-m3-authorization-map.md`". Commit that as `docs: mark M3 done in roadmap`.
