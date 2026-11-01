# semantic-sec M4 (Candidates, Call Graph, Payloads, `analyze --dry-run`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Decide which routes are worth sending to an LLM, and why. Then build the exact, line-tagged, redacted payload for each, and write them to disk with `semantic-sec analyze --dry-run`, with no network and no API key. Gate: every vulnerable benchmark variant is a candidate, and every `candidate: false` safe variant is not.

**Architecture:** The pieces are:
- **M3 fixes** close the parked over-claims and add an `auth_middleware` config list.
- **Symbol table extensions** add relation targets, the auth user model, class-level `@property`, interface lookups, and a `findProperty`/`isSubclassOf` helper.
- **`CallGraphBuilder`** walks from each route action up to `max_depth`, resolving call targets by static types only.
- **`CandidateSelector`** applies SPEC §7 using the authorization map, plus checks found anywhere in the call graph.
- **`Pruner`, `Redactor` and `TokenEstimator`** turn methods into compact, safe text.
- **`PayloadBuilder`** assembles the SPEC §9 payload (context block, `<untrusted_code>` fence, line tags, splitting).
- **`AnalyzeCommand --dry-run`** writes one file per payload.

**Tech Stack:** As before. No new runtime dependencies.

**Spec:** `docs/SPEC.md` §7 (candidates), §8 (call graph and pruning), §9 (payload), §13 (`--dry-run`), §16 (config). The M3 decisions in §6 bind too. Notably: the map is a pre-filter, so a false "protected" hides a vulnerability. When unsure, a route **is** a candidate.

## Global Constraints

- PHP ^8.2, `declare(strict_types=1)`, `final` classes, `final readonly` value objects, PHPStan level 8, Pint. Tests use `testCamelCase` + `self::assert*`.
- AST only; never run project code. Never crash on real projects: warn as `"<file>:<line>: <message>"` and continue. Never guess types: unresolvable means `null` plus an `unresolved` entry.
- **Conservative direction:**
  - Anything that can't be proven to protect does not exclude a route from candidacy.
  - Anything that can't be proven to be in a payload is **not** silently dropped. It is listed in the payload's "unresolved" section.
- Commands: `docker compose run --rm php <cmd>`. phpunit, `phpstan analyse --memory-limit=512M` and `pint --test` must be clean before each commit. Commits as Tushar Khan with no AI trailer. Branch `m4-candidates-payloads`. One PR (PR 6), then stop.
- **The benchmark is the oracle.** Never edit `benchmark/` to make something pass.
- **Real-app check:** a large real Laravel project, mounted read-only, is used for the "never crash, finishes in reasonable time" checks.

## New and changed types (binding names)

```php
// TusharKhan\SemanticSec\Framework\Laravel
AuthCheck: add `public ?string $model = null` (last ctor param): for query_scope checks, the FQN of the model the scoped query reads, when determinable.
AuthCheckExtractor: add public function bodyChecks(MethodSymbol|Expr\Closure|Expr\ArrowFunction $fn, string $file, array $boundParams /* param name => model FQN */): array{0: list<AuthCheck>, 1: list<string>}
                    // the action-body rules (ability calls, guards, query scopes, helpers) applied to any function body; used for callees

// TusharKhan\SemanticSec\Parsing\CallGraph
final readonly class CallSite { public function __construct(public string $file, public int $line, public bool $conditional) {} }
final readonly class PathNode { public function __construct(public string $id /* "Class::method" or "closure@file:line" */, public ?MethodSymbol $method, public ?Node\FunctionLike $closure, public string $file, public int $startLine, public int $endLine, public int $depth, public ?CallSite $calledFrom, public ?string $calledBy /* parent PathNode id */) {} }
final readonly class ExecutionPath { /** @param list<PathNode> $nodes entry first, BFS order @param list<string> $unresolved "file:line: <call text>" */ public function __construct(public array $nodes, public array $unresolved) {} public function entry(): PathNode; }
final class TypeResolver { public function typeOf(Expr $expr, PathNode $context): ?string /* FQN */ }
final class CallGraphBuilder { public function __construct(SymbolTable $symbols, TypeResolver $types, array $facadeMap, int $maxDepth) {} public function build(RouteEntry $route): ExecutionPath }

// TusharKhan\SemanticSec\Candidates
final readonly class Candidate { /** @param list<Category> $categories @param array<string, string> $reasons category value => one-line reason */ public function __construct(public RouteEntry $route, public ExecutionPath $path, public array $categories, public array $reasons) {} }
final class CandidateSelector { public function select(AuthorizationMap $map, /* ... deps */ bool $deep): array{0: list<Candidate>, 1: list<string>} }

// TusharKhan\SemanticSec\Payload
final readonly class PrunedMethod { /** @param list<array{line:int, text:string}> $lines */ public function __construct(public string $id, public string $file, public int $startLine, public int $endLine, public array $lines) {} }
final class Pruner { public function prune(PathNode $node, array $authHelpers): PrunedMethod }
final class Redactor { public function redact(string $text): string }
final class TokenEstimator { public static function estimate(string $text): int /* ceil(strlen/3.5) */ }
final readonly class Payload { public function __construct(public string $id, public Candidate $candidate, public string $context, public string $code, public int $part, public int $parts, public bool $truncated) {} public function text(): string; public function tokens(): int; }
final class PayloadBuilder { public function build(Candidate $candidate, /* deps */): array{0: list<Payload>, 1: list<string>} }

// TusharKhan\SemanticSec\Framework\FrameworkContext — add:
public function facadeMap(): array;      // short facade name and FQN => underlying class FQN or null when unknown
public function promptContext(): string; // short framework notes for the payload
```

## Review Focus

1. **A vulnerable route wrongly excluded from candidacy** is the worst failure. Every exclusion must cite the check that justifies it, recorded in a `Candidate`-free "excluded" debug list that tests inspect. Pinned in Task 6 (`testEveryExclusionHasAJustification`).
2. **Call-graph explosion or cycles on real code**, e.g. recursive services or huge controllers. BFS with a visited set and `max_depth`; the real-app check must finish under 30 s. Pinned in Task 5 (`testCyclesTerminate`) and Task 10 (real-app timing).
3. **A secret leaking into a payload or dry-run file.** The Redactor runs on the final text, including the context block. Pinned in Task 8 (`testContextBlockIsRedactedToo`).
4. **Line numbers in payloads not matching the source** after pruning or splitting. Every `L<n>|` tag must equal the original line. Pinned in Task 9 (`testEveryLineTagMatchesSource`).
5. **Untrusted code breaking out of the fence**, e.g. a string containing `</untrusted_code>`. Pinned in Task 9 (`testFenceCannotBeClosedFromInside`).

---

### Task 1: M3 leftovers, part 1 (over-claims)

**Files:** Modify `src/Framework/Laravel/AuthCheckExtractor.php`, `AuthExpressions.php`, `BodyPositions.php`, `docs/SPEC.md` §6. Tests go in `tests/Unit/Framework/Laravel/AuthCheckExtractorTest.php`.

**Rules (each gets a failing test first):**
- **P17, tautology:** an auth comparison whose both sides are auth expressions (`auth()->id() === $request->user()->id`) is no check.
- **P18, attacker input:** an auth comparison whose other side reads request input (`$request->input|get|query|post|route…`, `request(...)`, `$request->x`, or a variable whose every assignment is such a read) is no check.
- **P19, deciding without blocking:** a non-throwing ability call in an `if` condition counts only if the branch it gates **blocks**:
  - for `denies`/`cannot`/`!allows`: the if-body contains `abort(`, `abort_if`/`unless`, `throw`, or a `return` of an error response or `redirect()`
  - for `allows`/`can`: the **else** path, or the statements after the `if` when the body returns, blocks
  - otherwise no check
- **P21, `extract()`:** any `extract(...)`, `parse_str(...)` with one argument, or `$$var` in the method taints **all** variables. No variable-based auth expression counts after it.
- **Nested early return:** extend `bypassedBefore` so a `return` of a non-error value **anywhere** inside an earlier sibling statement's conditional body (any depth, excluding nested closures) voids later checks.
- **Abort-guard coverage (needed by Task 6):** an abort guard comparing `$x->prop` with an auth id, where `$x` is an untouched route-bound parameter variable, gets `covers` = that parameter. Other guards keep `covers` null.
- **Query-scope model:** query-scope checks record `model`:
  - the related class for relation reads (via Task 3's relation resolver, so implement after Task 3, or record null here and fill it in Task 3, whichever is cleaner; state the choice in the report)
  - `X` for `X::where(...)` scopes

Update SPEC §6 concisely. Gate: `BenchmarkMapTest` passes unchanged. Commit: `fix: close remaining M3 authorization over-claims`.

### Task 2: M3 leftovers, part 2 (`auth_middleware` config and domain params)

**Files:** `src/Config/Config.php`, `ConfigLoader.php`, `src/Framework/Laravel/MiddlewareRegistry.php`, `RouteCollector.php`, `RouteContext.php`, `PendingRoute.php`, `docs/SPEC.md` §16 and §6. Tests are the existing config, registry and collector tests, plus the extractor.

- **`auth_middleware` config:** add `auth_middleware: []` to `semantic-sec.yaml` (top-level list of strings; unknown-key validation still applies). `Config::$authMiddleware` is a `list<string>`. Each entry is an alias name or a class FQN. `MiddlewareRegistry::kind()` returns `Authentication` for a canonical name whose alias or class matches an entry, or whose class descends from one. Thread it through `MiddlewareRegistry::fromProject` (signature gains `array $authMiddleware = []`) and `LaravelContext`.
- **Domain parameters:** `RouteCollector` reads `domain('<pattern>')` (on a group or a route). Its `{param}`s become `RouteParameter`s (prepended, marked `domain: true`; add `public bool $domain = false` to `RouteParameter`). Binding and coverage treat them like path parameters. `keys()` is unchanged, since the URI is unaffected.
- Tests:
  - config parse plus an unknown-key error
  - an `auth_middleware` alias and class each give Authentication
  - `Route::domain('{account}.x.com')->group(...)` gives an `account` param bound to `Account $account`
- Commit: `feat: configurable auth middleware and domain route parameters`.

### Task 3: Symbol table extensions (relations, auth user, interfaces)

**Files:** `src/Parsing/Symbols/{SymbolTable,SymbolTableBuilder,ClassSymbol,MethodSymbol}.php`. New `src/Parsing/Symbols/RelationResolver.php` and `AuthUserModel.php`. Tests are `tests/Unit/Parsing/Symbols/*` and a benchmark integration test.

**Interfaces:**
- `ClassSymbol` gains:
  - `public array $docProperties = []`: name → type FQN, from class-level `@property`, `@property-read`, `@phpstan-property` and `@psalm-property`
  - `public array $docMethods = []`: name → return-type FQN, from `@method`
- `MethodSymbol` gains `public ?string $returnGeneric = null`: the first class-like generic argument of the return type. `HasMany<Invoice>` → `App\Models\Invoice`, and `@phpstan-return` / `@psalm-return` take precedence over `@return`.
- `SymbolTable` gains:
  - `findProperty(string $class, string $name): ?PropertySymbol`, covering own, traits, then parents
  - `isSubclassOf(string $class, string $ancestor): bool`, covering parents and interfaces with `extends`, transitively, cycle-safe, by name even when the ancestor is not in the table
  - `implementations(string $interface): list<string>`, listing classes in the table implementing it, transitively
- **Constructor-assigned property types:** an untyped property assigned `$this->p = $param;` from a typed constructor parameter takes that type (SPEC §8).
- `RelationResolver::relatedClass(string $model, string $relation): ?string`, for a method `relation()` on `$model`:
  - (a) the class in its body's `return $this->hasOne|hasMany|belongsTo|belongsToMany|hasOneThrough|hasManyThrough|morphOne|morphMany|morphToMany|morphedByMany(X::class, …)`
  - (b) else `returnGeneric`
  - (c) else `docProperties[relation]` / `docMethods[relation]`
  - (d) else null
- `AuthUserModel::resolve(ParseResult, SymbolTable, ConstantEvaluator): ?string`. It reads `config/auth.php` `providers.users.model` (an `Array_` literal, evaluated). Otherwise it falls back to `App\Models\User` if present, else `App\User` if present, else null.

**Tests:**
- benchmark laravel11: `relatedClass('App\Models\User', 'account')` gives `App\Models\Account`
- `HasMany<Invoice>`
- `@property-read`
- `isSubclassOf` through interface `extends`
- `implementations`
- `findProperty` through a trait
- ctor-assigned property type
- `AuthUserModel` with and without `config/auth.php`

Commit: `feat: resolve relations, auth user model and interfaces in the symbol table`.

### Task 4: `TypeResolver` and facade map

**Files:** New `src/Parsing/CallGraph/{TypeResolver,PathNode,CallSite,ExecutionPath}.php`. `FrameworkContext` gains `facadeMap()` and `promptContext()`, with `LaravelContext` implementing them. Tests: `tests/Unit/Parsing/CallGraph/TypeResolverTest.php`.

`TypeResolver::typeOf(Expr, PathNode)` resolves each form below, and returns null otherwise:
- `$this` → the class
- `$this->prop` → `findProperty`, including ctor-assigned and doc properties
- `$var` → a typed parameter of the current function, else the last same-function assignment from `new X`, `X::find*`, `X::where…->first*`, `app(X::class)`, `resolve(X::class)`, or a typed `@var` tag. It follows the M3 variable rule (every assignment agrees).
- auth user expressions → `AuthUserModel`
- `$model->relation` / `$model->relation()` → `RelationResolver`
- `$x->method()` return type → `MethodSymbol::returnType`, or `returnGeneric` for collection-returning queries where useful
- `X::make|create|find|findOrFail|first|firstOrFail` → `X`

`facadeMap()` for Laravel covers `Auth`, `Gate`, `DB`, `Cache`, `Log`, `Storage`, `Route`, `Request`, `Response`, `Session`, `Mail`, `Queue`, `Event`, `Config`, `Validator`, `Hash`, `URL` and `Redirect`. Each maps from its `Illuminate\Support\Facades\X` name and its short alias to a facade id. These are recorded as calls and never traversed.

`promptContext()` is a short, fixed Laravel note (5–8 lines) on route model binding, policies, FormRequests and middleware semantics, so the LLM knows the framework conventions.

Commit: `feat: resolve expression types for the call graph`.

### Task 5: `CallGraphBuilder`

**Files:** New `src/Parsing/CallGraph/CallGraphBuilder.php`. Test: `tests/Unit/Parsing/CallGraph/CallGraphBuilderTest.php`.

**Rules (SPEC §8):**
- BFS from the action (a method, or a closure for closure routes), up to `maxDepth`. The visited set is keyed by `PathNode::$id`.
- **Calls followed:** `$this->m()`, `$this->prop->m()`, `$var->m()`, `X::m()` (static, non-facade), `app(X::class)->m()` / `resolve(X::class)->m()`, and model calls via `TypeResolver`.
- **Recorded but not traversed:** facades, anything in a class not in `SymbolTable` (vendor), and unresolved targets. Each is listed in `ExecutionPath::$unresolved` as `"<file>:<line>: <printed call>"`. Facades are listed under a separate `facade:` prefix so they don't count as unresolved.
- **Interface-typed receiver:** with exactly one implementation (`SymbolTable::implementations`), traverse it and add a note. With several, list them all as unresolved, and don't guess.
- **Call-site conditionality:** each `CallSite::$conditional` uses M3's `BodyPositions` rules, so Task 6 can ignore checks behind conditional calls.
- **Closures passed to calls** (`DB::transaction(fn…)`, collection callbacks) are part of the calling method's body. They are not separate nodes. Their calls are followed with `conditional = true`, except `DB::transaction`, which always runs.

**Tests:**
- benchmark case 7: `Vuln\DownloadController::show` → `DownloadService::find` at depth 1
- depth limit respected
- `testCyclesTerminate`: A→B→A
- facade recorded, not traversed
- vendor class unresolved
- interface with one implementation followed; with two, both listed unresolved
- `app(X::class)->m()`
- closure route as the entry
- conditional call-site flag

Commit: `feat: build execution paths from route actions`.

### Task 6: `CandidateSelector` and the benchmark candidate gate

**Files:** New `src/Candidates/{Candidate,CandidateSelector,Exclusion}.php`. Modify `AuthCheckExtractor` (public `bodyChecks`). Test: `tests/Unit/Candidates/CandidateSelectorTest.php`, and integration `tests/Integration/Candidates/BenchmarkCandidateTest.php`.

**Rules (SPEC §7; record each decision as `Exclusion{route key, category, reason, checkSource}` in a debug list returned alongside the candidates):**
- **Path checks** are the route's map checks, plus `bodyChecks` of every non-entry `PathNode` whose `calledFrom` chain is entirely unconditional, with bound params passed down where a route param variable is passed as an argument. Only Authorization strength counts.
- **`idor`.**
  - **Identifier:** the route has a path or domain parameter, or the path reads `$request->input|get|query|route('id'|'*_id'|'*Id')` / `request(...)` reaching a model lookup.
  - **Excluded only if one of these holds:**
    - (a) an Authorization check with `covers` equal to the identifier's parameter
    - (b) a `query_scope` Authorization check whose `model` equals the model the identifier is looked up on (the bound model, or the model of the `find*`/`where` call that receives the identifier variable). If either model is unknown, this exclusion does **not** apply.
    - (c) a route-wide Authorization check with `covers` null and no model argument: a pure `Gate::allows('admin')`, a role check, or `can:` with no args
  - Several identifiers: excluded only if **every** one is covered.
- **`missing_authorization`.** The route changes state: method POST/PUT/PATCH/DELETE, or the path calls `save|update|delete|destroy|create|forceDelete|restore|insert|upsert` on a model. It has no Authorization check of any kind on the path. **Self-scoped exemption:** every model write is reached through the authenticated user (§7).
- **`mass_assignment`.** The path calls `create|update|fill|forceFill|upsert|firstOrCreate|updateOrCreate` with a mass-input argument (`$request->all()`, `->input()` with no args, `->except(...)`, `request()->all()`, `$request->post()`, or a variable whose every assignment is one of those) on a model, resolved via `TypeResolver`, whose `$guarded` is `[]` or whose `$fillable` intersects `Config::$sensitiveFields`. `validated()` / `safe()` are never mass input.
- **`insecure_deserialization`.** `unserialize(<non-constant>)` anywhere on the path. An `allowed_classes => false` option is still a candidate, but the reason says so.
- **`workflow_bypass`.** The path writes a status-like field (`status|state|stage|step`) via `update([...])`, `->field = `, or calls a method named `cancel|refund|approve|reject|ship|complete|publish|transition*`. It is a candidate unless an unconditional guard on the path compares that same field before the write: `abort_*`, `throw_*`, an `if` that blocks, or an `in_array` check.
- **`--deep`:** turns off exclusions (a)–(c) and the `missing_authorization` authorization exclusion. Routes with no identifier and no state change are never candidates.
- **Paths filter:** routes whose action file is outside `Config::$paths` (when that list is non-empty) are skipped.

**Benchmark gate (`BenchmarkCandidateTest`):**
- every vulnerable variant is a candidate, and its case `category` is among its categories
- every `candidate: false` safe variant is not a candidate for any category
- failure messages list the exclusion or trigger reasons

**`testEveryExclusionHasAJustification`:** every Exclusion has a non-empty `checkSource`, except the "no identifier / no state change" exclusions.

If the gate cannot pass under these rules, stop and report NEEDS_CONTEXT with the case and the rule in conflict. Never edit `benchmark/`.

Commit: `feat: select analysis candidates`.

### Task 7: `Pruner`

**Files:** `src/Payload/{Pruner,PrunedMethod}.php`. Test: `tests/Unit/Payload/PrunerTest.php`.

**Rules (SPEC §8):**
- Output lines come from the **original source text** of the method or closure (via `SourceFile::$code`), keyed by original line number. Never pretty-print, so line tags stay exact.
- **Drop whole lines** that are entirely:
  - comments
  - blank
  - `dd(`/`dump(`/`var_dump(`/`print_r(`/`ray(`/`logger(`/`Log::` statements
  - docblock lines other than `@param`/`@return`/`@var` (keep the `/**` and `*/` lines only if a kept tag remains)
- **Drop entire methods** that are trivial getters or setters, or an empty constructor. The `PrunedMethod` then has a single line `L<start>| // <id>: trivial accessor omitted`.
- **Never drop** a line containing a protected helper call (§8 list) or an `auth_helpers` entry, even if it is a comment-adjacent line. Comments are dropped, but statement lines never are, except the debug calls above.
- Multi-line statements keep all of their lines.

**Tests:**
- line numbers preserved
- comment and blank lines removed
- debug statement removed
- protected helper kept
- getter collapsed
- docblock kept-tags only
- closure entry

Commit: `feat: prune methods for payloads`.

### Task 8: `Redactor` and `TokenEstimator`

**Files:** `src/Payload/{Redactor,TokenEstimator}.php`. Tests: `tests/Unit/Payload/RedactorTest.php`, `TokenEstimatorTest.php`.

**Redactor:** it works on text, not the AST, so it covers the context block too. It replaces **the contents of string literals** (single- or double-quoted, and heredoc and nowdoc bodies) when they match:
- AWS `AKIA[0-9A-Z]{16}`
- `sk-[A-Za-z0-9_-]{20,}`, `sk_live_`/`sk_test_`/`pk_live_`/`rk_live_` + 16+ chars
- `ghp_`/`gho_`/`github_pat_` + 20+ chars
- `xox[abpr]-` Slack tokens
- JWT `eyJ[\w-]+\.[\w-]+\.[\w-]+`
- `-----BEGIN [A-Z ]*PRIVATE KEY-----` blocks
- any literal of 20+ chars with no spaces and Shannon entropy > 4.0

The replacement is `<redacted>`, keeping the quotes.

**Never redacted:** class names (contain `\`), paths (contain `/` and no high-entropy segment), URLs without credentials, route URIs, middleware strings, and `Class::class`.

**TokenEstimator:** `(int) ceil(strlen($text) / 3.5)`.

**Tests:**
- each pattern
- the entropy threshold, on both sides
- normal Laravel code unchanged, using a whole benchmark controller as a fixture: the output equals the input
- `testContextBlockIsRedactedToo`: an `.env`-style value inside a context string

Commit: `feat: redact secrets and estimate tokens`.

### Task 9: `PayloadBuilder`

**Files:** `src/Payload/{Payload,PayloadBuilder}.php`. Tests: `tests/Unit/Payload/PayloadBuilderTest.php`, plus a snapshot test `tests/Integration/Payload/BenchmarkPayloadSnapshotTest.php` with `tests/Fixtures/snapshots/idor-find-by-id.vuln.txt`.

**Format (SPEC §9):** `Payload::text()` is the context block, a blank line, then the code block. The code block is:
```
<untrusted_code>
// FILE: <path> :: <id> (L<start>-L<end>)
L<n>| <line>
...
</untrusted_code>
```

**The context block** is plain text with these sections, each omitted if empty:
- `Route:` the method(s), URI, action, middleware, parameters with bound models, and checks with kind/strength/source/covers
- `Candidate categories:` with reasons
- `FormRequest:` rules keys and the `authorize()` summary
- `Models:` `$fillable`/`$guarded` per model touched on the path
- `Policies:` the relevant policy method bodies, pruned and line-tagged, for the route's bound models
- `Unresolved calls:` from `ExecutionPath`, minus facades
- `Framework notes:` from `promptContext()`

**Fence safety:** any occurrence of `<untrusted_code` or `</untrusted_code` inside the code or the context is replaced by `<untrusted-code-escaped` / `</untrusted-code-escaped`.

**Redaction:** the whole text goes through the `Redactor`.

**Splitting:** if `TokenEstimator::estimate(text) > Config::$maxPayloadTokens`:
- part 1 is the entry plus depth-1 nodes
- then one part per remaining class, grouping that class's nodes
- every part repeats the context block plus an `Upstream summary:` section: the route checks, the FormRequest rules and authorize summary, and any check lines (from `bodyChecks`) in earlier nodes
- a single node still over the limit is cut at the limit, and gets `truncated = true` and a final line `// … truncated`

`Payload::$id` is `<NNN>-<sanitised route key>-<part>`, with `NNN` set by the command.

**Tests:**
- `testEveryLineTagMatchesSource`: every `L<n>| text` equals line n of its file after pruning
- `testFenceCannotBeClosedFromInside`
- context sections present and empty sections absent
- splitting at a tiny limit gives several parts, each with an upstream summary
- truncation flag
- redaction applied
- snapshot for the vulnerable `idor-find-by-id` case. Regenerate it only deliberately, via an env flag `UPDATE_SNAPSHOTS=1`.

Commit: `feat: build analysis payloads`.

### Task 10: `semantic-sec analyze --dry-run`

**Files:** `src/Console/Commands/AnalyzeCommand.php`, a new `src/Console/AnalysisPipeline.php` (extends what `MapBuilder` does: map, then candidates, then payloads), and `src/Console/Application.php`. Tests: `tests/Integration/Console/AnalyzeDryRunTest.php`.

**Options now:** `--project-root`, `--config`, `--framework`, `--deep`, `--dry-run`, `[paths...]`, and `--format=console|json` (for the summary). Without `--dry-run`: exit 2 with `analysis needs the LLM layer (M5); use --dry-run`.

**Dry run:**
- Writes each payload to `<project-root>/.semantic-sec/dry-run/NNN-<sanitised-key>[-pN].txt`. `NNN` is a 3-digit sequence in candidate order. The directory is recreated each run.
- Prints a summary table (route key, categories, parts, tokens), then `<n> candidates, <p> payloads, ~<t> tokens; written to <dir>`, then warnings.
- **No network** (assert it in tests by never constructing any HTTP client), **no API key**.

**Real-app check, in the report:** run `--dry-run` on a read-only mount of the real app at the default memory limit. It must finish with no crash, under 30 s. Report the counts and timing, and grep the output dir for any `AKIA|sk-|BEGIN .*PRIVATE` left un-redacted.

**Tests:**
- the benchmark laravel11 dry run writes one file per candidate payload
- the files contain `<untrusted_code>`
- the vulnerable case symbols are present
- no file for `candidate: false` safe variants
- exit 2 without `--dry-run`
- `--deep` produces at least as many candidates

Then mark M4 done in the roadmap, as a separate `docs:` commit. Commit: `feat: add analyze --dry-run`.
