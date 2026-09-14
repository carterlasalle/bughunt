<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
# BugHunt default rule pack

BugHunt ships repository-native rules in addition to every enabled rule from Ruff, the type checkers, Pylint/extensions, Bandit, Semgrep, CodeQL, and other engines.

Run:

```bash
uv run bughunt rules
```

to see the installed native pack.

The native rules are intentionally conservative where a repository's semantics cannot be proven. High-confidence control-flow/security defects can be errors; architecture/test/configuration heuristics are usually warnings or notes until repository evidence makes them stronger.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Control flow

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### `BHCTRL001` — jump from `finally` — error

Flags `return`, `break`, or `continue` executed by a `finally` block because the jump can suppress a pending exception or override control flow.

This rule is deliberately redundant. Maximum BugHunt coverage also gets the same class from Ruff `B012` and the shipped ast-grep rule `bughunt-return-in-finally`.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### `bughunt-swallowed-exception` — error

Shipped ast-grep rule for `except ...: pass` / bare `except: pass`. It is kept even though other engines overlap because silent exception loss is a high-value correctness signal.


<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Semgrep correctness rules

`configure --auto` writes an independently authored BugHunt Semgrep pack under `.bughunt/configs/semgrep/rules/bughunt-correctness.yml`. These are bug/reliability rules, not a security bundle:

- `bughunt.cached-generator` — cached generator functions can return an iterator that was already consumed on an earlier cache hit.
- `bughunt.unconsumed-threadpool-map` — `ThreadPoolExecutor.map` results that are never consumed can hide worker exceptions.
- `bughunt.dict-delete-during-iteration` — deleting from the dictionary currently being iterated can invalidate iteration and raise at runtime.
- `bughunt.list-mutation-during-iteration` — structural list mutation during its own iteration commonly skips/repeats/extends work; warning because deliberate patterns exist.
- `bughunt.sync-sleep-in-async` — `time.sleep` inside async code blocks the event loop.
- `bughunt.file-rebound-before-close` — reassigning a file-handle variable before close leaks the previous resource.
- `bughunt.named-tempfile-name-before-flush` — handing a temporary-file path to another reader after writes but before flush/close can expose incomplete contents.

The registry baseline remains `p/default`. Security-specific Semgrep packs are opt-in, keeping the default signal centered on escaped defects.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Configuration contract

BugHunt's default configuration policy is:

- runtime/operational configuration belongs in typed configuration, config files, environment variables, command-line options, generated configuration, or constants that represent genuine invariants;
- environment-driven projects should maintain an accurate `.env.example`;
- `.env.example` must never contain real credentials;
- where static evidence exists, the generated environment contract records required/optional status, default, inferred type, units, accepted ranges, an example, and source location.

Rules:

- `BHCFG001`: environment variables are used but `.env.example` is absent.
- `BHCFG002`: a used environment variable is absent from `.env.example`.
- `BHCFG003`: a value in `.env.example` looks like a real credential. **Error.**
- `BHCFG004`: a module-level operational knob is hard-coded outside a config/settings/constants mechanism.
- `BHCFG005`: a call-site operational keyword such as `timeout=30` or `retries=4` is hard-coded. This is a note because some values are legitimate invariants.

`bughunt configure --auto` creates or refreshes only a BugHunt-managed block in `.env.example`; user-owned lines are preserved and secret-like variables are always emitted blank.

<!-- trace:exempt reason=repo-docs-move-no-product-behavior -->
## Unit contracts

Unit-bearing names must carry their unit, and one expression must not mix
units of one dimension. Call keyword arguments are the callee's contract
and are never flagged.

- `BHUNIT001` (warning): `timeout = 10` binds a unit-bearing stem to a
  bare number; suffix the unit (`timeout_s`). Suffixed names (`timeout_ms`),
  computed values (`size = len(x)`), and dimensionless counts (`retries`)
  are clean.
- `BHUNIT002` (error): `deadline_ms + grace_s`, or unit arithmetic with a
  bare number (`elapsed_ms + 500`). An explicit `×/÷1000` (or 1024) factor
  reads as a deliberate conversion and is exempt, as is comparison
  against 0.
- `BHUNIT003` (warning): one stem bound in two units in one file
  (`timeout_ms` and `timeout_s`) is an ambiguous contract.
- `BHUNIT004` (error/warning): a milliseconds value reaches a seconds
  sink (`time.sleep`, `socket.settimeout`) across function boundaries
  with no valid `/1000` conversion. Confidence-gated: name evidence
  plus a contract sink, or a provably wrong conversion factor.
- `BHSEM001` (error/warning): representation-equal values from
  incompatible nominal domains interchange (`user_id` into
  `project_id`, `USD` into `EUR`).
- `BHSEM002` (error/warning): instant/duration confusion — two
  instants added, or an instant where a duration is expected.
- `BHSEM003` (warning): naive and aware datetimes mixed in one
  expression.
- `BHSEM004` (error/warning): dtype narrowing (`float64` into `int8`,
  float into int) at a NumPy cast with a known source dtype.
- `BHSEM005` (warning): unsafe promotion (`uint64` with `int64` may
  lose integer precision).
- `BHSEM006` (error/warning): shape contradiction — reshape literal
  totals disagree, or jaxtyping symbolic dims mismatch at a call.
- `BHSEM007` (warning): percent flows where a fraction is expected
  (without `/100`); bits where bytes are expected and vice versa.
- `BHSEM008` (warning): coordinate-frame mismatch (`world` value
  into a `camera` parameter).
- `BHSEM009` (error/warning): `str` into a bytes-only sink
  (`hashlib.md5`) without `.encode()`; bytes where text is required.
- `BHSEM010` (warning): single-argument `.get()` dereferenced with
  no `is None`, truthiness, `isinstance`, or early-exit guard.
- `BHCONC001` (warning): two thread/task-entry functions write one
  literal path or global with no lock, transaction, or queue.
<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Architecture and persistence boundaries

- `BHPERS001`: a higher layer (`api`, `service`, `domain`, `controller`, etc.) imports an obvious persistence implementation (`sqlite`, SQLAlchemy, Redis, MongoDB, etc.) directly. Prefer a public repository/protocol contract unless the dependency is intentional.
- `BHPERS002`: a public higher-layer function exposes an imported persistence implementation type in its annotations/signature.
- `BHARCH001`: code imports an internal/private implementation module across a source boundary.
- `BHARCH002`: code imports a private symbol from another module.

BugHunt also generates a conservative Import Linter contract that checks sibling package cycles. It does **not** invent an arbitrary clean/layered architecture when repository evidence does not establish one.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Everything exported must come home

For supported export/import and backup/restore formats, the desired invariant is:

```text
object
  -> export
  -> import
  -> equivalent object
```

Rules:

- `BHRT001`: an identified export/import or backup/restore pair lacks a detected round-trip test.
- `BHRT002`: a function that looks like a real user-format export/import/backup/restore operation lacks its inverse operation.

When static signatures provide strong enough evidence for `A -> B -> A`, `configure --auto` goes further and generates an executable Hypothesis round-trip property automatically. The policy rule is the fallback for operations involving files, archives, persistence, richer objects, or otherwise non-generatable inputs.

BugHunt does not blindly infer that every function containing the word `import` or `export` is a user data format. One-sided rules require additional serialization/file/archive evidence to reduce false positives.

When a repository format evolves, an agent working the finding should consider export, import, format version, migration, validation, round-trip tests, and format documentation together.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Test quality

These defaults target tests that can go green while behavior is wrong because the tests merely mirror implementation:

- `BHTEST001`: test imports a private implementation symbol directly.
- `BHTEST002`: test asserts exact mock call history/order (`assert_has_calls`, `mock_calls`, `call_args_list`) when that order may not be contractual.
- `BHTEST003`: test asserts an enormous literal/snapshot rather than semantic properties.
- `BHTEST004`: test patches many collaborators and then asserts exact orchestration details.
- `BHTEST005`: test compares generated/source-like output against a large exact string when exact source text does not appear to be the contract.

These are warnings, not proof that a test is invalid. Exact call order is legitimate when ordering itself is a contract.

BugHunt intentionally does not try to regex-detect every instance of "duplicating production conditionals"; proving that reliably requires semantic comparison and belongs in the V2 agent/code-analysis layer.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Complexity and size rules

The built-in complexity scanner emits:

- `BHCX001`: cyclomatic complexity budget.
- `BHCX002`: function LOC budget.
- `BHCX003`: file LOC budget.
- `BHCX004`: ABC magnitude (assignments, branches, conditions).
- `BHCX005`: per-file JavaScript/CSS/WASM asset budget.
- `BHCX006`: built JavaScript/CSS/WASM bundle budget.

These are risk signals, not instructions to game a metric. A finding explicitly does **not** justify splitting a coherent file into meaningless fragments or moving logic through pointless indirection.

See `COMPLEXITY.md` for the default budgets and the independent external complexity engines BugHunt also runs.


<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## 0.6 seam, coverage, evidence, and history rules

- `BHCOV001` — executable source range is not exercised by the test suite.
- `BHCOV002` — branch edge is not exercised; exception/alternative paths deserve special attention.
- `BHSEAM001` — serialized dictionary key-set producer/consumer drift.
- `BHSEAM002` — `**kwargs` forwarding chain can reach an incompatible terminal signature.
- `BHSEAM003` — local producer return-shape and consumer key usage disagree.
- `BHSEAM004` — schema/model field drift.
- `BHSEAM005` — external HTTP JSON is consumed without explicit runtime validation.
- `BHSEAM006` — external payload integration lacks a recorded-payload regression corpus.
- `BHSEAM007` — Pact consumer/provider contract mismatch.
- `BHEVID001` — known type widened to `Any`/`object`/broad mapping and later cast back.
- `BHEVID002` — chained cast reconstructs type evidence through assertions.
- `BHEVID003` — growing accumulator is repeatedly copied inside a loop.
- `BHDB001` — query-like operation inside a loop; N+1/query-explosion candidate.
- `BHTIME001` — wall-clock/timezone-sensitive behavior lacks time-boundary test evidence.
- `BHDIFF001` — safe old-release-vs-HEAD behavioral differential changed.
- `BHDIS001` — strict type-checking engines disagree at the same source location.
- `BHPKG001` — packaging/installability metadata or built artifact validation failure.

See `BUG_TAXONOMY.md` for the rule-mining roadmap and `SEAM_CORRECTNESS.md` for the contract philosophy.

<!-- trace:exempt reason=repo-docs-new-section-no-behavior-change -->
## Protocol correctness

- `BHPRT001` (error): `assert cond, ValueError(...)` never raises the
  carried exception; raise explicitly.
- `BHPRT002` (error): `async def` on a synchronous-protocol magic method.
- `BHPRT003` (error): `yield` inside a magic method that must not become
  a generator (`__len__`, `__bool__`, ...; `__iter__` is fine).
- `BHPRT004` (error): bare single-argument `next()` inside a generator
  (PEP 479 `RuntimeError` on exhaustion).
- `BHPRT005` (error): method call on a file handle after `close()`.
- `BHPRT006` (error): read on a write-mode open, or write on a
  read-mode open (builtin `open`, `Path.open`, and `mode=` keywords).
- `BHPRT007` (error): reflective dunder raises `NotImplementedError`;
  return `NotImplemented` so Python tries the reflected operation.
- `BHPRT008` (warning): constant subscript stored twice in one block
  with no read between; the first store is dead. Variable keys and
  exclusive branches stay silent.
- `BHPRT009` (warning): `TestCase` subclass with methods but no tests.
- `BHPRT010` (warning): `sqrt(x**2 + y**2)`; `math.hypot` is stable.
- `BHPRT011` (warning): `json.loads(f.read())` / `f.write(json.dumps(x))`;
  stream with `json.load` / `json.dump`.
- `BHPRT012` (error, SQLAlchemy-gated): `and`/`or` on column
  expressions; use `&`/`|` (or `and_`/`or_`).
- `BHPRT013` (error, Django-gated): `null=True` on `ManyToManyField`
  has no effect.
- `BHPRT014` (warning, Django-gated): `unique=True` alongside
  `primary_key=True` is redundant.
- `BHPRT015` (warning, Django-gated): `unique_for_*` is app-level
  validation, not a database constraint.
