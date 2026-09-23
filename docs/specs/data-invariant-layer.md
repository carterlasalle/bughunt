<!-- trace:v1 id=SPEC-BUG-DATA01 type=spec work=WORK-BUG-06107X2Q -->
# Data-invariant layer (SPEC-BUG-DATA01)

<!-- trace:exempt reason=design-spec-no-product-behavior -->
## Status

SPEC-BUG-DATA01. Implements ADR-009. Extends the ADR-008 semantic engine
with data/interval/artifact/config-provenance invariants derived from the
2026-09-23 SunStack PR review analysis. Ground truth for every rule below
is a concrete finding from that review; each rule ships with the three
fixtures before it fires on real code.

<!-- trace:exempt reason=design-spec-no-product-behavior -->
## 1. Facet extensions (semantic/model.py)

```python
missingness: unknown | measured | imputed | measured_zero
time_basis: utc | local_wall | naive_unknown
interval_alignment: point | trailing | leading | centered
dependencies: frozenset[str]
```

Transfer rules (name/shape/API evidence, same ranks as existing facets):

- `.fillna(0)` / `.fillna(0.0)` on a nullable/unknown value →
  `missingness=imputed`, provenance `fillna-zero`.
- `pd.to_numeric(..., errors="coerce")` → `missingness=unknown`
  (coercion manufactures NaN from non-numeric input).
- `pd.to_datetime(x, utc=True)` where `x` carries local-wall name
  evidence (`local`, `dt_local`, `wall`, ...) and no preceding
  `tz_localize` → `BHTIME002` at the call site; result `time_basis=utc`
  with provenance `mislabeled-local-as-utc`.
- `Series.dt.tz_localize(...)` → `time_basis=utc` (or the named zone);
  `datetime.replace(tzinfo=...)` → `time_basis=utc` with medium
  confidence (name evidence decides strong vs silent).
- Names `*_trailing`, `tan_dose_30m*`, `trailing_*` → `interval_alignment
  =trailing`; `best_*_start`, `*_start` assigned a trailing value →
  `BHINT002`.
- Subscript stores `out["col"] = f(...)` record `col depends_on {read
  columns}`; later store to a dependency without recomputing `col`,
  followed by a read/export of `col` → `BHDF001`.

`combine()` keeps a facet only on agreement (missingness/time_basis/
interval_alignment); `dependencies` intersects. Same conservative-join
discipline as every existing facet.

<!-- trace:exempt reason=design-spec-no-product-behavior -->
## 2. data_scan.py (native, pure AST)

One module, one `scan(root, source_paths)` returning findings with codes:

- `BHMISS001` missingness destruction: `fillna(0)`-imputed value flows
  into a quantitative sink (name evidence: `irradiance|dose|integrat|
  scoring|radiation|index|_wm2|_j_m2`, or a call to `integrate_*`/
  `window_*dose`/`*_score`). Fires at the sink call, not the fillna.
- `BHDF001` stale derived column: column-level SSA per function —
  `out["p"] = f(out["a"], out["b"])` then `out["a"] = ...` then a load
  of `out["p"]` (subscript load, `.to_*`, `to_dict`, `return out`,
  function-arg pass) before any recompute of `out["p"]`.
- `BHINT001` lost integration endpoint: half-open mask
  `(t >= start) & (t < end)` (or `query`/`.loc` equivalents) whose
  result flows into a call named `integrate_*`/`trapz`-family/
  `window_*dose`. Endpoint-inclusive masks (`<= end`) are quiet.
- `BHINT002` interval alignment: a trailing-evidence value assigned to
  a forward-name target (`best_*_start`, `*_start`, `*_begin`) or
  passed as a `start=` kwarg. Name-evidence both sides; silent unless
  both fire.
- `BHART001` use-before-validation: a read of a cached artifact path
  (`parquet|pkl|pickle|npz|npy|joblib|pt|onnx|bin`) precedes any
  freshness check (`exists|stat|mtime|_version|fresh|stale|manifest`)
  in the same function. Validation first = quiet.
- `BHART002` incomplete fingerprint: artifact write site reads config
  keys `{A, B, C}` (UPPER_SNAKE names loaded in the function) but the
  companion freshness predicate (same function or `_fresh|_valid|
  _stale|_manifest|_version` sibling) mentions only a strict subset.
- `BHMETA001` contradictory metadata: literal `complete=True` /
  `coverage=1.0` (or `1`) alongside a NaN-able quantity default
  (`float("nan")`, `np.nan`, `None`) in the same dict literal / return.
- `BHTIME002` local-as-UTC: `pd.to_datetime(x, utc=True)` where `x`
  has local-wall name evidence and no `tz_localize` dominates. (Also
  wired through semantic SINK_CONTRACTS when the engine runs.)

Confidence: name-evidence pairs fire at warning (0.60–0.75); API-shape
pairs (`fillna(0)` + `integrate_*` call, half-open mask + integrator
call) fire at error (≥0.85). Anything weaker is silent — the ADR-008
no-cry-wolf rule applies unchanged.

<!-- trace:exempt reason=design-spec-no-product-behavior -->
## 3. Cheap local shapes (generators, not native)

ast-grep (`_astgrep_config`):

- `bughunt-unguarded-first-index`: `splitlines()[0]` / `readlines()[0]`
  / `split(...)[0]` on a call result with no length/emptiness guard in
  the function → `BHSEQ001`.
- `bughunt-fillna-zero`: `.fillna(0)` hot pattern (native BHMISS001
  decides at the sink; this is the local tripwire) → `BHMISS001`.
- `bughunt-runtime-assert`: bare `assert` outside tests/type-narrowing
  idiom → `BHCTRL002` (Ruff S101 overlaps; this carries the `-O`
  message).
- `bughunt-repo-relative-resource`: `Path(__file__).parent... / "data"`
  with 2+ parents, or `Path.cwd() / "data"` inside installable
  packages → `BHPKG002` static half.
- `bughunt-unbalanced-ics`: `BEGIN:VEVENT` string literal in a file
  with no `END:VEVENT` literal → `BHFMT001` static half.

Semgrep (`_semgrep_correctness_rules`):

- `bughunt.boolean-env-denylist`: `not in {"0","false","no"}` /
  `os.getenv(...) not in ...` → `BHCFG006`. (ONE metavariable-regex
  per rule; the second constraint is pattern-not-regex — repo memory.)
- `bughunt.duplicated-version-constant`: same string literal matching
  `[A-Za-z]+-v\d+` / `v\d+(\.\d+)*` in 2+ files → `BHCONST001`
  (implemented as a per-file literal-shape rule + a native dupe check
  in data_scan; Semgrep half flags the literal shape).
- `bughunt.hardcoded-success-claim`: `ERROR count = 0` / `errors = 0`
  f-string after a computed validation → `BHEVID004` (message carries
  the compute-then-claim shape).

<!-- trace:exempt reason=design-spec-no-product-behavior -->
## 4. BHINV001 / BHMETA002 / BHPKG002

- `BHINV001` (native, in data_scan): collect simple string predicates
  per function (`x == "lit"`, `x != "lit"` with early reject/return).
  Group by variable; infer domain = union of compared literals.
  Two groups over the same variable with different accept sets →
  finding naming both sites. Tiny set-equivalence only; anything
  beyond `==`/`!=`-on-literals is silent.
- `BHMETA002` (seam_scan): quality-suffix family (`_complete`,
  `_coverage`, `_coverage_fraction`, `_valid`, `_stale`, `_version`,
  `_confidence`, `_source`). A dict literal / return / DataFrame
  assignment carrying `X<base>` without its produced `X<base><suffix>`
  siblings (produced = same function defines them) → finding. Fits
  the existing producer/consumer seam machinery.
- `BHPKG002` smoke (package_checks): after `uv build`, if a wheel
  exists: create isolated venv in cache dir, `--no-deps` install the
  wheel, run `import <top_package>` + console entry `--help` probes
  from an empty cwd with `PYTHONPATH` unset. Any failure → `BHPKG002`
  finding with the probe output. Missing `uv` = skip (never error).

<!-- trace:exempt reason=design-spec-no-product-behavior -->
## 5. Wiring

- `data_scan` + `BHPKG002` smoke + `BHINV001` follow the `protocol`
  precedent: pure-AST/native, one `add()` each, `findings_exit_codes
  ={1}`, PR floor inclusion (old bughunt.toml files get them via the
  runtime floor augmentation).
- Default rules registry documents every new ID with its engine +
  overlap note.
- BugCorpus: one case per distinct bug family (MISS/DF/INT1/INT2/
  ART2/META/TIME/SEQ/CFG006/CFG007/CFG008/INV/CONST/FMT), each with
  positive + negative + adversarial fixtures.

<!-- trace:exempt reason=design-spec-no-product-behavior -->
## 6. Non-goals (this change)

- `BHCFG007` (literal-shadows-config) and `BHCFG008` (policy-kwarg
  propagation) need cross-function config-key resolution; recorded as
  follow-up, not silently half-built.
- Generated Hypothesis integration campaigns: recorded follow-up
  (needs the integrator-signature discovery in discovery.py first).
- Full artifact-validation ring (parse emitted ICS/JSON/YAML at scan
  time): recorded follow-up; BHFMT001 static half + smoke probes now.
- `check-wheel-contents` dependency: out of scope per ADR-009.
