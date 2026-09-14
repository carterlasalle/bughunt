<!-- trace:exempt reason=design-spec-no-product-behavior -->
# Semantic correctness engine + graph-backed detection

<!-- trace:exempt reason=design-spec-no-product-behavior -->
## Status

SPEC-BUG-SEM01. Revives `docs/specs/unit-tracking-future.md` (both
deferred layers: preconditions now met — naming layer shipped, and the
SCC export on this tree carries 1395 resolved call edges to propagate
over). Implements goal §10–§11 with the §39 ordering (graph substrate
first, then dataflow rules).

<!-- trace:exempt reason=design-spec-no-product-behavior -->
## 0. Ground truth (measured 2026-09-14, not assumed)

SCC 0.1.0 export on this tree (`.bughunt/cache/system-ir.json`):

- 2259 entities, 5196 relationships, 69 flows.
- Predicates present: `contains` 1684, `calls` 1395 (symbol→symbol,
  confidence, e.g. 0.99 resolved), `exports` 536, `declared_as` 459,
  `crosses_boundary` 458 (symbol→external API), `imports` 374,
  `tested_by` 201 (confidence 0.65, heuristic), `annotates` 65,
  `configured_by` 21, `reads` 1, `depends_on` 1, `registers` 1.
- Predicates ABSENT: no call-site arguments, no returns, no writes,
  no produces/consumes, no serialization edges. Store modeling is one
  `store` entity + one `reads` edge — effectively absent.
- `evidence` items resolve to file/line/symbol (`type: source`).
- `scc drift` is empty without history; `check-invariants` passes
  without declared invariants; `likely_internal_unresolved` (3369 here)
  is surfaced by the adapter as one warning aggregate
  (`scc:unresolved-references`), not per-edge findings.
- `scc runtime` has zero ingested observations. Static-vs-observed
  evidence therefore comes from OUR OWN `coverage.json` executed-line
  sets, not from SCC runtime.
- `tested_by` at 0.65 is supporting evidence only. It must never
  become a verification claim (proxy-predicate rule).

Consequence: SCC is the canonical who-calls-whom skeleton. Everything
about WHAT flows (arguments, returns, assignments, names, literals) is
extracted by BugHunt's own intraprocedural AST pass and joined to SCC
edges. No second call-graph implementation; no invented SCC predicates.

<!-- trace:exempt reason=design-spec-no-product-behavior -->
## 1. Architecture

```text
scc export system-ir.json (cached, keyed like the adapter)
        │ calls(symbol→symbol, conf), tested_by, crosses_boundary,
        │ evidence(file/line), contains/exports/imports
        ▼
graph/facts.py — normalized facts, provenance+confidence preserved.
        │ Function summaries keyed by canonical symbol:
        │   params, returns(exprs), call sites (callee expr, arg mapping),
        │   assignments, sinks reached, stores written
        ▼
AST intraprocedural extraction (ast module, per file, cached by mtime)
        │ local facts per function body
        ▼
semantic/infer.py — evidence → SemanticValue per program point
        │ ranks: annotation 1.00, API contract 0.98, schema/model 0.95,
        │        docstring 0.85, name suffix 0.80, comment 0.75,
        │        conversion pattern 0.70, magnitude 0.20
        ▼
semantic/propagate.py — forward + backward over summaries + SCC edges,
  fixed-point with cycle cutoff (max 3 revisits per symbol), confidence
  = min along path × evidence rank product, floored at 0.10.
        ▼
semantic/contradictions.py — BHUNIT004 / BHSEM001–010 emitters.
  Fire ONLY on high-confidence contradictions (≥0.70) or medium (≥0.45)
  with two independent evidence sources. Anything weaker is silent —
  a semantic linter that cries wolf is worse than none.
        ▼
semantic/crosshair_confirm.py — for pure eligible functions, synthesize
  a witness check from the contradicted constraint and run CrossHair;
  a found counterexample upgrades severity to error, inconclusive keeps
  warning. CrossHair never invents semantics; it only confirms.
```

<!-- trace:exempt reason=design-spec-no-product-behavior -->
## 2. SemanticValue (single struct, all domains)

```python
SemanticValue:
    python_type: str | None
    dimension: tuple[str, ...]      # e.g. ("time",) exponents map
    unit: str | None                # seconds, ms, radians, px, ...
    nominal: str | None             # user-id, usd, utc-ts, ...
    dtype: str | None               # float32, int64, ...
    shape: tuple | None             # concrete or symbolic names
    numeric_range: (lo, hi) | None
    nullable: bool
    timezone: str | None            # aware-utc, naive, ...
    encoding: str | None            # utf8, bytes, ...
    frame: str | None               # world, camera, ...
    provenance: str                 # evidence source description
    confidence: float               # 0..1, see ranks above
```

Domains are transfer functions over this struct, not separate
checkers: `domains/units.py` (time, angle, length, bytes/bits,
percent/normalized), `domains/nominal.py` (ids, currency, instant vs
duration), `domains/nullability.py` (.get/optional/None flows),
`domains/dtype.py` (NumPy promotion table, narrowing),
`domains/shape.py`, `domains/range.py`, `domains/timezone.py`,
`domains/encoding.py`, `domains/frame.py`.

Unit algebra: `+ - < ==` require compatible dimensions; `* /`
compose; `sqrt/pow` scale exponents; `log/exp/sin` require
dimensionless/angle. Conversion patterns (`/1000` between ms and s
positions) are recognized, not hardcoded per function: any division
of a Time[ms] value by ~1000 flowing into a Time[s] sink is a valid
transformation; any other factor is a strong contradiction.

<!-- trace:exempt reason=design-spec-no-product-behavior -->
## 3. Sink contracts (closed list, stdlib-first)

Only sinks with documented unit contracts constrain: `time.sleep`
seconds, `socket.settimeout` seconds, `asyncio.sleep` seconds,
`datetime.timedelta` per-kwarg units, `threading.Timer` seconds.
Framework sinks activate on applicability (numpy dtypes only when
numpy imported, torch shapes only when torch imported). Unknown
third-party calls never constrain — they propagate `unknown`.

<!-- trace:exempt reason=design-spec-no-product-behavior -->
## 4. Graph-backed detectors (no other ring catches these)

- BHUNIT004 interprocedural unit contradiction (semantic engine).
- BHSEM001 nominal-domain mismatch (user-id vs project-id, usd vs eur).
- BHSEM002 instant/duration confusion.
- BHSEM003 timezone-naive vs aware flow.
- BHSEM004 dtype narrowing (float64→float32 store, int→int8 range).
- BHSEM005 unsafe promotion (uint64+int64, precision loss).
- BHSEM006 shape contradiction (matmul/symbolic dim mismatch).
- BHSEM007 scale/range mismatch (percent vs fraction, bits vs bytes).
- BHSEM008 coordinate-frame mismatch.
- BHSEM009 encoding mismatch (bytes vs str without decode).
- BHSEM010 nullable dereference without dominating guard
  (dict.get, optional return, regex match, env lookup sources).
- BHCONC001 shared-state multi-writer without synchronization
  (writers = file open(w/a) to same path + global/nonlocal stores;
  reachability from thread/async entry via SCC calls; no lock/with,
  transaction, or queue serialization on path).
- BHOBS001 static-unobserved contradiction support: executed-line
  sets from coverage.json strengthen/weaken hypotheses; never erase
  unexecuted static possibilities.

PTC concept ports (provenance recorded, cheapest adequate engine):
PTC-W0021 use-after-close, PTC-W0022 open-mode mismatch (resource
state domain); PTC-W0031 .get().method (covered by BHSEM010, no
duplicate when type checkers prove it); PTC-W0032 assert-with-
exception-arg (AST); PTC-W0045 async magic method, PTC-W0054
NotImplementedError-vs-NotImplemented, PTC-W0059 yield-in-magic,
PTC-W0063 unguarded next() (protocol AST + CFG); PTC-W0057
overwrite-before-read (def-use); PTC-W0046 empty TestCase (AST);
PTC-W0028 hypot (local AST, low priority); PY-W0078/0079 json
load/dump (low priority); PY-W0800 sqlalchemy and/or (framework
gated); PTC-W0902/0905/0908/0910 Django (capability gated;
W0910 defers to pytest-mrt first).

<!-- trace:exempt reason=design-spec-no-product-behavior -->
## 5. Fingerprints, reporting, calibration

Graph/semantic findings fingerprint on (rule, canonical source
symbol, canonical sink symbol, contradiction kind) — never line
numbers. They join dedup/correlation/risk like any finding, with
confidence attached. Dogfood rule: zero new findings on this tree
without a planted-bug proof first; any dogfood finding must be a
true positive, a fixed bug, or a calibration fix — never a
tolerance. New rules ship positive + negative + adversarial
fixtures and go through BugCorpus detector lifecycle.

<!-- trace:exempt reason=design-spec-no-product-behavior -->
## 6. Acceptance

1. `scc:unresolved-references` stays a single aggregate; per-edge
   firehose is a correctness bug in this spec.
2. Planted `timeout_ms → time.sleep` across a function boundary is
   caught (BHUNIT004) with the /1000-valid vs /100-contradiction
   distinction proven by fixtures.
3. Every shipped rule has the three fixtures; full suite green;
   `trace verify --changed` clean; ruff/mypy clean; dogfood on this
   tree yields no false positive (fixed or calibrated).
4. Modules live outside `cli.py`; wiring is one `add()` per defense.
