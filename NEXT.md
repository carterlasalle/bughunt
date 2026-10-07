<!-- trace:exempt reason=repo-planning-no-product-behavior -->
# What comes next

<!-- trace:exempt reason=repo-planning-no-product-behavior -->
Ordered by value. Each item states its acceptance evidence.

## 1. Coverage: orchestrator paths (68% → 85%) — DONE 2026-09-14

Closed `e9ce011`: line **87.5%** (gate ≥85), branch **80.0%** (gate ≥80),
367 tests green, no new unconditional skips. Approach was branch-arc
targeting in pure-logic modules (seam_scan and verify_gaps to 100%,
adapters/runners/scanners gap tests) plus removing two dead branches
proven unreachable, instead of the planned cli.py/installers grind.
cli.py + installers env-dependent paths remain open for the orchestrator
thread (item 2) if it wants them; the repo-wide gate no longer depends
on them.

<!-- trace:exempt reason=repo-planning-no-product-behavior -->
## 2. Orchestrator splits (dedicated thread)

Done first cut 2026-09-14: `parsers.py` (all tool-output parsers) and
`models.py` (Finding/Result/Check/Status/DebtEntry) extracted from `cli.py`
with byte-identical scan output (golden `report.json` diff) and 294 green.
Remaining: `build_checks`, `main`, `install_all`, `discover_*`. Complexity
signals stay ledger-tracked meanwhile.

## 3. Confirm the loop-scan numbers

Superseded by the 2026-09-14 sweep: fresh `skipmutmut` scans run, findings
fixed at root (pysa calibration, nox CWD/dev-group, backup crash, dead
fields, timeout naming, audit markers), ledger re-snapshotted below.

## 4. Known-contradictions guard (built 2026-09-14)

BHPLC001 in the policy pack: ISC003 vs basedpyright implicit-concat and
pylint-booleaness vs pyrefly-implicit-bool fire when both sides are enabled
in repo configs. Dogfood-quiet on this tree.

<!-- trace:exempt reason=repo-planning-no-product-behavior -->
## 5. Taint-style unit tracking and dtype narrowing (specced TODO)

Specified in `docs/specs/unit-tracking-future.md` with revival triggers.
Do not build until the naming layer (BHUNIT001/002/003, shipped) is adopted
and a real tree carries annotated arithmetic (units) or numpy/torch/pandas
boundaries (dtypes) to prove against.

<!-- trace:exempt reason=repo-planning-no-product-behavior -->
## 6. OCR applications (b) and (c) (deferred)

`paths` on custom checks plus an explain command, and dry-run plan preview.
Studied in `alibaba/open-code-review`; application pending owner pick.
The precision-policy ADR (a) is recommended whenever scoping debates recur.

<!-- trace:exempt reason=repo-planning-no-product-behavior -->
## 7. Release hygiene follow-ups

0.7.0 shipped before the sdist excludes landed, so its sdist contains
harness surfaces; cannot be fixed retroactively — verified clean for the
next tag. The `cmpop` dict-key strict debt in `_range_for_variable` is
pre-existing (proven at HEAD) and waits with the rest of the strict overlay.

<!-- trace:exempt reason=repo-planning-no-product-behavior -->
## 8. Oracle-layer review (2026-10-07) — boundary rule shipped, rest triaged

A defense review proposed a broad oracle/property/fault-injection agenda. The
outcome per item, so the same proposals do not get re-litigated:

**Shipped**: BHVERIFY002 (unverified boundary fault path) in `verify_gaps.py` —
a module-level public function that calls an external boundary (HTTP,
subprocess, socket, database) and has no detected failure-path test. Calibrated
on this repo: 5 findings, each cross-checked by hand (the `technology`/`probes`
`subprocess.run` sites have happy-path-only tests). The same work fixed two
mention-heuristic gaps that also over-reported BHVERIFY001 on real code:
re-exports (`from .runners import x`, where tests import from `bughunt.cli`) and
module-attribute calls (`mod.func()`), worth 34 → 21 findings on this tree.

**Already covered, no work needed**: runtime types (typeguard), memory (memray),
async blocking (blockbuster), parallel/pollution (pytest-parallel,
pytest-random, pytest-xdist), network isolation (pytest-no-network),
interpreter/timezone/locale matrices, contracts (deal, pact-contracts),
property and stateful generation (hypofuzz + hypothesis), packaging
(packaging, version-diff, twine, check-manifest).

**Triaged, not adopted** (each needs an acceptance case before it earns a ring):

- beartype, scalene, objgraph, tracemalloc: alternatives to engines already
  wired; add only if a measured gap appears.
- N+1 query counting (`nplusone`, pytest-antilop): needs an ORM-specific
  runtime hook (SQLAlchemy/Django), so it belongs behind a technology
  capability gate like the JS engines, not in the Python core.
- `abi3audit`, `check-wheel-contents`: meaningful only for C-extension or
  wheel-shipping targets; wire when such a target appears.
- TLA+/Z3: formal specification of the target's own algorithms, which a
  scanner cannot infer from source.
- Known-bad calibration corpus (one planted defect per defense, asserted
  caught): the per-rule tests already plant the defect they target (the
  BHVERIFY002 tests above are exactly that shape), and the doctor tables carry
  the engine-level signal. A whole-corpus harness is a larger piece needing its
  own ADR.
- JEV (`jev-lint`, mizchi): a natural-language rule linter — ast-grep selects
  the code, a written sentence is the rule, and a verdict comes back. It ships
  `gate`, `report`, and a `calibrate`/`eval` harness for precision scoring.
  Interesting for rule *authoring*, but the verdict path needs a model and the
  rules are user prose, so it does not replace the deterministic native pack.
  Revisit if BugHunt grows user-authored rules.
