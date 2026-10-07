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
- JEV (`jev-lint`, mizchi; the verdict model is Jev from typesafe.ai): a rule
  is an ast-grep matcher plus one sentence and its criteria ("does this
  function's body do what its name promises?"), ast-grep deciding *which* code
  is judged and the model deciding whether the sentence holds, over a cutoff
  fitted to a labelled corpus. It is explicit that this is the axis parsers
  cannot take — name-vs-body drift, stale comments, tests that cannot verify
  their title, catch blocks that hide failures — and that it is measurably poor
  at what a compiler or type checker already decides. Not adopted here: the
  verdict path needs an API key, it is non-deterministic by construction (~1 in
  5 findings wrong on its own repo), and BugHunt's native pack is deterministic
  ast-grep/semgrep. Three disciplines worth borrowing regardless:
  (a) labels for a calibration corpus must live outside the judged artifact —
  jev-lint's own markers inside the files it showed the model inflated its fit
  from 17 real rules at 1.00 to 22 claimed; (b) record/replay so a threshold is
  auditable and CI can re-score for free (`eval --replay`), which is the shape a
  known-bad corpus should take if item above is ever built; (c) report the
  blind spot explicitly — "N rules matched nothing" and "N without a verdict"
  are never noise, the same contract as `Check.empty_scope_markers` and
  BHVERIFY003.

<!-- trace:exempt reason=repo-planning-no-product-behavior -->
## 9. Per-defense receipts: the version and the scope actually used

`Result` already records what a review needs to trust a row: the exact
`command`, `duration_s`, `status`/`exit_code`, the raw `stdout`/`stderr`,
`note`, and `artifacts`. Three receipts from the same review are still missing
from `report.json` (schema_version 3):

- **tool version per defense** — the doctor tables detect installed versions at
  scan start (`doctor_engines.py`, `doctor_tables.py`) but the report does not
  carry them, so "which ruff produced this finding" needs the environment;
- **what was actually analyzed** — a tool's own "N files" line lives in
  `stdout`, not as a first-class field, so a scan cannot be diffed against the
  next one to say what entered or left scope;
- **suppressions and rule packs applied** — partly in `command` for the
  engines that take flags, absent for those that read a config file
  (`.semgrep.yml`, `eslint.config.js`, `pytest.ini`).

This is a schema change (`schema_version` bump) with consumers to update
(agent queue, bugcorpus and tracelayer adapters), which is why it is a separate
change rather than a field bolted onto the boundary-ring work.
