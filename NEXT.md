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
