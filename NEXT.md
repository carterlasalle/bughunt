<!-- trace:exempt reason=repo-planning-no-product-behavior -->
# What comes next

<!-- trace:exempt reason=repo-planning-no-product-behavior -->
Ordered by value. Each item states its acceptance evidence.

<!-- trace:exempt reason=repo-planning-no-product-behavior -->
## 1. Coverage: orchestrator paths (68% → 85%)

The zero-modules are done (evidence 87%, package ~85%, coverage-runner 73%).
What remains is cli.py orchestration, installers, seam_scan, importtime_runner,
and pact_runner — mostly env-dependent paths needing tmp-dir + monkeypatched
fixtures, following the `test_fault_boundaries.py` pattern. Acceptance: the
repo-wide coverage gates in AGENTS.md (85% line, 80% branch) pass on a local
`coverage run -m pytest` with no new unconditional skips.

<!-- trace:exempt reason=repo-planning-no-product-behavior -->
## 2. Orchestrator splits (dedicated thread)

`build_checks` (511 cognitive), `main`, `install_all`, `discover_*`, and
`_scan_*_policies` are linear dispatch, not tangled logic — splitting them is
surgery with regression risk, not sweep filler. The `_kwargs_drift`
three-phase precedent applies. Complexity signals are ledger-tracked, so
growth is caught meanwhile. Acceptance per split: identical scan output on
the repo itself (golden `report.json` diff) plus the full suite green.

<!-- trace:exempt reason=repo-planning-no-product-behavior -->
## 3. Confirm the loop-scan numbers

Several batches landed after the last full scan (strict pylint disables,
E501 clearance, fault tests, unit rules). Run `uv run --frozen bughunt
skipmutmut`, confirm pylint strict ≈300→lower, ruff actionable down, and no
new ERROR defenses. Then re-snapshot any shifted ledger counts and commit
`debt.toml`.

<!-- trace:exempt reason=repo-planning-no-product-behavior -->
## 4. Known-contradictions guard (offered, unbuilt)

A small table of mutually-contradictory check pairs (pylint
use-implicit-booleaness vs pyrefly implicit-bool, first entry) that warns
when both sides are simultaneously enabled. It would have flagged the
ADR-005 situation before scoping, and doubles as regression protection
for the calibration ADRs. Build on owner approval.

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
