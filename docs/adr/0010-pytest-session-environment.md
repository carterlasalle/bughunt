<!-- trace:exempt reason=design-record-no-product-behavior -->
# ADR-010: One pytest-session environment, resolved from the repository

<!-- trace:exempt reason=design-record-no-product-behavior -->
## Context

Readiness for the pytest family was inferred in three different places with
three different notions of "the environment": the installer (per branch:
`uv add` into a project, `uv tool install` or `sys.executable` otherwise),
`bughunt doctor` (`target_python`, and `importlib` against BugHunt's own
interpreter), and the run-time plugin/coverage gates (`pytest_interp`).

The result was a scan whose defenses depended on *how BugHunt was launched*.
Receipt, same target, 2026-10-02:

- globally installed `bughunt` (uv tool): `pytest`, `coverage`, `typeguard`,
  `memray`, `blockbuster` resolved from five different environments, so
  `coverage` and `runtime-types` reported ERROR and every plugin skipped,
  while `doctor` reported them READY;
- `uv run bughunt` from BugHunt's own checkout: the same repo passed, because
  `uv run` puts BugHunt's `.venv/bin` on PATH and pytest happened to find the
  plugins there.

ADR-002 fixed the target-repository *preference* but left the case where the
repository has no virtualenv at all resolving from PATH. ADR-003 stated that
pytest plugins belong "in the target venv, and repos without a usable target
venv get an explicit SKIP".

<!-- trace:exempt reason=design-record-no-product-behavior -->
## Decision

1. `technology.pytest_python(root)` is the single resolver for the
   interpreter that runs the target's pytest session: the project virtualenv
   (`.venv`), else BugHunt's private pytest environment
   (`.bughunt/runtime/pytest-venv`), else the `pytest` console script's own
   environment, else `target_python`. The installer, `doctor`, and every
   run-time plugin/coverage gate use this one function.
2. The pytest family (pytest, its plugins, coverage.py, typeguard,
   hypothesis, mutmut, and the test-support libraries) installs into that
   environment and nothing else. BugHunt's own installation environment must
   never hold them.
3. A repository with no virtualenv gets BugHunt's private pytest environment
   (created with `uv venv`, seeded best-effort from `requirements.txt`) rather
   than a blanket SKIP. This amends ADR-003: provisioning removes the
   launch-dependence that a SKIP would merely report. SKIP remains when
   provisioning itself fails.
4. `technology.pytest_executable` resolves pytest-family console scripts only
   from the session environment, so a copy on PATH cannot answer for it.

<!-- trace:exempt reason=design-record-no-product-behavior -->
## Alternatives

- Keep PATH-style resolution (rejected: the scan result depends on the
  launcher's environment, which is the inconsistency above).
- Install the whole family into BugHunt's own interpreter for every repo
  (rejected: leaks BugHunt's dependencies into the target's test session and
  is wiped by `uv tool upgrade`).
- Blanket SKIP when there is no project virtualenv (rejected for the pytest
  family: it forfeits every test-session defense on repositories BugHunt can
  provision for, which is most of them).

<!-- trace:exempt reason=design-record-no-product-behavior -->
## Consequences

The same repository yields the same defenses under `uv run`, `uvx`,
`uv tool install`, pipx, and CI; `doctor` reports the environment the run
will actually use. Cost: one cached virtualenv per repository without one,
and a `uv pip install` pass for the family. Not covered, tracked separately:
`install_all` still uses `uv add --dev` for repositories that carry a
`pyproject.toml` (ADR-003 forbids manifest mutation; that branch is a
separate change with its own migration note).
