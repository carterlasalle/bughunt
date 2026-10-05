<!-- trace:v1 id=DOC-CHANGELOG type=document work=WORK-BUG-4ABH9VEY satisfies=REQ-BUG-KZG483AX -->
# Changelog

Follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.10.3] - 2026-10-02

### Fixed

- The pytest session now resolves from one environment, so a scan no longer
  depends on how BugHunt was launched. The same repository used to pass some
  plugin defenses under `uv run` (BugHunt's `.venv` on PATH) and fail them
  under a globally installed `bughunt` (`coverage`/`runtime-types` ERROR,
  every plugin skipped, while `doctor` still said READY).
  `technology.pytest_python` is now the single resolver used by the installer,
  `doctor`, and every run-time plugin/coverage gate.
- A repository without a virtualenv gets BugHunt's own pytest environment at
  `.bughunt/runtime/pytest-venv` instead of `pytest`, `coverage`, and each
  plugin landing in separate isolated `uv tool` environments (or BugHunt's own
  interpreter) that the session could never import from. `requirements.txt` is
  seeded into it, best effort.
- `doctor` probes pytest plugins against the interpreter that runs the session,
  not `target_python`, so READY/MISSING now predicts what the scan will do.
- Pytest-family console scripts (`hypothesis` for HypoFuzz, `mutmut`) resolve
  only from the session environment, so a copy on PATH cannot report a tool as
  available that the session cannot import.

## [0.10.2] - 2026-10-02

### Fixed

- First-party packages are now importable by target-python defenses (crosshair,
  pytest, and the timezone/locale matrices) in nested and src-layout repos; the
  source roots go on `PYTHONPATH` with correct flat-vs-src detection.
- Pytest-plugin readiness (memray, blockbuster, xdist, and friends) is probed
  against the interpreter that owns the `pytest` console script, not
  `target_py`, so a plugin missing from pytest's environment is a clean skip
  instead of an ImportError.
- The hypofuzz check confirms the HypoFuzz `fuzz` subcommand exists before
  running it; a Hypothesis CLI without hypofuzz no longer reports
  "No such command: fuzz" as a failed defense.
- `coverage` requires coverage and pytest co-located (it runs
  `coverage run -m pytest`) and `coverage_runner` surfaces the real error
  (BHCOV002) when no report is produced, instead of a bare "tool failed".
- `vulture` carries `--exclude` for generated/dependency directories, so a broad
  scope no longer reports dead code inside `.bughunt/` configs and virtualenvs.

## [0.10.1] - 2026-09-30

### Fixed

- `bughunt install` no longer routes library/pytest-plugin packages through
  `uv tool install`, which refuses any package that ships no console script
  (typeguard, pytest-randomly, deal, and the rest reported
  "Failed to install entrypoints"). They install into the Python BugHunt runs
  under instead, where the plugin probes actually look.
- Isolated `uv tool` environments now pin a stable CPython
  (`BUGHUNT_TOOL_PYTHON`, default 3.12) instead of inheriting the newest
  interpreter on the machine; a free-threaded build (3.14t) has no wheels for
  several analyzer C extensions and failed the stack install.
- The generated-directory ignore sets used by the tree walkers and the
  generated analyzer configs are now one canonical list, so `node_modules`,
  `.venv`, build output, and cache directories are excluded consistently.

### Added

- `bughunt init`: bootstrap a repository with a starter `bughunt.toml` and
  auto-configure analysis targets. Never overwrites an existing config.
- Shipped rule `bughunt-unused-auth-param` (ast-grep, JS): a function taking an
  authorization-shaped parameter that never reaches its digest/comparison
  sink. Covers the auth-preimage family (BC-000022) with positive/negative
  fixtures.

## [0.10.0] - 2026-09-24

Data-invariant layer (SPEC-BUG-DATA01, ADR-009): new native `data`
defense with BHMISS001 (fillna(0) into quantitative sinks), BHDF001
(stale derived columns via column-level SSA), BHINT001/2 (half-open
selection into integrators; trailing-as-forward), BHART001/2
(use-before-validation; freshness-subset fingerprints), BHMETA001/2
(contradictory availability metadata; quality-metadata gaps),
BHTIME002 (local-wall-as-UTC), BHINV001 (eq-vs-neq predicate pairs).
SemanticValue gains missingness/time_basis/interval_alignment/
dependencies facets. Cheap shapes via generators: 4 ast-grep rules
(unguarded [0], fillna tripwire, runtime assert, repo-relative
resource) + 3 Semgrep rules (boolean denylist, version-constant
shape, hardcoded success claim). Packaging gains BHPKG002 isolated
wheel-install smoke. BugCorpus BC-000014-021 with pos/neg/adv
fixtures. `data` joins the PR correctness floor (old bughunt.toml
files gain it automatically).

Scan-fix release: generated checker configs no longer ship defects
(mypy `explicit_package_bases` + `mypy_path`, dead pylint disables
dropped), binary-spy tests patch the real `technology` resolver,
vulture/ruff false positives scoped with reasons, `_supports_flag`
promoted to public `supports_flag`, assertion-free-test rule scoped
to test files, yaml indentation fixed, lockfile current.

## [0.9.3] - 2026-09-16

cli.py split: the 6.5k-line orchestrator is now focused modules
(`checkctx`, `checks_*`, `probes`, `config`, `debt`, `reporting`,
`argparse_cli`, `runners`, `doctor_*`, `ui`) with cli.py at 872 lines;
mutmut generation completes per file (cli.py 9.5s, reporting 30s).
Silent-failure rule search: assertion-free tests, swallowed loop
errors, ignored warnings filters, and suppressed exceptions, each
proven against the real binaries. Scan hardening: threaded-test
serialization with capture drain, main-thread SIGINT guard, racy-tree
discovery tolerance, capped post-exit drains, and a stall heartbeat.
Strict-debt batch: typed raw-config accessors (call-overload cleared
on touched paths), public cross-module names, import-cycle fix, and
precision fixes (BHDB001 `dict.get` noise, redundant imports).

## [0.9.2] - 2026-09-15

Isolated-install repair: every analyzer resolves through the target
environment (no more phantom "not installed" SKIPs or reinstall
churn), ready checks probe the target venv directly, module checks
use the target interpreter, and the protocol helper emits the
findings envelope so findings survive parsing. Version-drift armor:
import-linter flags and pylint disables are validated against the
installed binary. Atheris requires its native extension in the
target env; alembic skips without runnable config; benchmarks map
exit-5 to SKIP; nested build output is excluded from JS tooling.

## [0.9.1] - 2026-09-15

Every invocation prints `bughunt vX.Y.Z` to stderr, so the running
version is always visible while stdout stays clean for machine output.

## [0.9.0] - 2026-09-15

Semantic-correctness release: interprocedural abstract-interpretation
engine over the SCC graph skeleton with confidence-ranked evidence
(BHUNIT004 time-unit contradictions, BHSEM001 nominal, BHSEM002
instant/duration, BHSEM003 timezone, BHSEM004 dtype narrowing,
BHSEM005 promotion, BHSEM006 shape, BHSEM007 scale, BHSEM008 frames,
BHSEM009 encoding, BHSEM010 nullability, BHCONC001 shared writers);
protocol batch BHPRT005-015 (resource state, def-use, framework
semantics); CrossHair witness confirmation; twelve BugCorpus family
cases. Field hardening from real-repo runs: installers get a 600s
kill-timeout and target-env ready checks, all analyzer resolutions go
through the target environment, atheris requires its native extension,
alembic skips without runnable config, benchmarks run serially,
bugcorpus findings use the real result schema, nested build output is
excluded from JS tooling, and Ctrl-C writes a partial report (130)
instead of tracebacking.

## [0.8.0] - 2026-09-14

Graph-evidence release: SCC/System IR and TraceLayer wired as real rings
(index/export cache, drift/invariant findings, verification/diagnostic
evidence); Transitive Verification (BHVERIFY001) and hollow-surface
(BHIMPL001) detectors over the System IR graph; protocol-correctness ring
(BHPRT001-004: assert-carried exceptions, async magic, yield-in-magic,
unguarded next) as DeepSource-PTC concept ports with provenance; recursive
`**kwargs` drift (BHSEAM002) extended one file-boundary outward via SCC
call edges with stale-cache and ambiguity guards; test suite at 87.5% line
and 80.0% branch coverage with two dead branches removed.

## [0.7.0] - 2026-09-13

Repository-governance release: accepted-debt ledger (`debt.toml`) with
snapshot/review so known debt stays visible without inflating health;
target-environment interpreter handling and isolated analyzer runtimes;
subprocess and import safety work including injection BugCase BC-000001;
repository-compliance spec with actionable-clean `skipmutmut`; naming-layer
unit rules BHUNIT001/002/003; calibrated strict-analyzer overlays with ADRs;
test suite at 85% line coverage; packaging provenance (`py.typed`, sdist
excludes, MANIFEST.in); fault-injection regression tests proving graceful
degradation; seam comparators repaired (chained-call JSON, dotted
serialization boundaries, validator inputs, soft-vs-hard reads).

## [0.6.0] - 2026-09-10

Runtime, seam, environment, and history correctness: branch coverage,
runtime Typeguard verification, randomized test order, timezone/locale/
interpreter matrices, concurrency checks, HypoFuzz, packaging verification,
public-API/version differentials, seam drift detection, and a
coverage-weighted risk map. Full notes in `docs/RELEASE_0.6.0.md`.
