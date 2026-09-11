<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
# BugHunt Strict Configuration Audit

BugHunt's generated configs are deliberately **max-recall**. The goal is not to create a pleasant lint baseline; it is to expose as many plausible defects and analysis blind spots as the installed engines can express. `uv run bughunt configure --auto` owns these overlays under `.bughunt/configs/` and refreshes them before normal scans unless `--no-auto-config` is supplied.

A finding can be deprioritized in the report, but a rule is not silently disabled merely because it is noisy. Generated/runtime/vendor paths are excluded so strictness applies to first-party code.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Ruff

Generated: `.bughunt/configs/ruff.toml`

- `select = ["ALL"]` — every non-deprecated rule family.
- `preview = true` + `explicit-preview-rules = false` — broad selectors include preview rules too.
- `ignore = []` — BugHunt does not hide rule families.
- `unfixable = ["ALL"]` and no `--fix` — analysis never mutates source.
- `force-exclude = true` — exclusions still apply when BugHunt passes paths explicitly.
- First-party `src` paths are supplied for import classification.
- Strict annotation/type-checking settings and tighter McCabe/Pylint-derived complexity limits are enabled.
- Style/convention results remain findings but are ranked below correctness/security findings in the agent queue.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## basedpyright

Generated: `.bughunt/configs/basedpyrightconfig.json`

- `typeCheckingMode = "all"`, `failOnWarnings = true`, `pythonPlatform = "All"`.
- Strict list/set/dict inference and `strictGenericNarrowing`.
- `Any`, explicit `Any`, all `Unknown*` flows, unreachable code, missing stubs, invalid casts, unsafe multiple inheritance, implicit abstract classes, incompatible unannotated overrides, and local private-import violations are errors.
- Generic `# type: ignore` is disabled; rule-qualified BasedPyright suppressions are auditable.
- Legacy bytes promotions are disabled.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## mypy

Generated: `.bughunt/configs/mypy.ini`

- `strict = True` plus checks not implied by strict, including `warn_unreachable` and optional correctness codes.
- Every practical `Any` escape hatch is banned: unimported, expression, decorated, explicit, generic, and subclassing.
- Untyped third-party Python imports are analyzed with `follow_untyped_imports = True` instead of being immediately collapsed to `Any`.
- Strict bytes/equality/None equality, extra checks, unused-ignore/redundant-cast reporting, and exhaustive-match/possibly-undefined/unused-awaitable checks are enabled.
- Missing imports are **not** ignored.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## ty

Generated: `.bughunt/configs/ty.toml`

- `[rules] all = "error"` enables even rules disabled by default.
- Strict equality semantics and strict generic narrowing are enabled.
- Generic `type: ignore` comments are not accepted by ty, keeping it independent from the other checkers' escape hatches.
- Warnings fail the run.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Pyrefly

Generated: `.bughunt/configs/pyrefly.toml`

- `preset = "all"` enables every error kind.
- Unannotated function bodies are checked and return types are inferred.
- No unresolved/untyped import is intentionally replaced with `Any`.
- Strict callable subtyping is explicit; ALL_CAPS names are treated as final to surface accidental constant redefinitions.
- Generated-code errors are not globally ignored; BugHunt instead excludes its own runtime/generated infrastructure by path.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Pylint

Generated: `.bughunt/configs/pylintrc`

Pylint 4 removed the old `suggestion-mode` option; BugHunt does not emit it.

- `enable=all` activates every standard message, including normally-disabled informational diagnostics.
- BugHunt dynamically discovers the **bundled extension modules in the installed Pylint version** and loads every public one. This avoids maintaining a stale hard-coded extension list.
- Inference result limits are raised substantially above default and complexity/design thresholds are strict.
- Tool/runtime/vendor paths are excluded.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Vulture

Configured by BugHunt runner.

- `quick`: confidence >= 80.
- `pr`: confidence >= 60.
- `deep` and `all`: confidence >= 0, maximizing dead/unreachable-code recall.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Bandit

Generated: `.bughunt/configs/bandit.yaml`

- Empty `tests` / `skips` means every installed Bandit test runs.
- Scans first-party source roots only so test assertions and BugHunt's private runtimes do not dominate the output.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## deptry

Configured by BugHunt runner because deptry also needs the project's real `pyproject.toml` to resolve dependency declarations.

- No DEP rule is ignored.
- Experimental namespace-package discovery is enabled for additional recall.
- First-party source roots are scanned and BugHunt/build/vendor paths are excluded.
- DEP001..DEP005 are normalized individually into the report.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Import Linter

Generated: `.bughunt/configs/importlinter.toml`

BugHunt will not invent an application layering policy. It does generate the strongest architecture invariant that is generically defensible: recursively check inferred first-party package siblings for import cycles using `acyclic_siblings`. TYPE_CHECKING edges remain visible. If no importable package root can be proven, the config remains a review gap rather than a fabricated contract.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## ast-grep

Generated: `.bughunt/configs/sgconfig.yml` plus rule/test directories.

A high-confidence generic structural pack is generated immediately (for example swallowed exceptions and `return` in `finally`). The directory is also the destination for Bug Corpus/V2-generated project-specific structural detectors.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Semgrep

Configured by BugHunt runner plus `.bughunt/configs/semgrep/rules/`. BugHunt is correctness-first: auto-configuration writes seven locally owned high-signal correctness rules and every Semgrep scan includes those local/generated rules plus the explicit `p/default` registry baseline. `auto` is rewritten to `p/default` because BugHunt keeps metrics disabled.

Security-only packs are **not forced into the correctness baseline**. They remain available through:

```toml
[semgrep]
include_security = true
security_configs = ["p/security-audit", "p/secrets"]
```

User-specified `semgrep.configs` are preserved, deduplicated, and supplemented by `p/default` plus BugHunt's local correctness rules. The generated pack currently covers cached generators, unconsumed `ThreadPoolExecutor.map`, mutation during iteration, blocking sleep in async code, file-handle rebinding before close, and temporary-file flush/order mistakes.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## CodeQL

Configured by BugHunt runner.

- Python uses `security-and-quality`, not the smaller default suite. That includes default + security-extended + additional reliability/maintainability queries.
- Database creation prefers the configured first-party source root instead of indexing `.bughunt/runtime` and unrelated project artifacts.
- Any custom `.ql` queries under `.bughunt/configs/codeql/queries/` are added to the analysis automatically.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Pysa / Pyre

Generated: `.pyre_configuration`, `.bughunt/configs/pysa/taint.config`, and `.bughunt/configs/pysa/*.pysa` when no existing project config blocks safe generation. Execution prefers an isolated `.bughunt/runtime/pysa-venv` compatibility environment and explicitly sets the legacy CLI version arguments.

- First-party source directories and BugHunt taint model path are configured.
- Model verification is **never disabled by BugHunt's strict runner**. A malformed model is an analysis failure, not something to bypass with `--no-verify`.
- A valid custom source/sink namespace is established. Application-specific semantic source/sink models are added only when evidence supports them; guessing them would create a false claim of taint coverage.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Deal

Configured by BugHunt runner.

`python -m deal lint --json` runs across first-party source roots. CrossHair separately consumes Deal contracts during symbolic execution. Deal's own formal verifier remains a candidate extra deep stage for contract-heavy repositories because it only applies to a limited pure-Python subset.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## CrossHair

Configured by BugHunt runner.

- Analysis kinds: assertions, PEP 316, Deal, and icontract.
- Solver budgets increase from normal runs to deep/all runs.
- First-party source roots only.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## pytest + Hypothesis

Generated: `.bughunt/configs/hypothesis_plugin.py`; pytest flags supplied by runner.

- pytest uses `--strict-config`, `--strict-markers`, and strict xfail handling.
- Hypothesis BugHunt profile uses 2,000 examples, 100 state-machine steps, shrinking, multiple-bug reporting, and no suppressed health checks.
- The run is intentionally not deterministically seeded so repeated deep campaigns explore new examples; Hypothesis still emits reproduction information for failures.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## mutmut

Current mutmut requires project-root configuration, so BugHunt appends a bounded managed `[tool.mutmut]` block when one is absent and first creates `.bughunt/backups/pyproject.toml.before-bughunt-mutmut`.

- All inferred source paths are mutated.
- `mutate_only_covered_lines = false` intentionally includes uncovered source because uncovered logic is itself a correctness risk.
- A BugHunt-managed block is refreshed when inferred source/test roots change.
- User-owned `[tool.mutmut]` configuration is never overwritten, but auto-configuration now checks whether `source_paths` and `pytest_add_cli_args_test_selection` actually cover the inferred repository roots. Missing/obsolete configuration is reported as `REVIEW`, not falsely as ready.
- Use `bughunt skipmutmut`, `bughunt all --skip-mutmut`, or `bughunt all --skip mutmut` for the maximal profile without the expensive mutation stage.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Schemathesis

Generated: `.bughunt/configs/schemathesis.toml` plus safe auto-discovered targets.

- Positive + negative generation (`mode = "all"`).
- At least 1,000 examples per operation in BugHunt's strict auto configuration.
- Shrinking enabled, extra parameters and NUL bytes allowed, all checks enabled by command, continue-on-failure enabled, and workers set to auto.
- FastAPI apps can be tested in-process; remote server URLs are never attacked merely because they appear in an OpenAPI file.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Atheris

Engine installation and target discovery are separate.

- On Apple Silicon, BugHunt can source-build Atheris with Homebrew LLVM into `.bughunt/runtime/atheris/` without contaminating the project's uv lock.
- Auto-discovery generates a target only for a high-confidence module-level one-input parser/decoder/deserializer shape.
- Deep auto campaigns have a floor of 500,000 runs per generated target.
- Generated harnesses are first-class files under `.bughunt/generated/atheris/`, so agents can inspect and strengthen them.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## What auto-configuration cannot honestly invent

`configure --auto` now configures the analyzers themselves. Some *semantic targets* cannot be generated safely from syntax alone: a business-specific Pysa source/sink, the reference side of a differential test, a valid metamorphic invariant, or a fault-injection expectation. BugHunt records those as explicit coverage gaps rather than fabricating a rule that creates false confidence. V2 is designed to synthesize these from evidence and then adversarially validate them before promotion.


<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## v0.4.0 auto-target and fix metadata

Ruff keeps `fixable = ["ALL"]` while BugHunt never passes `--fix` during analysis. This preserves JSON fix/applicability metadata for reporting. Semgrep fix strings are likewise recorded but never applied during scans. `configure --auto` also generates evidence-backed semantic campaigns and direct Pysa wrapper models; see `AUTO_DISCOVERY.md`.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## v0.5.0: default policy + complexity layer

BugHunt now adds native policy and metric analyzers so important repository invariants still run even when a third-party engine is unavailable.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### Native policy scanner

The shipped rule manifest is in `DEFAULT_RULES.md` and can be rendered with `uv run bughunt rules`. The return/break/continue-in-finally hazard is intentionally redundant with Ruff `B012` and a dedicated ast-grep rule. Configuration/environment, architecture/persistence boundaries, user-format round trips, and test coupling are handled as evidence-sensitive repository policies.

`configure --auto` also maintains a managed `.env.example` contract when environment-variable access is detected. Secret-like variables are emitted blank; simple numeric range checks such as `1 <= PORT <= 65535` are reflected in the generated comments when statically visible.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### Complexity

The native scanner provides cyclomatic, function LOC, file LOC, ABC, and built-asset budgets. It is complemented by:

- Ruff `C901` at McCabe complexity 10;
- Complexipy cognitive complexity at 10;
- Lizard CCN/NLOC/parameter checks across supported languages;
- Radon Maintainability Index reporting;
- Pylint's design/refactoring limits.

See `COMPLEXITY.md` for the exact defaults and anti-gaming expectations.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## v0.5.2 technology-aware correctness layer

`configure --auto` now emits a capability inventory and only activates technology-specific engines when their input surface exists. Non-applicable engines are `N/A`, not skipped, and are excluded from the defense-health denominator. See `TECHNOLOGY_ENGINES.md` for the engine-by-engine policy.

The correctness-focused additions are actionlint, ShellCheck, dotenv-linter, oasdiff, Buf, SQLFluff (curated semantic rules), Squawk, Hadolint, TFLint, golangci-lint (curated bug linters), Clippy correctness/suspicious, Cppcheck, clang-tidy bugprone/analyzer/concurrency, Infer when provisioned, PHPStan max, Oxlint correctness/suspicious, ESLint's correctness fallback, and React Doctor without supply-chain scanning. OpenAPI and Protobuf checks are history-aware when a local Git baseline is available.



<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## v0.6.0 runtime and behavioral correctness layers

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### Coverage

Coverage.py is the canonical portable engine with branch measurement enabled. Missing executable ranges (`BHCOV001`) and missing branch edges (`BHCOV002`) are findings, not dashboard trivia. Coverage feeds the per-file risk map. Slipcover is an optional speed-oriented second implementation.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### Mutation

BugHunt-managed mutmut configuration mutates covered lines by default. This deliberately separates two questions: coverage asks *can the suite reach this behavior?*; mutation asks *would the suite notice if reachable behavior changed?* Exhaustive mutation can still be requested separately.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### Runtime types

A dedicated Typeguard pytest pass turns annotations into runtime contracts for executed code. beartype is an optional alternative rather than a second mandatory runtime instrumentation layer.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### Test variation and concurrency

Deep/all runs include randomized test/hash ordering, network denial, xdist loadfile isolation, asyncio Blockbuster checks, `PYTHONASYNCIODEBUG=1`, hostile timezone/locale passes when supported, and a Nox interpreter matrix. Free-threaded Python sessions get pytest-run-parallel. A canonical seed remains recorded for reproduction; random exploration is not pinned permanently to zero.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### Property/fuzz search

Hypothesis remains the property engine. HypoFuzz uses coverage feedback under a bounded search budget. A budget timeout is reported as budget exhaustion, not as an analyzer crash. Ghostwriter and Pynguin are guarded generators: they remain visible but are not silently executed against arbitrary application imports.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### Packaging and API history

Packaging checks include validate-pyproject, `uv lock --check`, `uv pip check`, build metadata validation, `twine check`, and manifest checks where applicable. Griffe and BugHunt's safe version-differential runner compare HEAD against a local Git baseline. OpenAPI/Protobuf technology layers add their own compatibility checks.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### Seam correctness

BHSEAM/BHEVID/BHDB/BHTIME rules defend points where static types are commonly erased: JSON, dict payloads, kwargs, DB boundaries, external HTTP responses, files/queues, time, and schema/model transitions. See `SEAM_CORRECTNESS.md`.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### Reporting

Reports preserve raw findings and add logical issue clusters, cross-tool correlations, ODC-like defect classes, branch-coverage summaries, and a coverage-weighted risk map. Logical deduplication must never destroy independent analyzer evidence.
