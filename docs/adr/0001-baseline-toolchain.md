<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
# ADR-001: Baseline toolchain (uv, Ruff, Mypy, CI)

<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
## Context

The repo had no pinned interpreter, no lockfile, no lint/type config, and
no CI. Contributors and agents need one reproducible path.

<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
## Decision

- `uv` manages Python (`dev` group in `pyproject.toml`, `uv.lock` committed).
- Local dev pins Python 3.12 (`.python-version`); the package still
  supports `>=3.11` per `pyproject.toml`.
- Ruff owns lint and format; Mypy owns typechecking; pytest owns tests.
- CI (`test`, `lint`, `typecheck` jobs) mirrors CONTRIBUTING.md commands.
- Dependabot tracks `pip` and `github-actions` weekly; CodeQL scans Python.

<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
## Alternatives

Poetry/PDM (rejected: repo already declares `uv` everywhere), pinning 3.11
(rejected: 3.12 is what the Pysa compatibility runtime targets, and 3.11
remains supported as a floor, not the dev default).

<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
## Consequences

`uv sync` reproduces the environment; CI fails on lint/type/test drift.
Bumping the dev interpreter means updating `.python-version`, this ADR's
context, and the CI matrix together.
