# BugHunt 0.6.0 Release Verification

## Verified in the build environment

- `python -m compileall` over `src/` and `tests/`: PASS
- regression suite: **89 passed**
- `pyproject.toml` and `bughunt.toml` parse as TOML: PASS
- CLI parser / `bughunt rules`: PASS
- non-destructive 0.5.2 -> 0.6.0 hotfix migration smoke test: PASS
- synthetic `configure --auto`: PASS
  - branch coverage configuration emitted
  - interpreter-matrix configuration emitted
  - generated-target registry parses
  - typed encode/decode pair generated a round-trip campaign
  - bytes parser generated an Atheris target

## Network-limited verification

An online `uv lock` attempt was made, but the build container could not resolve `pypi.org` (DNS failure while requesting `py-spy`). An offline retry also could not resolve because the container package cache does not contain even the base `rich` requirement. Therefore this release does **not** claim that dependency resolution was completed in the build sandbox.

The dependency specifications themselves are retained in `pyproject.toml`, and current implementation tests do not depend on an invented lock result. Run `uv sync` in the destination environment as the final package-resolution check.

A failed dependency-resolution environment must never be reported as a clean package validation result.
