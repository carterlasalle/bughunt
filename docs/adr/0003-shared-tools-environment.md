<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
# ADR-003: Shared tools environment replaces `uv add` into target repos

<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
## Context

The installer provisioned analyzer tools with `uv add --dev <tool>` inside
the *target* repository (observed: ~50 consecutive adds on a fresh repo).
That mutates `pyproject.toml` and `uv.lock`, dirties the tree, forces a
full re-resolution per added package (lock drift makes every later `uv run`
re-sync and redownload), and repeats the whole cost on every scan. The
Pysa runtime already proves the alternative: an isolated venv under
`.bughunt/runtime/` owned by BugHunt, never by the target manifest.

<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
## Decision

- BugHunt never runs `uv add` (or any manifest/lock mutator) in the target
  repo. Provisioning is read-only with respect to the target manifest.
- Static analyzers (ruff, mypy, pylint, bandit, semgrep, …) install once
  into a shared, content-addressed tools venv managed by BugHunt, rebuilt
  only when the pinned tool spec changes. `project_executable` keeps
  checking the target `.venv` first (per-repo version fidelity), then the
  shared env, then `PATH`.
- pytest *plugins* cannot live in the shared env (they import target code
  inside the target's pytest process). They install with
  `uv pip install --python <target-venv>` — venv-only, no manifest churn.
  Repos without a usable target venv get an explicit SKIP stating what to
  install, never a silent system-python fallback that errors on imports.
- JS tools already follow this shape (project `node_modules` first, no
  `package.json` mutation); no change there.

<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
## Alternatives

- One `uv tool install` per analyzer (rejected: ~50 isolated venvs,
  multiplied disk and no shared dependency resolution).
- Keep `uv add --dev` (rejected: tree pollution, per-scan re-resolution
  and redownloads, lock drift; the exact pain in the 2026-09-11 report).
- Ephemeral per-scan venvs (rejected: same download cost as today with
  extra complexity; the shared env caches across scans and repos).

<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
## Consequences

Fresh-repo scans stop dirtying `pyproject.toml`/`uv.lock` and stop
re-resolving the world: first scan pays one shared install, later scans
reuse it. Per-repo tool pins still win via the existing resolution order.
Implementing this replaces the `uv add` branches in `installers.py` and
needs the installer test matrix plus a migration note (repos carrying
previously added dev deps keep working; nothing removes them).
