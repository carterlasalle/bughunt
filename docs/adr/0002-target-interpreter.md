<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
# ADR-002: Resolve test interpreters from the target repository

<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
## Context

Defenses resolved `pytest`, plugin availability, and helper interpreters
from the *runner* environment (`shutil.which`, `importlib`,
`sys.executable`). An isolated install (`uv tool install bughunt`) scanning
a repo with its own `.venv` therefore ran system pytest against foreign
tests (`ModuleNotFoundError`, observed 2026-09-10) and reported ~35 phantom
"not installed" SKIPs for packages present in the target env.

<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
## Decision

`technology.py` owns three helpers: `target_python` (`.venv/bin/python`,
else `sys.executable`), `target_executable` (`.venv/bin/<name>`, else PATH),
and `target_has_module` (importlib probe against a given interpreter).
The pytest family (pytest, doctest, matrices, memray, benchmark,
runtime-types, pytest-* plugins), the coverage launcher, and the installer
readiness checks use the target interpreter. Helpers that execute BugHunt's
own modules (`-m bughunt.*`) stay on the runner unless the target can import
`bughunt`, preserving foreign-target behavior exactly.

<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
## Alternatives

Requiring `uv run` (rejected: uvx/pipx/CI consumers cannot); auto-wrapping
commands in `uv run` inside BugHunt (rejected: nests environments, slow,
surprising); fixing each defense ad hoc (rejected: one bug class, one fix).

<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
## Consequences

Repos without `.venv` behave exactly as before (fallback chain). Empty
pytest-style exits (5, nothing collected) map to SKIP via `skip_exit_codes`
instead of ERROR. Re-check the Windows `Scripts/` branch on a Windows runner;
all receipts are POSIX.
