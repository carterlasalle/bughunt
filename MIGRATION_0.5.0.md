# BugHunt 0.5.0

## What changed

- ships a first-class native default rule pack (`uv run bughunt rules`);
- keeps the return/break/continue-in-finally rule as a default **error**, with independent Ruff and ast-grep overlap;
- adds configuration-contract rules and managed `.env.example` generation;
- `.env.example` metadata can include required/optional status, defaults, inferred type, units, simple statically-provable numeric ranges, examples, and source locations;
- adds private/internal and persistence-boundary architecture rules;
- adds "everything exported must come home" round-trip policy plus generated Hypothesis properties where signatures make the invariant executable;
- adds implementation-coupled-test warnings;
- adds native cyclomatic, function/file LOC, ABC, and built-asset budgets;
- adds Complexipy, Radon, and Lizard as independent complexity engines;
- adds `full` as an alias for `all`;
- `all` / `full` install missing analyzers by default before configuring/scanning;
- the standalone BugHunt dev group now includes the normal analyzer stack, so a fresh `uv sync` dogfood checkout is useful instead of mostly blind;
- scan summaries continue to show safe/review/unsafe deterministic autofix counts and the percent of all findings with a known deterministic fix.

## Existing 0.4 checkout

```bash
cd ~/Downloads/bughunt
unzip -o ~/Downloads/bughunt-hotfix-0.5.0.zip
python3 HOTFIX_APPLY.py
uv sync
uv run bughunt configure --auto
uv run bughunt doctor
uv run bughunt rules
uv run bughunt full
```

`HOTFIX_APPLY.py` upgrades the BugHunt project version, adds missing dogfood dev analyzers, augments existing PR/deep/all profiles with the policy/complexity engines, and appends default complexity budgets only when you do not already have a `[complexity]` table. It preserves unrelated/custom configuration.
