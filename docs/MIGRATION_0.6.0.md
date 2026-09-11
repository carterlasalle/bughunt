<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
# Migrating BugHunt 0.5.x to 0.6.0

0.6.0 adds runtime, branch-coverage, environment-variation, seam/contract, package, API-history, concurrency, test-generation candidate, and risk/correlation layers.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Existing checkout

```bash
cd ~/Downloads/bughunt
unzip -o ~/Downloads/bughunt-hotfix-0.6.0.zip
python3 HOTFIX_APPLY.py
uv sync
uv run bughunt configure --auto
uv run bughunt doctor
```

Use `uv run bughunt skipmutmut` for the strongest routine maximal scan without the expensive mutation phase; use `uv run bughunt all` for every applicable executable defense.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Important behavior changes

- coverage.py branch coverage is a PR-level defense;
- BugHunt-managed mutmut uses covered lines, while uncovered code is reported independently;
- deep/all exercise randomized hash/test order and hostile environment variants;
- Typeguard verifies annotations at runtime during a separate test pass;
- applicable technology engines are capability-selected; irrelevant engines are `N/A`;
- raw findings are preserved, but reports also include logical deduplication and cross-tool correlations;
- guarded test generators such as Pynguin are visible but do not lower correctness health merely because BugHunt refuses unsafe automatic execution;
- agent checklists direct debugging of flaky/hanging infrastructure through `ci-fix-dont-freeze` before disabling defenses.
