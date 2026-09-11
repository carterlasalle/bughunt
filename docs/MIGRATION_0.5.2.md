<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
# BugHunt 0.5.2 Migration

0.5.2 adds technology-aware correctness analysis. It is backwards-compatible with old `bughunt.toml` profile lists: PR/deep/all dynamically receive the new applicable-engine floor, so an old project config cannot silently omit a new correctness defense.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Existing 0.5.1 checkout

```bash
cd ~/Downloads/bughunt
unzip -o ~/Downloads/bughunt-hotfix-0.5.2.zip
python3 HOTFIX_APPLY.py
uv sync
uv run bughunt configure --auto
uv run bughunt doctor

# Maximal scan without mutation testing
uv run bughunt skipmutmut

# Everything, including mutation testing
uv run bughunt all
```

`HOTFIX_APPLY.py` preserves unrelated project configuration. It updates the BugHunt version and makes the new tool names visible in the bundled profile config; runtime profile augmentation also protects older external configs.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## What changes in reports

A new `N/A` state distinguishes an irrelevant defense from an applicable defense that failed to run:

- `N/A`: no matching repository capability; does **not** lower defense health.
- `SKIPPED`: capability applies, but tool/required config could not run; **does** lower defense health.
- `ERROR`: analyzer/runtime failure; lowers health and causes the default exit code 2.

`configure --auto` and `doctor` now display repository capabilities and their evidence. Capability inventory is persisted at `.bughunt/generated/capabilities.json`.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## History-aware checks

When a local Git baseline can be established, OpenAPI and Protobuf gain compatibility checks in addition to current-revision validation/linting. No network fetch is required to choose the baseline.
