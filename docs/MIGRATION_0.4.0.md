<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
# BugHunt 0.4.0

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Existing 0.3.1 checkout

Apply the source hotfix, preserving your project-level dependency additions:

```bash
cd ~/Downloads/bughunt
unzip -o ~/Downloads/bughunt-hotfix-0.4.0.zip
python3 HOTFIX_APPLY.py
uv sync
uv run bughunt configure --auto
uv run bughunt doctor
uv run bughunt pr
uv run bughunt all
```

`configure --auto` will add or replace only the bounded `# BEGIN BUGHUNT MANAGED CUSTOM CHECKS` block in `bughunt.toml`; manually authored configuration outside it is preserved.

New in this version: repository-root inference, high-confidence semantic campaign generation, Pysa wrapper inference, automatic managed custom checks, and deterministic autofix accounting.
