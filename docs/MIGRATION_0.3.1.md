<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
# BugHunt 0.3.1 Hotfix

This release fixes defects exposed by a real v0.3.0 `deep/all` run.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Fixed

- Semgrep no longer combines `--config auto` with `--metrics=off`; `auto` is normalized to `p/default`, while `p/security-audit` and `p/secrets` remain enabled.
- Pysa gets an isolated `.bughunt/runtime/pysa-venv` compatibility runtime using Python 3.12 and `click<8.2`, while the fallback CLI receives explicit `--version=none` arguments.
- Pylint 4 compatibility: the removed `suggestion-mode` option is no longer generated.
- CodeQL database construction and `mutmut results` are internal phases rather than extra logical defenses, fixing counters such as `completed 25/23`.
- Absolute/relative finding paths are canonicalized so hot-file counts do not duplicate the same file.
- Pyrefly groups by its named diagnostic kind instead of internal negative numeric codes.
- Generic mypy `misc` findings group by normalized message shape rather than collapsing unrelated diagnostics.
- Mutmut survivors group by owning function instead of individual mutant number.
- Signal ranking is severity-first, then frequency; low-priority/style frequency is still shown separately.
- Pysa clean results are marked degraded/incomplete if Pyrefly is not clean.
- Normal scans auto-configure quietly.
- Deep/all pytest enables CPython developer mode and treats warnings as errors.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Apply to an existing 0.3.0 tree

```bash
cd ~/Downloads/bughunt
unzip -o ~/Downloads/bughunt-hotfix-0.3.1.zip

uv sync

# One-time: create the isolated Pysa compatibility runtime.
uv run bughunt install --only pysa

uv run bughunt configure --auto
uv run bughunt doctor

uv run bughunt pr
uv run bughunt deep
# or:
uv run bughunt all
```

The hotfix deliberately does not overwrite your `pyproject.toml` or root `bughunt.toml`, because earlier `bughunt install` runs may already have added analyzer dependencies there. Runtime normalization safely handles old Semgrep `configs = ["auto", ...]` settings.

For a new installation, use the full 0.3.1 package instead.
