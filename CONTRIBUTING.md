# Contributing

BugHunt is a Python project managed with `uv`. Python 3.11+ required
(see `.python-version`).

## Setup

```sh
uv sync
uv run bughunt doctor
```

## Day-to-day

```sh
uv run pytest -q            # focused/full test suite (tests/ is the whole suite)
uv run ruff check src tests # lint
uv run ruff format --check src tests
uv run mypy src             # typecheck (strict; see pyproject.toml)
uv run bughunt quick        # low-latency analyzer pass over this repo
```

## Pull requests

- Small, atomic commits; subject ~50 chars, imperative mood, no trailing
  period (see AGENTS.md for the full standard).
- PR title: `type(scope): summary`, e.g. `fix(cli): report skipped tools`.
- PR body: Goal, Summary, What changed, How to verify, Risks/follow-ups.
- `trace verify --changed` must pass; new behavior needs a `trace:v1`
  marker or an explicit `# trace:exempt` reason.
- Do not commit `.bughunt/reports/`, `.bughunt/cache/`, or coverage output.
