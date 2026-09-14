# Copyright (c) 2026 Carter LaSalle
"""Check construction: wanted subsets, N/A branches, tech engines."""

from pathlib import Path


def _cfg(root: Path):
    from bughunt.cli import load_config

    return load_config(root, root / "bughunt.toml")


def _project(root: Path, tools: list[str]) -> None:
    _ = (root / "bughunt.toml").write_text(
        '[project]\npython_paths = ["src"]\nsource_paths = ["src"]\n'
        + 'test_paths = ["tests"]\n[profiles.pr]\ntools = '
        + str(tools).replace("'", '"')
        + "\n",
    )


def test_excluded_tools_are_not_wanted(tmp_path: Path) -> None:
    from bughunt.cli import build_checks

    _project(tmp_path, ["compile", "ruff", "bandit"])
    src = tmp_path / "src"
    src.mkdir()
    _ = (src / "a.py").write_text("x = 1\n")
    checks, skipped = build_checks(_cfg(tmp_path), "pr", excluded={"ruff", "bandit"})
    check_names = {check.name for check in checks}
    skip_names = {item.name for item in skipped}
    assert "compile" in check_names
    assert "ruff" not in check_names
    assert "bandit" not in check_names
    assert {"ruff", "bandit"} <= skip_names


def test_no_python_capability_marks_python_only_na(tmp_path: Path) -> None:
    from bughunt.cli import Status, build_checks

    _project(tmp_path, ["compile", "ruff", "mypy"])
    _ = (tmp_path / "Dockerfile").write_text("FROM x\n")
    checks, skipped = build_checks(_cfg(tmp_path), "pr")
    by_name = {item.name: item for item in skipped}
    assert by_name["ruff"].status == Status.NA
    assert by_name["mypy"].status == Status.NA
    assert "compile" not in {check.name for check in checks}


def test_technology_engines_selected_when_applicable(tmp_path: Path) -> None:
    from bughunt.cli import build_checks

    _project(tmp_path, ["compile", "hadolint", "sqlfluff", "actionlint"])
    _ = (tmp_path / "Dockerfile").write_text("FROM x\n")
    _ = (tmp_path / "q.sql").write_text("SELECT 1\n")
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    _ = (workflows / "ci.yml").write_text("on: push\n")
    checks, skipped = build_checks(_cfg(tmp_path), "pr")
    names = {check.name for check in checks} | {item.name for item in skipped}
    assert {"hadolint", "sqlfluff", "actionlint"} <= names
