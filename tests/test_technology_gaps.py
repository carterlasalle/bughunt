# Copyright (c) 2026 Carter LaSalle
"""Technology probes: git baseline, paths, dialects, executables."""

from pathlib import Path


def test_git_baseline_without_repo_is_none(tmp_path: Path) -> None:
    from bughunt.technology import _git_baseline

    assert _git_baseline(tmp_path) is None


def test_git_baseline_on_real_repo() -> None:
    from bughunt.technology import _git_baseline

    root = Path(__file__).resolve().parent.parent
    sha = _git_baseline(root)
    assert sha is None or len(sha) == 40


def test_git_path_exists_guards() -> None:
    from bughunt.technology import git_path_exists

    root = Path(__file__).resolve().parent.parent
    assert git_path_exists(root, None, "pyproject.toml") is False
    assert git_path_exists(root, "HEAD", "pyproject.toml") is True
    assert git_path_exists(root, "HEAD", "no-such-file-xyz.toml") is False


def test_infer_sql_dialect_defaults_to_ansi(tmp_path: Path) -> None:
    from bughunt.technology import infer_sql_dialect

    assert infer_sql_dialect(tmp_path, []) == "ansi"
    _ = (tmp_path / "q.sql").write_text("SELECT id SERIAL PRIMARY KEY")
    assert infer_sql_dialect(tmp_path, ["q.sql"]) == "postgres"


def test_project_executable_prefers_repo_local(tmp_path: Path) -> None:
    import os
    import stat

    from bughunt.technology import project_executable

    local = tmp_path / ".venv" / "bin"
    local.mkdir(parents=True)
    tool = local / "mytool"
    _ = tool.write_text("#!/bin/sh\n")
    _ = tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    assert project_executable(tmp_path, "mytool") == str(tool)
    assert project_executable(tmp_path, "no-such-tool-xyz") is None
    assert os.access(tool, os.X_OK)


def test_inventory_evidence_lists_detections(tmp_path: Path) -> None:
    from bughunt.technology import discover_technologies

    inventory = discover_technologies(tmp_path, persist=False)
    assert inventory.evidence("python") == []


def test_engine_applicable_unknown_engine_defaults_true(tmp_path: Path) -> None:
    from bughunt.technology import discover_technologies, engine_applicable

    inventory = discover_technologies(tmp_path, persist=False)
    assert engine_applicable(inventory, "no-such-engine-xyz") is True
