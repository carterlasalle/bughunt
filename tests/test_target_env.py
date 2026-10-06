# Copyright (c) 2026 Carter LaSalle
"""Target-environment resolution and empty-exit mapping."""

import asyncio
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from bughunt.cli import Check, Status, run_process
from bughunt.technology import (
    pytest_executable,
    pytest_python,
    pytest_venv,
    target_executable,
    target_has_module,
    target_python,
)


def _make_venv(root: Path, *names: str) -> Path:
    bindir = root / ".venv" / "bin"
    bindir.mkdir(parents=True)
    for name in names:
        script = bindir / name
        script.write_text("#!/bin/sh\n")
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return bindir


# trace:v1 id=test.tests-test-target-env.test-target-python-prefers-venv work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_target_python_prefers_venv(tmp_path: Path) -> None:
    _make_venv(tmp_path, "python")
    assert target_python(tmp_path) == str(tmp_path / ".venv" / "bin" / "python")


# trace:v1 id=test.tests-test-target-env.test-target-python-falls-back-without-venv work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_target_python_falls_back_without_venv(tmp_path: Path) -> None:
    assert target_python(tmp_path) == sys.executable


# trace:v1 id=test.tests-test-target-env.test-target-executable-prefers-venv work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_target_executable_prefers_venv(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _make_venv(tmp_path, "pytest")
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/" + name)
    assert target_executable(tmp_path, "pytest") == str(
        tmp_path / ".venv" / "bin" / "pytest",
    )


# trace:v1 id=test.tests-test-target-env.test-target-executable-falls-back work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_target_executable_falls_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "shutil.which",
        lambda name: "/usr/bin/" + name if name == "pytest" else None,
    )
    assert target_executable(tmp_path, "pytest") == "/usr/bin/pytest"
    assert target_executable(tmp_path, "nope") is None


def test_target_has_module() -> None:
    assert target_has_module(sys.executable, "os")
    assert not target_has_module(sys.executable, "definitely_missing_module_xyz")


# trace:v1 id=test.tests-test-target-env.test-target-has-module-missing-interpreter work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_target_has_module_missing_interpreter(tmp_path: Path) -> None:
    assert not target_has_module(str(tmp_path / "no-such-python"), "os")


def _exit_five_check(**kwargs):
    return Check(
        name="t",
        category="c",
        command=[sys.executable, "-c", "raise SystemExit(5)"],
        parser=lambda o, e, c: [],
        timeout=30,
        cwd=Path(),
        **kwargs,
    )


# trace:v1 id=test.tests-test-target-env.test-exit-five-skips-with-skip-codes work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_exit_five_skips_with_skip_codes(tmp_path: Path) -> None:
    check = _exit_five_check(skip_exit_codes={5})
    check.cwd = tmp_path
    assert asyncio.run(run_process(check, 1024)).status == Status.SKIPPED


# trace:v1 id=test.tests-test-target-env.test-exit-five-errors-without-skip-codes work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_exit_five_errors_without_skip_codes(tmp_path: Path) -> None:
    check = _exit_five_check()
    check.cwd = tmp_path
    assert asyncio.run(run_process(check, 1024)).status == Status.ERROR


# trace:v1 id=test.tests-test-target-env.test-pytest-python-prefers-repo-pytest-env work=WORK-BUG-4ABH9VEY satisfies=REQ-BUG-KZG483AX
def test_pytest_python_prefers_repo_pytest_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The suite's environment belongs to the repository, not BugHunt.

    A repo with no virtualenv used to run pytest from PATH, so the scan's
    result silently depended on how BugHunt was launched (`uv run` from the
    BugHunt checkout vs a globally installed tool). BugHunt's private pytest
    environment must win.
    """
    bindir = pytest_venv(tmp_path) / "bin"
    bindir.mkdir(parents=True)
    python = bindir / "python"
    python.write_text("#!/bin/sh\n")
    python.chmod(python.stat().st_mode | stat.S_IXUSR)
    pytest_script = bindir / "pytest"
    pytest_script.write_text(f"#!{python}\n")
    pytest_script.chmod(pytest_script.stat().st_mode | stat.S_IXUSR)

    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/" + name)
    assert target_executable(tmp_path, "pytest") == str(pytest_script)
    assert pytest_python(tmp_path) == str(python)


# trace:v1 id=test.tests-test-target-env.test-pytest-executable-stays-in-session-env work=WORK-BUG-4ABH9VEY satisfies=REQ-BUG-KZG483AX
def test_pytest_executable_stays_in_session_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A pytest-family CLI on PATH belongs to a foreign environment.

    Resolving it there would report the tool ready while the session cannot
    import it, so only the environment that owns the session may answer.
    """
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/" + name)
    # The repository owns the session, but has no hypothesis of its own: the
    # PATH copy (and BugHunt's own) must not answer for it.
    _make_venv(tmp_path, "python")
    assert pytest_executable(tmp_path, "hypothesis") is None

    tool = tmp_path / ".venv" / "bin" / "hypothesis"
    _ = tool.write_text("#!/bin/sh\n")
    tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    assert pytest_executable(tmp_path, "hypothesis") == str(tool)


def _scope_repo(root: Path) -> None:
    """A repo with two excluded trees and one first-party tree."""
    (root / "src" / "pkg").mkdir(parents=True)
    (root / "vendored" / "deep").mkdir(parents=True)
    (root / "third_party" / "legacy").mkdir(parents=True)
    for rel in (
        "src/pkg/keep.py",
        "vendored/drop.py",
        "vendored/deep/drop.py",
        "third_party/legacy/drop.py",
        "third_party/keep.py",
    ):
        _ = (root / rel).write_text("x = 1\n")


# trace:v1 id=test.tests-test-target-env.test-project-exclude-scopes-every-walker work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_project_exclude_scopes_every_walker(tmp_path: Path) -> None:
    """`[project] exclude` must reach the native walkers, not just the tools.

    The directory set used to be a fixed constant, so a vendored tree could
    only be dropped from Ruff; BugHunt's own scanners kept walking it. Bare
    names match any path component, slashed entries match a path prefix.
    """
    from bughunt.technology import _iter_files, scope_files

    _scope_repo(tmp_path)
    (tmp_path / "bughunt.toml").write_text(
        '[project]\nexclude = ["vendored", "third_party/legacy"]\n',
    )
    kept = {
        path.relative_to(tmp_path).as_posix() for path in scope_files(tmp_path, ["."])
    }
    assert kept == {"src/pkg/keep.py", "third_party/keep.py"}

    walked = {
        path.relative_to(tmp_path).as_posix()
        for path in _iter_files(tmp_path)
        if path.suffix == ".py"
    }
    assert walked == kept


# trace:v1 id=test.tests-test-target-env.test-gitignore-scopes-native-walkers work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_gitignore_scopes_native_walkers(tmp_path: Path) -> None:
    """A gitignored tree is skipped by the native engines, as it is by Ruff.

    Ruff's generated config sets `respect-gitignore`, so a gitignored vendored
    tree was already invisible to it while BugHunt's own scanners still read
    it. Both now agree.
    """
    from bughunt.technology import git_ignored, scope_files

    _scope_repo(tmp_path)
    (tmp_path / ".gitignore").write_text("third_party/\n")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)

    assert git_ignored(tmp_path, ["third_party/keep.py"]) == {"third_party/keep.py"}
    kept = {
        path.relative_to(tmp_path).as_posix() for path in scope_files(tmp_path, ["."])
    }
    assert kept == {"src/pkg/keep.py", "vendored/drop.py", "vendored/deep/drop.py"}


# trace:v1 id=test.tests-test-target-env.test-gitignore-is-inert-outside-a-repo work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_gitignore_is_inert_outside_a_repo(tmp_path: Path) -> None:
    """Without a git repository the built-in and configured excludes still hold.

    `git check-ignore` exits 128 outside a work tree; that must be a no-op, not
    a failure, and it must never hide first-party code on its own.
    """
    from bughunt.technology import git_ignored, scope_files

    _scope_repo(tmp_path)
    (tmp_path / ".gitignore").write_text("src/\n")
    assert git_ignored(tmp_path, ["src/pkg/keep.py"]) == set()
    kept = {
        path.relative_to(tmp_path).as_posix() for path in scope_files(tmp_path, ["."])
    }
    assert "src/pkg/keep.py" in kept


# trace:v1 id=test.tests-test-target-env.test-exclusions-match-names-and-prefixes work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_exclusions_match_names_and_prefixes(tmp_path: Path) -> None:
    """Built-in names, configured names, and configured prefixes all resolve."""
    from bughunt.technology import resolve_exclusions

    (tmp_path / "bughunt.toml").write_text(
        '[project]\nexclude = ["vendored", "third_party/legacy", "/trailing/"]\n',
    )
    exclusions = resolve_exclusions(tmp_path)
    assert ".venv" in exclusions.names
    assert "vendored" in exclusions.names
    assert "trailing" in exclusions.names
    assert exclusions.covers("anywhere/vendored/x.py")
    assert exclusions.covers("third_party/legacy/x.py")
    assert not exclusions.covers("third_party/kept/x.py")
