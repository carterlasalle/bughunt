# Copyright (c) 2026 Carter LaSalle
"""Target-environment resolution and empty-exit mapping."""

import asyncio
import stat
import sys
from pathlib import Path

import pytest

from bughunt.cli import Check, Status, run_process
from bughunt.technology import target_executable, target_has_module, target_python


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
