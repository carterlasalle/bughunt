"""Target-environment resolution and empty-exit mapping."""

import asyncio
import stat
import sys
from pathlib import Path

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


def test_target_python_prefers_venv(tmp_path):
    _make_venv(tmp_path, "python")
    assert target_python(tmp_path) == str(tmp_path / ".venv" / "bin" / "python")


def test_target_python_falls_back_without_venv(tmp_path):
    assert target_python(tmp_path) == sys.executable


def test_target_executable_prefers_venv(tmp_path, monkeypatch):
    _make_venv(tmp_path, "pytest")
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/" + name)
    assert target_executable(tmp_path, "pytest") == str(
        tmp_path / ".venv" / "bin" / "pytest"
    )


def test_target_executable_falls_back(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "shutil.which", lambda name: "/usr/bin/" + name if name == "pytest" else None
    )
    assert target_executable(tmp_path, "pytest") == "/usr/bin/pytest"
    assert target_executable(tmp_path, "nope") is None


def test_target_has_module():
    assert target_has_module(sys.executable, "os")
    assert not target_has_module(sys.executable, "definitely_missing_module_xyz")


def test_target_has_module_missing_interpreter(tmp_path):
    assert not target_has_module(str(tmp_path / "no-such-python"), "os")


def _exit_five_check(**kwargs):
    return Check(
        name="t",
        category="c",
        command=[sys.executable, "-c", "raise SystemExit(5)"],
        parser=lambda o, e, c: [],
        timeout=30,
        cwd=Path("."),
        **kwargs,
    )


def test_exit_five_skips_with_skip_codes(tmp_path):
    check = _exit_five_check(skip_exit_codes={5})
    check.cwd = tmp_path
    assert asyncio.run(run_process(check, 1024)).status == Status.SKIPPED


def test_exit_five_errors_without_skip_codes(tmp_path):
    check = _exit_five_check()
    check.cwd = tmp_path
    assert asyncio.run(run_process(check, 1024)).status == Status.ERROR
