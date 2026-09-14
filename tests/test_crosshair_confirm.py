# Copyright (c) 2026 Carter LaSalle
"""CrossHair confirmation: witness upgrades, silent otherwise."""

from pathlib import Path

from bughunt.semantic import crosshair_confirm
from bughunt.semantic.contradictions import Contradiction


def _finding() -> Contradiction:
    return Contradiction(
        code="BHUNIT004",
        message="m",
        file="a.py",
        caller="main",
        sink="time.sleep",
        lineno=1,
        confidence=0.80,
    )


# trace:v1 id=test.tests-test-crosshair-confirm.test-missing-binary-is-silent work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_missing_binary_is_silent(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(crosshair_confirm.shutil, "which", lambda _: None)
    assert crosshair_confirm.confirm(tmp_path, [_finding()]) == set()


# trace:v1 id=test.tests-test-crosshair-confirm.test-counterexample-confirms work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_counterexample_confirms(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(crosshair_confirm.shutil, "which", lambda _: "/bin/xh")

    class _Proc:
        stdout = "Counterexample found in main:\n  x = 5"
        stderr = ""

    monkeypatch.setattr(crosshair_confirm.subprocess, "run", lambda *a, **k: _Proc())
    assert crosshair_confirm.confirm(tmp_path, [_finding()]) == {("a.py", "main")}


# trace:v1 id=test.tests-test-crosshair-confirm.test-clean-run-keeps-warning work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_clean_run_keeps_warning(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(crosshair_confirm.shutil, "which", lambda _: "/bin/xh")

    class _Proc:
        stdout = "No counterexamples found."
        stderr = ""

    monkeypatch.setattr(crosshair_confirm.subprocess, "run", lambda *a, **k: _Proc())
    assert crosshair_confirm.confirm(tmp_path, [_finding()]) == set()


# trace:v1 id=test.tests-test-crosshair-confirm.test-runner-error-keeps-warning work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_runner_error_keeps_warning(monkeypatch, tmp_path: Path) -> None:
    import subprocess

    monkeypatch.setattr(crosshair_confirm.shutil, "which", lambda _: "/bin/xh")

    def _boom(*args, **kwargs):
        raise subprocess.TimeoutExpired("xh", 1)

    monkeypatch.setattr(crosshair_confirm.subprocess, "run", _boom)
    assert crosshair_confirm.confirm(tmp_path, [_finding()]) == set()
