# Copyright (c) 2026 Carter LaSalle
"""Version-differential oracle: safe-function gating and behavior diffs."""

import ast
import json
import subprocess
from pathlib import Path


def _parse(source: str) -> ast.FunctionDef:
    for node in ast.parse(source).body:
        if isinstance(node, ast.FunctionDef):
            return node
    raise AssertionError(f"no function in:\n{source}")


def test_safe_function_gates() -> None:
    from bughunt.version_diff_runner import _safe_function

    ok = _parse("def add(a: int, b: int) -> int:\n    return a + b\n")
    assert _safe_function(ok) is not None
    cases = [
        "import os\n@dec\ndef f(a: int) -> int:\n    return a\n",
        "def f(a: int, *args) -> int:\n    return a\n",
        "def f(a: int, b: int, c: int, d: int) -> int:\n    return a\n",
        "def f(a: Custom) -> Custom:\n    return a\n",
        "def f(a: int) -> int:\n    x = []\n    for i in range(3):\n        x.append(i)\n    return a\n",
        "def f(a: int) -> int:\n    return evil(a)\n",
        "def f(a: int) -> int:\n    x = {}\n    x[0] = a\n    return a\n",
        "def f() -> int:\n    return 1\n",
    ]
    for source in cases:
        assert _safe_function(_parse(source)) is None, source


def test_functions_skips_unparseable() -> None:
    from bughunt.version_diff_runner import _functions

    assert _functions("def f(:\n") == {}
    assert set(_functions("def f() -> None:\n    pass\n")) == {"f"}


def test_main_needs_three_args(capsys) -> None:
    from bughunt.version_diff_runner import main

    assert main([]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["compared"] == 0


def test_git_show_without_repo_returns_none(tmp_path: Path) -> None:
    from bughunt.version_diff_runner import _git_show

    assert _git_show(tmp_path, "HEAD", "a.py") is None


def _git(*args: str, cwd: Path) -> None:
    _ = subprocess.run(  # noqa: S603 - test-only git with literal args
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )


def test_behavior_change_is_caught(tmp_path: Path, capsys) -> None:
    from bughunt.version_diff_runner import main

    _git("init", "-q", cwd=tmp_path)
    _git("config", "user.email", "t@example.com", cwd=tmp_path)
    _git("config", "user.name", "t", cwd=tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    target = src / "calc.py"
    _ = target.write_text("def add(a: int, b: int) -> int:\n    return a + b\n")
    _git("add", ".", cwd=tmp_path)
    _git("commit", "-qm", "base", cwd=tmp_path)
    _ = target.write_text("def add(a: int, b: int) -> int:\n    return a - b\n")
    assert main([str(tmp_path), "HEAD", "src"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["compared"] == 1
    assert payload["findings"][0]["code"] == "BHDIFF001"


def test_identical_tree_is_clean(tmp_path: Path, capsys) -> None:
    from bughunt.version_diff_runner import main

    _git("init", "-q", cwd=tmp_path)
    _git("config", "user.email", "t@example.com", cwd=tmp_path)
    _git("config", "user.name", "t", cwd=tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    _ = (src / "calc.py").write_text(
        "def add(a: int, b: int) -> int:\n    return a + b\n",
    )
    _git("add", ".", cwd=tmp_path)
    _git("commit", "-qm", "base", cwd=tmp_path)
    assert main([str(tmp_path), "HEAD", "src"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"] == []


# trace:v1 id=test.tests-test-version-diff.test-signature-only-change-is-clean work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_signature_only_change_is_clean(tmp_path: Path, capsys) -> None:
    from bughunt.version_diff_runner import main

    _git("init", "-q", cwd=tmp_path)
    _git("config", "user.email", "t@example.com", cwd=tmp_path)
    _git("config", "user.name", "t", cwd=tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    target = src / "calc.py"
    _ = target.write_text("def add(a: int, b: int) -> int:\n    return a + b\n")
    _git("add", ".", cwd=tmp_path)
    _git("commit", "-qm", "base", cwd=tmp_path)
    # Same behavior, wider annotation domain: Griffe owns API-shape drift.
    _ = target.write_text("def add(a: int, b: float) -> float:\n    return a + b\n")
    assert main([str(tmp_path), "HEAD", "src"]) == 0
    assert json.loads(capsys.readouterr().out)["findings"] == []
    # Same behavior, changed default: not a behavioral mismatch.
    _ = target.write_text("def add(a: int, b: int = 1) -> int:\n    return a + b\n")
    assert main([str(tmp_path), "HEAD", "src"]) == 0
    assert json.loads(capsys.readouterr().out)["findings"] == []
