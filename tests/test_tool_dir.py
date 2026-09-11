# Copyright (c) 2026 Carter LaSalle
"""Stale tool-output cleanup (must survive read-only analyzer droppings)."""

from pathlib import Path


import os
import stat

from bughunt.cli import _reset_tool_dir


# trace:v1 id=test.tests-test-tool-dir.test-reset-tool-dir-removes-read-only-tree work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_reset_tool_dir_removes_read_only_tree(tmp_path: Path) -> None:
    # Mirrors a CodeQL database directory: files the tool leaves read-only,
    # which made `database create --overwrite` fail its own delete step.
    nested = tmp_path / "db" / "nested"
    nested.mkdir(parents=True)
    locked = nested / "locked.dat"
    locked.write_bytes(b"x" * 64)
    locked.chmod(stat.S_IRUSR)
    (tmp_path / "db").chmod(stat.S_IRUSR | stat.S_IXUSR)

    _reset_tool_dir(tmp_path / "db")

    assert not (tmp_path / "db").exists()


# trace:v1 id=test.tests-test-tool-dir.test-reset-tool-dir-missing-path-is-noop work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_reset_tool_dir_missing_path_is_noop(tmp_path: Path) -> None:
    _reset_tool_dir(tmp_path / "nope")
    assert os.access(tmp_path, os.W_OK)
