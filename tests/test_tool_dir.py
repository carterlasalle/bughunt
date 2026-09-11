"""Stale tool-output cleanup (must survive read-only analyzer droppings)."""

import os
import stat

from bughunt.cli import _reset_tool_dir


def test_reset_tool_dir_removes_read_only_tree(tmp_path):
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


def test_reset_tool_dir_missing_path_is_noop(tmp_path):
    _reset_tool_dir(tmp_path / "nope")
    assert os.access(tmp_path, os.W_OK)
