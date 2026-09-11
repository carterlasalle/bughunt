"""Generated runtime plugins carry their own trace accounting (adjacent)."""

from bughunt.runtime_plugins import (
    TRACE_EXEMPT_PY,
    blockbuster_plugin,
    noxfile,
    write_runtime_plugins,
)


def _assert_adjacent_exempt(text: str) -> None:
    lines = text.splitlines()
    # The exempt must sit directly above the decorated function boundary
    # (decorator included), not merely somewhere in the file.
    idx = next(i for i, ln in enumerate(lines) if ln.startswith("@"))
    assert lines[idx - 1] == TRACE_EXEMPT_PY, "exempt must be directly above the boundary"


def test_blockbuster_plugin_stamped():
    _assert_adjacent_exempt(blockbuster_plugin())


def test_noxfile_stamped():
    _assert_adjacent_exempt(noxfile(["3.12"], ["tests"]))


def test_write_runtime_plugins_stamps_output(tmp_path):
    paths = write_runtime_plugins(tmp_path, ["3.12"], ["tests"])
    assert len(paths) == 2
    for path in paths:
        _assert_adjacent_exempt(path.read_text())
