"""Generated runtime plugins carry their own trace accounting."""

from bughunt.runtime_plugins import (
    TRACE_EXEMPT_PY,
    blockbuster_plugin,
    noxfile,
    write_runtime_plugins,
)


def test_blockbuster_plugin_stamped():
    # configure rewrites this file on every run, so a hand-placed marker
    # would evaporate and the authoring obligation would return.
    assert blockbuster_plugin().splitlines()[0] == TRACE_EXEMPT_PY


def test_noxfile_stamped():
    assert noxfile(["3.12"], ["tests"]).splitlines()[0] == TRACE_EXEMPT_PY


def test_write_runtime_plugins_stamps_output(tmp_path):
    paths = write_runtime_plugins(tmp_path, ["3.12"], ["tests"])
    assert len(paths) == 2
    for path in paths:
        assert path.read_text().splitlines()[0] == TRACE_EXEMPT_PY
