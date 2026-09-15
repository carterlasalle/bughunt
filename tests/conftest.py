# Copyright (c) 2026 Carter LaSalle
"""Shared pytest fixtures."""

import threading

import pytest


_GLOBAL_STATE_LOCK = threading.Lock()


# trace:v1 id=test.tests-conftest.serialize-global-mutation work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
@pytest.fixture(autouse=True)
def _serialize_global_mutation(request: pytest.FixtureRequest):
    """Hold one lock for every test that patches process-global state.

    ``monkeypatch`` is documented as not thread-safe, and most of its uses
    here patch process-global state (CLI module attributes, ``shutil.which``,
    environment variables). Under ``pytest-run-parallel`` those tests raced
    with each other and produced phantom world-state failures. Tests that do
    not use ``monkeypatch`` still run fully in parallel, so the
    thread-safety signal is preserved where it can exist.
    """
    if "monkeypatch" in request.fixturenames:
        with _GLOBAL_STATE_LOCK:
            yield
    else:
        yield
