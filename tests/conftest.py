# Copyright (c) 2026 Carter LaSalle
"""Shared pytest helpers."""

import functools
import threading
from collections.abc import Callable
from typing import ParamSpec, TypeVar

_GLOBAL_STATE_LOCK = threading.Lock()

_P = ParamSpec("_P")
_T = TypeVar("_T")


# trace:v1 id=test.tests-conftest.serialized work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def serialized(fn: Callable[_P, _T]) -> Callable[_P, _T]:
    """Hold one process-wide lock for the whole test call.

    ``pytest-run-parallel`` invokes the bare test function in worker threads
    with fixtures set up once around the bundle, so fixture-level locking
    cannot serialize invocations: only a decorator on the test itself runs
    inside each worker call. Use this on every test that touches
    process-global state (``monkeypatch`` targets, ``capsys``/``capfd``
    assertions, global registries). Tests without it still run fully in
    parallel, so the thread-safety signal is preserved where it can exist.

    The same bundle scope means one capture buffer is shared across
    iterations: after the call, drain any unread output so a print after the
    test's last readouterr cannot poison the next invocation's assertions.
    """

    # trace:v1 id=test.tests-conftest-serialized.wrapper work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    @functools.wraps(fn)
    def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> _T:
        with _GLOBAL_STATE_LOCK:
            try:
                return fn(*args, **kwargs)
            finally:
                for name in ("capsys", "capfd"):
                    readouterr = getattr(kwargs.get(name), "readouterr", None)
                    if callable(readouterr):
                        _ = readouterr()

    return wrapper
