# Copyright (c) 2026 Carter LaSalle
"""BHCONC001: shared-state multi-writer without synchronization."""

from pathlib import Path

from bughunt.detectors import concurrency
from bughunt.graph.facts import GraphFacts


def _scan(tmp_path: Path, source: str):
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    _ = (src / "conc.py").write_text(source)
    return concurrency.scan(tmp_path, ["src"], GraphFacts())


# trace:v1 id=test.tests-test-concurrency.test-dual-unsync-writers work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_dual_unsync_writers(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "import threading\n"
        + "def w1():\n"
        + "    f = open('/tmp/x.log', 'w')\n"
        + "    f.write('a')\n"
        + "def w2():\n"
        + "    f = open('/tmp/x.log', 'w')\n"
        + "    f.write('b')\n"
        + "t1 = threading.Thread(target=w1)\n"
        + "t2 = threading.Thread(target=w2)\n",
    )
    assert [item.code for item in findings] == ["BHCONC001"]


# trace:v1 id=test.tests-test-concurrency.test-locked-writers-quiet work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_locked_writers_quiet(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "import threading\n"
        + "lock = threading.Lock()\n"
        + "def w1():\n"
        + "    with lock:\n"
        + "        f = open('/tmp/x.log', 'w')\n"
        + "        f.write('a')\n"
        + "def w2():\n"
        + "    with lock:\n"
        + "        f = open('/tmp/x.log', 'w')\n"
        + "        f.write('b')\n"
        + "t1 = threading.Thread(target=w1)\n"
        + "t2 = threading.Thread(target=w2)\n",
    )
    assert findings == []


# trace:v1 id=test.tests-test-concurrency.test-unthreaded-writers-quiet work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_unthreaded_writers_quiet(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "def w1():\n"
        + "    f = open('/tmp/x.log', 'w')\n"
        + "    f.write('a')\n"
        + "def w2():\n"
        + "    f = open('/tmp/x.log', 'w')\n"
        + "    f.write('b')\n",
    )
    assert findings == []


# trace:v1 id=test.tests-test-concurrency.test-distinct-paths-quiet work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_distinct_paths_quiet(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "import threading\n"
        + "def w1():\n"
        + "    f = open('/tmp/a.log', 'w')\n"
        + "    f.write('a')\n"
        + "def w2():\n"
        + "    f = open('/tmp/b.log', 'w')\n"
        + "    f.write('b')\n"
        + "t1 = threading.Thread(target=w1)\n"
        + "t2 = threading.Thread(target=w2)\n",
    )
    assert findings == []


# trace:v1 id=test.tests-test-concurrency.test-global-writer work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_global_writer(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "import threading\n"
        + "def w1():\n"
        + "    global total\n"
        + "    total = 1\n"
        + "def w2():\n"
        + "    global total\n"
        + "    total = 2\n"
        + "t1 = threading.Thread(target=w1)\n"
        + "t2 = threading.Thread(target=w2)\n",
    )
    assert [item.code for item in findings] == ["BHCONC001"]


# trace:v1 id=test.tests-test-concurrency.test-acquire-sync-quiet work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_acquire_sync_quiet(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "import threading\n"
        + "lock = threading.Lock()\n"
        + "def w1():\n"
        + "    lock.acquire()\n"
        + "    f = open('/tmp/x.log', 'w')\n"
        + "    lock.release()\n"
        + "def w2():\n"
        + "    lock.acquire()\n"
        + "    f = open('/tmp/x.log', 'w')\n"
        + "    lock.release()\n"
        + "t1 = threading.Thread(target=w1)\n"
        + "t2 = threading.Thread(target=w2)\n",
    )
    assert findings == []


# trace:v1 id=test.tests-test-concurrency.test-unreachable-writer-quiet work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_unreachable_writer_quiet(tmp_path: Path) -> None:
    from bughunt.detectors import concurrency

    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    _ = (src / "conc.py").write_text(
        "import threading\n"
        + "def w1():\n"
        + "    f = open('/tmp/x.log', 'w')\n"
        + "def w2():\n"
        + "    f = open('/tmp/x.log', 'w')\n"
        + "t1 = threading.Thread(target=w1)\n"
        + "t2 = threading.Thread(target=other)\n"
    )
    findings = concurrency.scan(tmp_path, ["src"], GraphFacts())
    assert [item.code for item in findings] == []
