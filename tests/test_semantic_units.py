# Copyright (c) 2026 Carter LaSalle
"""BHUNIT004: interprocedural unit contradiction over sink contracts."""

from pathlib import Path

from bughunt.graph.facts import CallEdge, GraphFacts, Symbol
from bughunt.semantic import contradictions


def _facts(*pairs: tuple[str, str, str, str]) -> GraphFacts:
    facts = GraphFacts()
    for caller_file, caller, callee_file, callee in pairs:
        facts.calls.append(
            CallEdge(
                Symbol(f"u:{caller}", caller_file, caller),
                Symbol(f"u:{callee}", callee_file, callee),
                0.9,
            )
        )
    return facts


def _scan(tmp_path: Path, files: dict[str, str], facts: GraphFacts) -> list[str]:
    paths: list[Path] = []
    for name, source in files.items():
        path = tmp_path / name
        path.write_text(source)
        paths.append(path)
    return [c.code for c in contradictions.scan(tmp_path, paths, facts)]


# trace:v1 id=test.tests-test-semantic-units.test-direct-ms-to-sleep work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_direct_ms_to_sleep(tmp_path: Path) -> None:
    codes = _scan(
        tmp_path,
        {"a.py": "import time\n\n\ndef f(timeout_ms):\n    time.sleep(timeout_ms)\n"},
        GraphFacts(),
    )
    assert codes == ["BHUNIT004"]


# trace:v1 id=test.tests-test-semantic-units.test-interprocedural-ms-to-sleep work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_interprocedural_ms_to_sleep(tmp_path: Path) -> None:
    codes = _scan(
        tmp_path,
        {
            "a.py": (
                "import time\n\n\ndef retry(delay):\n    time.sleep(delay)\n"
                "\n\ndef main(timeout_ms):\n    retry(timeout_ms)\n"
            )
        },
        _facts(("a.py", "main", "a.py", "retry")),
    )
    assert codes == ["BHUNIT004"]


# trace:v1 id=test.tests-test-semantic-units.test-bad-divisor-to-sleep work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_bad_divisor_to_sleep(tmp_path: Path) -> None:
    codes = _scan(
        tmp_path,
        {
            "a.py": (
                "import time\n\n\ndef conv(x):\n    return x / 100\n"
                "\n\ndef main(timeout_ms):\n    v = conv(timeout_ms)\n"
                "    time.sleep(v)\n"
            )
        },
        _facts(("a.py", "main", "a.py", "conv")),
    )
    assert codes == ["BHUNIT004"]


# trace:v1 id=test.tests-test-semantic-units.test-valid-conversion-is-quiet work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_valid_conversion_is_quiet(tmp_path: Path) -> None:
    codes = _scan(
        tmp_path,
        {
            "a.py": (
                "import time\n\n\ndef conv(x):\n    return x / 1000\n"
                "\n\ndef main(timeout_ms):\n    v = conv(timeout_ms)\n"
                "    time.sleep(v)\n"
            )
        },
        _facts(("a.py", "main", "a.py", "conv")),
    )
    assert codes == []


# trace:v1 id=test.tests-test-semantic-units.test-seconds-to-sleep-is-quiet work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_seconds_to_sleep_is_quiet(tmp_path: Path) -> None:
    codes = _scan(
        tmp_path,
        {"a.py": "import time\n\n\ndef f(timeout_s):\n    time.sleep(timeout_s)\n"},
        GraphFacts(),
    )
    assert codes == []


# trace:v1 id=test.tests-test-semantic-units.test-unknown-to-sleep-is-quiet work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_unknown_to_sleep_is_quiet(tmp_path: Path) -> None:
    codes = _scan(
        tmp_path,
        {"a.py": "import time\n\n\ndef f(x):\n    time.sleep(x)\n"},
        GraphFacts(),
    )
    assert codes == []


# trace:v1 id=test.tests-test-semantic-units.test-id-domain-mismatch work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_id_domain_mismatch(tmp_path: Path) -> None:
    codes = _scan(
        tmp_path,
        {
            "a.py": (
                "def get_user(user_id):\n    return user_id\n"
                "\n\ndef main(project_id):\n    get_user(project_id)\n"
            )
        },
        _facts(("a.py", "main", "a.py", "get_user")),
    )
    assert codes == ["BHSEM001"]


# trace:v1 id=test.tests-test-semantic-units.test-same-id-domain-is-quiet work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_same_id_domain_is_quiet(tmp_path: Path) -> None:
    codes = _scan(
        tmp_path,
        {
            "a.py": (
                "def get_user(user_id):\n    return user_id\n"
                "\n\ndef main(user_id):\n    get_user(user_id)\n"
            )
        },
        _facts(("a.py", "main", "a.py", "get_user")),
    )
    assert codes == []


# trace:v1 id=test.tests-test-semantic-units.test-frame-mismatch work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_frame_mismatch(tmp_path: Path) -> None:
    codes = _scan(
        tmp_path,
        {
            "a.py": (
                "def render(point_world):\n    return point_world\n"
                "\n\ndef main(point_camera):\n    render(point_camera)\n"
            )
        },
        _facts(("a.py", "main", "a.py", "render")),
    )
    assert codes == ["BHSEM008"]


# trace:v1 id=test.tests-test-semantic-units.test-instant-arithmetic work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_instant_arithmetic(tmp_path: Path) -> None:
    codes = _scan(
        tmp_path,
        {
            "a.py": (
                "import time\n\n\ndef f():\n    start = time.time()\n"
                "    stamp = time.time()\n    return start + stamp\n"
            )
        },
        GraphFacts(),
    )
    assert codes == ["BHSEM002"]


# trace:v1 id=test.tests-test-semantic-units.test-mixed-dimension-addition work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_mixed_dimension_addition(tmp_path: Path) -> None:
    codes = _scan(
        tmp_path,
        {
            "a.py": (
                "def f(distance_m, duration_s):\n    return distance_m + duration_s\n"
            )
        },
        GraphFacts(),
    )
    assert codes == ["BHUNIT004"]


# trace:v1 id=test.tests-test-semantic-units.test-get-deref work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_get_deref(tmp_path: Path) -> None:
    codes = _scan(
        tmp_path,
        {"a.py": "def f(d, k):\n    v = d.get(k)\n    return v.strip()\n"},
        GraphFacts(),
    )
    assert codes == ["BHSEM010"]


# trace:v1 id=test.tests-test-semantic-units.test-get-with-default-is-quiet work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_get_with_default_is_quiet(tmp_path: Path) -> None:
    codes = _scan(
        tmp_path,
        {"a.py": "def f(d, k):\n    v = d.get(k, '')\n    return v.strip()\n"},
        GraphFacts(),
    )
    assert codes == []


# trace:v1 id=test.tests-test-semantic-units.test-guarded-get-is-quiet work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_guarded_get_is_quiet(tmp_path: Path) -> None:
    codes = _scan(
        tmp_path,
        {
            "a.py": (
                "def f(d, k):\n    v = d.get(k)\n"
                "    if v is None:\n        return ''\n"
                "    return v.strip()\n"
            )
        },
        GraphFacts(),
    )
    assert codes == []


# trace:v1 id=test.tests-test-semantic-units.test-early-exit-guard-is-quiet work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_early_exit_guard_is_quiet(tmp_path: Path) -> None:
    codes = _scan(
        tmp_path,
        {
            "a.py": (
                "def f(d, k):\n    v = d.get(k)\n"
                "    if not v:\n        return ''\n"
                "    return v.strip()\n"
            )
        },
        GraphFacts(),
    )
    assert codes == []


# trace:v1 id=test.tests-test-semantic-units.test-tz-mixing work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_tz_mixing(tmp_path: Path) -> None:
    codes = _scan(
        tmp_path,
        {
            "a.py": (
                "import datetime\n\n\ndef f():\n"
                "    a = datetime.datetime.now(datetime.timezone.utc)\n"
                "    b = datetime.datetime.now()\n"
                "    return a + b\n"
            )
        },
        GraphFacts(),
    )
    assert codes == ["BHSEM003"]


# trace:v1 id=test.tests-test-semantic-units.test-dtype-narrowing work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_dtype_narrowing(tmp_path: Path) -> None:
    codes = _scan(
        tmp_path,
        {
            "a.py": (
                "import numpy as np\n\n\ndef f():\n"
                "    a = np.zeros((4,), dtype=np.float64)\n"
                "    return a.astype(np.int8)\n"
            )
        },
        GraphFacts(),
    )
    assert codes == ["BHSEM004"]


# trace:v1 id=test.tests-test-semantic-units.test-widening-cast-is-quiet work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_widening_cast_is_quiet(tmp_path: Path) -> None:
    codes = _scan(
        tmp_path,
        {
            "a.py": (
                "import numpy as np\n\n\ndef f():\n"
                "    a = np.zeros((4,), dtype=np.float32)\n"
                "    return a.astype(np.float64)\n"
            )
        },
        GraphFacts(),
    )
    assert codes == []


# trace:v1 id=test.tests-test-semantic-units.test-promotion-risk work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_promotion_risk(tmp_path: Path) -> None:
    codes = _scan(
        tmp_path,
        {
            "a.py": (
                "import numpy as np\n\n\ndef f():\n"
                "    a = np.zeros((), dtype=np.uint64)\n"
                "    b = np.zeros((), dtype=np.int64)\n"
                "    return a + b\n"
            )
        },
        GraphFacts(),
    )
    assert codes == ["BHSEM005"]


# trace:v1 id=test.tests-test-semantic-units.test-reshape-total work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_reshape_total(tmp_path: Path) -> None:
    codes = _scan(
        tmp_path,
        {
            "a.py": (
                "import numpy as np\n\n\ndef f():\n"
                "    a = np.zeros((2, 3))\n"
                "    return a.reshape(4, 2)\n"
            )
        },
        GraphFacts(),
    )
    assert codes == ["BHSEM006"]


# trace:v1 id=test.tests-test-semantic-units.test-good-reshape-is-quiet work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_good_reshape_is_quiet(tmp_path: Path) -> None:
    codes = _scan(
        tmp_path,
        {
            "a.py": (
                "import numpy as np\n\n\ndef f():\n"
                "    a = np.zeros((2, 3))\n"
                "    return a.reshape(3, 2)\n"
            )
        },
        GraphFacts(),
    )
    assert codes == []


# trace:v1 id=test.tests-test-semantic-units.test-jaxtyping-dims work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_jaxtyping_dims(tmp_path: Path) -> None:
    codes = _scan(
        tmp_path,
        {
            "a.py": (
                "def f(x: 'Float[Tensor, \"batch channels\"]'):\n"
                "    return x\n"
                "def g(y: 'Float[Tensor, \"batch height\"]'):\n"
                "    return f(y)\n"
            )
        },
        _facts(("a.py", "g", "a.py", "f")),
    )
    assert codes == ["BHSEM006"]


# trace:v1 id=test.tests-test-semantic-units.test-percent-fraction work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_percent_fraction(tmp_path: Path) -> None:
    codes = _scan(
        tmp_path,
        {
            "a.py": (
                "def show(opacity):\n"
                "    return opacity\n"
                "def main(progress_pct):\n"
                "    show(progress_pct)\n"
                "def good(progress_pct):\n"
                "    show(progress_pct / 100)\n"
            )
        },
        _facts(
            ("a.py", "main", "a.py", "show"),
            ("a.py", "good", "a.py", "show"),
        ),
    )
    assert codes == ["BHSEM007"]


# trace:v1 id=test.tests-test-semantic-units.test-bytes-into-md5 work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_str_into_md5(tmp_path: Path) -> None:
    codes = _scan(
        tmp_path,
        {
            "a.py": (
                "import hashlib\n\n\ndef f(password: str):\n"
                "    return hashlib.md5(password)\n"
                "def g(password: str):\n"
                "    return hashlib.md5(password.encode())\n"
            )
        },
        GraphFacts(),
    )
    assert codes == ["BHSEM009"]


# trace:v1 id=test.tests-test-semantic-units.test-domain-edges work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_domain_edges() -> None:
    from bughunt.semantic.domains import dtype as D
    from bughunt.semantic.domains import units as U
    from bughunt.semantic.model import SemanticValue as V

    assert D.normalize_dtype("np.float32") == "float32"
    assert D.normalize_dtype("str") is None
    assert not D.is_narrower("int32", "int32")
    assert not D.is_narrower("int32", "int64")
    assert D.is_narrower("float32", "int32")
    assert D.is_narrower("uint32", "int32")
    assert not D.is_narrower("int32", "float64")
    same = V(dtype="float32", confidence=0.9, provenance="a")
    assert D.transfer_arith(same, same) is None
    assert D.transfer_arith(V(confidence=0.5), V(confidence=0.5)) is None
    plain = V(provenance="p", confidence=0.5)
    assert U.transfer_additive(
        V(dimension={"time": 1}, confidence=0.8), plain
    ).dimension == {"time": 1}
    assert U.compatible(plain, plain)
    assert U.transfer_div(
        V(dimension={"time": 1}, unit="ms", provenance="name:x", confidence=0.8), plain
    ).provenance.startswith("bad-divisor:")


# trace:v1 id=test.tests-test-semantic-units.test-extractor-shapes work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_extractor_shapes(tmp_path: Path) -> None:
    codes = _scan(
        tmp_path,
        {
            "a.py": (
                "import time\n\n\nasync def a(timeout_ms):\n"
                "    time.sleep(timeout_ms)\n"
                "class C:\n"
                "    def m(self, timeout_ms):\n"
                "        time.sleep(timeout_ms)\n"
                "def k(*, timeout_ms):\n"
                "    time.sleep(timeout_ms)\n"
                "def n(timeout_ms):\n"
                "    x: int = timeout_ms\n"
                "    time.sleep(x)\n"
                "def r(sock, pw: str):\n"
                "    import hashlib\n"
                "    data = sock.recv(1024)\n"
                "    s = data.decode()\n"
                "    hashlib.md5(data)\n"
                "    hashlib.md5(s)\n"
            )
        },
        GraphFacts(),
    )
    assert sorted(codes) == [
        "BHSEM009",
        "BHUNIT004",
        "BHUNIT004",
        "BHUNIT004",
        "BHUNIT004",
    ]


# trace:v1 id=test.tests-test-semantic-units.test-quiet-shapes work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_quiet_shapes(tmp_path: Path) -> None:
    codes = _scan(
        tmp_path,
        {"a.py": "def f():\n    x = foo()()\n    return x\n"},
        GraphFacts(),
    )
    assert codes == []
