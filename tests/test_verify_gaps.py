# Copyright (c) 2026 Carter LaSalle
"""Verification gaps: transitive coverage and hollow stubs from graph data."""

from pathlib import Path


def _ir(*entities, calls=(), tested=()):
    rels = [{"predicate": "calls", "subject": s, "object": o} for s, o in calls] + [
        {"predicate": "tested_by", "subject": s} for s in tested
    ]
    return {
        "entities": list(entities),
        "relationships": rels,
    }


def _sym(symbol_id, file="src/pkg/mod.py", line=1, kind="function"):
    return {
        "id": symbol_id,
        "kind": "symbol",
        "attributes": {
            "file": file,
            "start_line": line,
            "end_line": line + 5,
            "kind": kind,
        },
    }


def test_transitive_gap_names_tested_callees(monkeypatch, tmp_path: Path) -> None:
    from bughunt import verify_gaps

    _ = (tmp_path / "src" / "pkg").mkdir(parents=True)
    _ = (tmp_path / "src" / "pkg" / "mod.py").write_text(
        "def top():\n    return helper()\n"
    )
    data = _ir(
        _sym("s/top"),
        _sym("s/helper"),
        calls=[("s/top", "s/helper")],
        tested=["s/helper"],
    )
    monkeypatch.setattr(verify_gaps, "_load_graph", lambda root: data)
    findings = verify_gaps.scan(tmp_path)
    assert [(item["code"], item["path"]) for item in findings] == [
        ("BHVERIFY001", "src/pkg/mod.py")
    ]
    assert "helper" in str(findings[0]["message"])


def test_directly_tested_is_quiet(monkeypatch, tmp_path: Path) -> None:
    from bughunt import verify_gaps

    data = _ir(_sym("s/top"), tested=["s/top"])
    monkeypatch.setattr(verify_gaps, "_load_graph", lambda root: data)
    assert verify_gaps.scan(tmp_path) == []


def test_private_and_nested_and_tests_are_quiet(monkeypatch, tmp_path: Path) -> None:
    from bughunt import verify_gaps

    _ = (tmp_path / "src").mkdir()
    _ = (tmp_path / "src" / "m.py").write_text("def _hidden():\n    pass\n")
    data = _ir(
        _sym("s/_hidden", file="src/m.py"),
        _sym("s/helper", file="src/m.py"),
        _sym("s/test_x", file="tests/test_m.py"),
        calls=[("s/_hidden", "s/helper")],
        tested=["s/helper"],
    )
    monkeypatch.setattr(verify_gaps, "_load_graph", lambda root: data)
    assert verify_gaps.scan(tmp_path) == []


def test_hollow_stub_is_flagged(monkeypatch, tmp_path: Path) -> None:
    from bughunt import verify_gaps

    _ = (tmp_path / "src").mkdir()
    _ = (tmp_path / "src" / "m.py").write_text("def serve():\n    ...\n")
    data = _ir(_sym("s/serve", file="src/m.py", line=1))
    monkeypatch.setattr(verify_gaps, "_load_graph", lambda root: data)
    findings = verify_gaps.scan(tmp_path)
    assert [(item["code"]) for item in findings] == ["BHIMPL001"]


def test_abstract_stub_is_quiet(monkeypatch, tmp_path: Path) -> None:
    from bughunt import verify_gaps

    _ = (tmp_path / "src").mkdir()
    _ = (tmp_path / "src" / "m.py").write_text(
        "import abc\n\n\nclass Base:\n"
        + "    @abc.abstractmethod\n"
        + "    def serve(self):\n"
        + "        ...\n"
    )
    data = _ir(_sym("s/serve", file="src/m.py", line=6))
    monkeypatch.setattr(verify_gaps, "_load_graph", lambda root: data)
    assert verify_gaps.scan(tmp_path) == []


def test_mention_suppresses_heuristic_gap(monkeypatch, tmp_path: Path) -> None:
    from bughunt import verify_gaps

    _ = (tmp_path / "src" / "pkg").mkdir(parents=True)
    _ = (tmp_path / "src" / "pkg" / "mod.py").write_text(
        "def top():\n    return helper()\n"
    )
    _ = (tmp_path / "tests").mkdir()
    _ = (tmp_path / "tests" / "test_mod.py").write_text(
        "from pkg.mod import top\n\ndef test_top() -> None:\n    top()\n"
    )
    data = _ir(
        _sym("s/top"),
        _sym("s/helper"),
        calls=[("s/top", "s/helper")],
        tested=["s/helper"],
    )
    monkeypatch.setattr(verify_gaps, "_load_graph", lambda root: data)
    assert verify_gaps.scan(tmp_path) == []


def test_main_gates_and_contracts(monkeypatch, tmp_path: Path, capsys) -> None:
    import json
    import sys

    from bughunt import verify_gaps

    monkeypatch.setattr(sys, "argv", ["bughunt-verify-gaps"])
    assert verify_gaps.main([]) == 2
    assert "root required" in capsys.readouterr().out
    assert verify_gaps.main([str(tmp_path)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["not_applicable"] is True


def test_load_graph_failure_is_empty_scan(monkeypatch, tmp_path: Path) -> None:
    from bughunt import verify_gaps

    monkeypatch.setattr("bughunt.verify_gaps._load_graph", lambda root: None)
    assert verify_gaps.scan(tmp_path) == []


def test_module_level_guards(tmp_path: Path) -> None:
    from bughunt.verify_gaps import _module_level

    assert _module_level(tmp_path, "m.py", "x") is False
    assert _module_level(tmp_path, "missing.py", 1) is False
    _ = (tmp_path / "m.py").write_text("def f():\n    pass\n")
    assert _module_level(tmp_path, "m.py", 0) is False
    assert _module_level(tmp_path, "m.py", 99) is False
    assert _module_level(tmp_path, "m.py", 1) is True
    assert _module_level(tmp_path, "m.py", 2) is False


def test_stub_body_variants(tmp_path: Path) -> None:
    from bughunt.verify_gaps import _stub_body

    cases = [
        ("def f():\n    pass\n", True),
        ("def f():\n    return 42\n", True),
        ("def f():\n    raise NotImplementedError\n", True),
        ("def f():\n    raise NotImplementedError('x')\n", True),
        ("def f():\n    raise ValueError('x')\n", False),
        ('def f():\n    """Doc."""\n', True),
        ("def f():\n    x = 1\n    return x\n", False),
        ("def f(:\n", False),
    ]
    for index, (source, expected) in enumerate(cases):
        path = tmp_path / f"s{index}.py"
        _ = path.write_text(source)
        assert _stub_body(tmp_path, path.name, 1, 3) is expected, source
    assert _stub_body(tmp_path, "missing.py", 1, 3) is False
    assert _stub_body(tmp_path, "s0.py", "1", 3) is False


# trace:v1 id=test.tests-test-verify-gaps.test-load-graph-reads-cache work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_load_graph_reads_cache(monkeypatch, tmp_path: Path) -> None:
    import json

    from bughunt import system_ir_adapter, verify_gaps

    cache = tmp_path / "cache.json"
    _ = cache.write_text(json.dumps({"system_ir": {"entities": []}}))
    monkeypatch.setattr(system_ir_adapter, "export", lambda root: (cache, None))
    assert verify_gaps._load_graph(tmp_path) == {"entities": []}
    monkeypatch.setattr(system_ir_adapter, "export", lambda root: (None, "boom"))
    assert verify_gaps._load_graph(tmp_path) is None
    _ = cache.write_text("not json")
    monkeypatch.setattr(system_ir_adapter, "export", lambda root: (cache, None))
    assert verify_gaps._load_graph(tmp_path) is None
    _ = cache.write_text(json.dumps({"system_ir": [1, 2]}))
    assert verify_gaps._load_graph(tmp_path) is None


# trace:v1 id=test.tests-test-verify-gaps.test-stub-body-decorator-shapes work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_stub_body_decorator_shapes(tmp_path: Path) -> None:
    from bughunt.verify_gaps import _stub_body

    cases = [
        ("@deco\ndef f():\n    pass\n", True),
        ("@abc.abstractmethod\ndef f():\n    pass\n", False),
        ("@abc.overload\ndef f():\n    pass\n", False),
        ("def f():\n    ...\n", True),
        ("def f():\n    raise mod.NotImplementedError()\n", True),
        ("def f():\n    raise factory()()\n", False),
        ("def f():\n    raise ValueError\n", False),
        ("def g():\n    pass\ndef f():\n    pass\n", True),
        ("x = 1\n", False),
        ("async def f():\n    pass\n", True),
    ]
    for index, (source, expected) in enumerate(cases):
        path = tmp_path / f"d{index}.py"
        _ = path.write_text(source)
        if index == 7:
            assert _stub_body(tmp_path, path.name, 3, 5) is expected
        elif source.startswith("@"):
            # Decorated defs report lineno at the `def`, not the decorator.
            assert _stub_body(tmp_path, path.name, 2, 4) is expected, source
        else:
            assert _stub_body(tmp_path, path.name, 1, 3) is expected, source


# trace:v1 id=test.tests-test-verify-gaps.test-call-decorator-and-concrete-pair work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_call_decorator_and_concrete_pair(monkeypatch, tmp_path: Path) -> None:
    from bughunt import verify_gaps
    from bughunt.verify_gaps import _stub_body

    path = tmp_path / "c.py"
    _ = path.write_text('@deco("x")\ndef f():\n    pass\n')
    assert _stub_body(tmp_path, path.name, 2, 4) is True
    src = tmp_path / "src"
    _ = src.mkdir(exist_ok=True)
    _ = (src / "m.py").write_text(
        "def concrete():\n    x = 1\n    return x\n\n\ndef hollow():\n"
        "    pass\n\n\ndef tail():\n    y = 2\n    return y\n"
    )

    # trace:v1 id=test.tests-test-verify-gaps-test-call-decorator-and-concrete-pair.ent work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    def _ent(symbol: str, line: int) -> dict[str, object]:
        return {
            "id": symbol,
            "kind": "symbol",
            "attributes": {
                "file": "src/m.py",
                "start_line": line,
                "end_line": line + 1,
                "kind": "function",
            },
        }

    data = {
        "entities": [_ent("s/concrete", 1), _ent("s/hollow", 6), _ent("s/tail", 10)],
        "relationships": [],
    }
    monkeypatch.setattr(verify_gaps, "_load_graph", lambda root: data)
    findings = verify_gaps.scan(tmp_path)
    assert [item["code"] for item in findings] == ["BHIMPL001"]


# trace:v1 id=test.tests-test-verify-gaps.test-scan-ignores-malformed-graph work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_scan_ignores_malformed_graph(monkeypatch, tmp_path: Path) -> None:
    from bughunt import verify_gaps

    for bad in (
        {"entities": {}, "relationships": []},
        {"entities": [], "relationships": {}},
    ):
        monkeypatch.setattr(verify_gaps, "_load_graph", lambda root: bad)
        assert verify_gaps.scan(tmp_path) == []
    data = {
        "entities": [
            "nope",
            {"kind": "edge", "id": "e/1"},
            {"kind": "symbol", "id": 42},
            {"kind": "symbol", "id": "s/1", "attributes": []},
            {
                "kind": "symbol",
                "id": "s/2",
                "attributes": {"file": "docs/a.md", "kind": "function"},
            },
            {
                "kind": "symbol",
                "id": "s/3",
                "attributes": {"file": "src/a.py", "kind": "class"},
            },
        ],
        "relationships": [
            "nope",
            {"predicate": "tested_by", "subject": 42},
            {"predicate": "calls", "subject": "s/1", "object": 42},
            {"predicate": "likes", "subject": "s/1", "object": "s/2"},
        ],
    }
    _ = (tmp_path / "src").mkdir(exist_ok=True)
    _ = (tmp_path / "src" / "a.py").write_text("X = 1\n")
    monkeypatch.setattr(verify_gaps, "_load_graph", lambda root: data)
    assert verify_gaps.scan(tmp_path) == []


# trace:v1 id=test.tests-test-verify-gaps.test-test-mentions-edge-shapes work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_test_mentions_edge_shapes(tmp_path: Path) -> None:
    from bughunt.verify_gaps import _test_mentions

    assert _test_mentions(tmp_path) == set()
    test_dir = tmp_path / "tests"
    _ = test_dir.mkdir()
    _ = (test_dir / "bad.py").write_text("def (:\n")
    _ = (test_dir / "plain.py").write_text("from . import thing\n")
    _ = (test_dir / "unused.py").write_text(
        "from pkg.mod import helper\n\n\ndef test_x():\n    assert True\n"
    )
    assert _test_mentions(tmp_path) == set()


# trace:v1 id=test.tests-test-verify-gaps.test-main-reports-findings work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_main_reports_findings(monkeypatch, tmp_path: Path, capsys) -> None:
    import json

    from bughunt import verify_gaps

    _ = (tmp_path / ".scc").mkdir()
    finding = {"tool": "verify-gaps", "code": "BHVERIFY001"}
    monkeypatch.setattr(verify_gaps, "scan", lambda root: [finding])
    assert verify_gaps.main([str(tmp_path)]) == 1
    assert json.loads(capsys.readouterr().out)["findings"] == [finding]
    monkeypatch.setattr(verify_gaps, "scan", lambda root: [])
    assert verify_gaps.main([str(tmp_path)]) == 0
