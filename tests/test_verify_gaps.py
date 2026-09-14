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
