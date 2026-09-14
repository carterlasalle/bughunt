# Copyright (c) 2026 Carter LaSalle
"""System IR adapter: real SCC consumption, cache discipline, N/A semantics."""

import json
from pathlib import Path


def _mini(tmp_path: Path) -> Path:
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    _ = (src / "a.py").write_text("def add(a: int, b: int) -> int:\n    return a + b\n")
    return tmp_path


def test_main_needs_root(monkeypatch, capsys) -> None:
    import sys

    from bughunt.system_ir_adapter import main

    monkeypatch.setattr(sys, "argv", ["bughunt-system-ir"])
    assert main([]) == 2
    assert "root required" in capsys.readouterr().out


def test_missing_cli_is_not_applicable(monkeypatch, tmp_path: Path, capsys) -> None:
    from bughunt import system_ir_adapter

    monkeypatch.setattr(system_ir_adapter, "_cli", lambda: None)
    assert system_ir_adapter.main([str(tmp_path)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["not_applicable"] is True
    cache, error = system_ir_adapter.export(tmp_path)
    assert cache is None
    assert error is not None
    assert system_ir_adapter.graph_findings(tmp_path) == []


def test_export_cache_is_stable(tmp_path: Path) -> None:
    from bughunt.system_ir_adapter import _cache_key, _cli, export

    root = _mini(tmp_path)
    first, error = export(root)
    assert error is None and first is not None
    payload = json.loads(first.read_text())
    assert payload["system_ir"]["schema_version"] == "0.1.0"
    cli = _cli()
    assert cli is not None
    assert _cache_key(root, cli) == payload["cache_key"]
    second, error = export(root)
    assert error is None and second is not None
    assert json.loads(second.read_text())["cache_key"] == payload["cache_key"]


def test_graph_findings_empty_on_clean_tree(tmp_path: Path) -> None:
    from bughunt.system_ir_adapter import graph_findings

    assert graph_findings(_mini(tmp_path)) == []


def test_main_end_to_end(tmp_path: Path, capsys) -> None:
    from bughunt.system_ir_adapter import export, main

    root = _mini(tmp_path)
    cache, error = export(root)
    assert error is None and cache is not None
    assert main([str(root)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"] == []
    assert payload["cache"] is not None


def test_run_oserror_is_structured(monkeypatch, tmp_path: Path) -> None:
    import subprocess

    from bughunt import system_ir_adapter

    def _boom(*args, **kwargs):
        raise OSError("nope")

    monkeypatch.setattr(subprocess, "run", _boom)
    code, _out, err = system_ir_adapter._run("/bin/scc", tmp_path, "index")
    assert code == 127
    assert "nope" in err


def test_export_and_graph_failures(monkeypatch, tmp_path: Path) -> None:
    from bughunt import system_ir_adapter

    _ = (tmp_path / ".scc").mkdir()
    calls = {"n": 0}

    def _fail(*args, **kwargs):
        calls["n"] += 1
        return (1, "", "boom")

    monkeypatch.setattr(system_ir_adapter, "_cli", lambda: "/bin/scc")
    monkeypatch.setattr(system_ir_adapter, "_run", _fail)
    cache, error = system_ir_adapter.export(tmp_path)
    assert cache is None and error is not None
    findings = system_ir_adapter.graph_findings(tmp_path)
    assert any(item["code"] == "BHGRAPH001" for item in findings)
    assert any(item["code"] == "BHGRAPH002" for item in findings)


def test_unparseable_payloads(monkeypatch, tmp_path: Path) -> None:
    from bughunt import system_ir_adapter

    _ = (tmp_path / ".scc").mkdir()
    monkeypatch.setattr(system_ir_adapter, "_cli", lambda: "/bin/scc")
    monkeypatch.setattr(system_ir_adapter, "_run", lambda *a, **k: (0, "not json", ""))
    cache, error = system_ir_adapter.export(tmp_path)
    assert cache is None and error is not None
    assert system_ir_adapter.graph_findings(tmp_path) == []
