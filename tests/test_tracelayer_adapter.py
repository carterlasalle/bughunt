# Copyright (c) 2026 Carter LaSalle
"""TraceLayer adapter: verification diagnostics and health as findings."""

import json
from pathlib import Path


def test_main_needs_root(monkeypatch, capsys) -> None:
    import sys

    from bughunt.tracelayer_adapter import main

    monkeypatch.setattr(sys, "argv", ["bughunt-tracelayer"])
    assert main([]) == 2
    assert "root required" in capsys.readouterr().out


def test_no_trace_dir_is_not_applicable(tmp_path: Path, capsys) -> None:
    from bughunt.tracelayer_adapter import main

    assert main([str(tmp_path)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["not_applicable"] is True


def test_verify_clean_on_real_repo(capsys) -> None:
    from bughunt.tracelayer_adapter import main, verify

    root = Path(__file__).resolve().parent.parent
    assert verify(root) == []
    assert main([str(root)]) in (0, 1)
    payload = json.loads(capsys.readouterr().out)
    assert "findings" in payload


def test_health_counters(monkeypatch, tmp_path: Path) -> None:
    from bughunt import tracelayer_adapter

    _ = (tmp_path / ".trace").mkdir()
    monkeypatch.setattr(tracelayer_adapter, "_cli", lambda: "/bin/trace")
    monkeypatch.setattr(
        tracelayer_adapter,
        "_run",
        lambda *a, **k: (0, '{"broken_refs": 0, "blocking_stale": 0}', ""),
    )
    assert tracelayer_adapter.health(tmp_path) == []


def test_failing_verify_becomes_findings(monkeypatch, tmp_path: Path) -> None:
    from bughunt import tracelayer_adapter

    _ = (tmp_path / ".trace").mkdir()
    monkeypatch.setattr(tracelayer_adapter, "_cli", lambda: "/bin/trace")
    monkeypatch.setattr(
        tracelayer_adapter,
        "_run",
        lambda *a, **k: (
            1,
            json.dumps(
                {
                    "diagnostics": [
                        {
                            "rule": "TL012",
                            "severity": "error",
                            "message": "untraced",
                            "path": "a.py",
                            "line": 3,
                            "trace_id": "T1",
                        },
                        "junk",
                    ]
                }
            ),
            "",
        ),
    )
    findings = tracelayer_adapter.verify(tmp_path)
    assert len(findings) == 1
    item = findings[0]
    assert item["code"] == "trace:TL012"
    assert "T1" in str(item["message"])
    assert item["path"] == "a.py"


def test_broken_refs_are_error_findings(monkeypatch, tmp_path: Path) -> None:
    from bughunt import tracelayer_adapter

    _ = (tmp_path / ".trace").mkdir()
    monkeypatch.setattr(tracelayer_adapter, "_cli", lambda: "/bin/trace")
    monkeypatch.setattr(
        tracelayer_adapter,
        "_run",
        lambda *a, **k: (0, '{"broken_refs": 2, "blocking_stale": 1}', ""),
    )
    findings = tracelayer_adapter.health(tmp_path)
    assert len(findings) == 2
    assert all(item["code"] == "BHVERIFY003" for item in findings)


def test_exec_and_parse_failures(monkeypatch, tmp_path: Path) -> None:
    from bughunt import tracelayer_adapter

    _ = (tmp_path / ".trace").mkdir()
    monkeypatch.setattr(tracelayer_adapter, "_cli", lambda: "/bin/trace")
    monkeypatch.setattr(tracelayer_adapter, "_run", lambda *a, **k: (3, "", "boom"))
    findings = tracelayer_adapter.verify(tmp_path)
    assert findings and findings[0]["code"] == "BHVERIFY002"
    assert tracelayer_adapter.health(tmp_path) == []
    monkeypatch.setattr(tracelayer_adapter, "_run", lambda *a, **k: (0, "not json", ""))
    findings = tracelayer_adapter.verify(tmp_path)
    assert findings and findings[0]["code"] == "BHVERIFY002"
    assert tracelayer_adapter.health(tmp_path) == []


def test_run_oserror_is_structured(monkeypatch, tmp_path: Path) -> None:
    import subprocess

    from bughunt import tracelayer_adapter

    def _boom(*args, **kwargs):
        raise OSError("nope")

    monkeypatch.setattr(subprocess, "run", _boom)
    code, _out, err = tracelayer_adapter._run("/bin/trace", tmp_path, "status")
    assert code == 127
    assert "nope" in err
