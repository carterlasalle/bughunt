# Copyright (c) 2026 Carter LaSalle
"""BugCorpus adapter: real CLI consumption, N/A semantics, error surfacing."""

import json
from pathlib import Path


def test_main_needs_root(monkeypatch, capsys) -> None:
    import sys

    from bughunt.bugcorpus_adapter import main

    monkeypatch.setattr(sys, "argv", ["bughunt-bugcorpus"])
    assert main([]) == 2
    assert "root required" in capsys.readouterr().out


def test_main_without_corpus_is_not_applicable(tmp_path: Path, capsys) -> None:
    from bughunt.bugcorpus_adapter import main

    assert main([str(tmp_path), "fast"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["not_applicable"] is True


def test_verify_on_real_corpus() -> None:
    from bughunt.bugcorpus_adapter import verify

    root = Path(__file__).resolve().parent.parent
    ok, errors = verify(root)
    assert ok is True
    assert errors == []


def test_scan_normalizes_provenance(monkeypatch, tmp_path: Path) -> None:
    from bughunt import bugcorpus_adapter

    _ = (tmp_path / ".bugcorpus").mkdir()
    monkeypatch.setattr(bugcorpus_adapter, "_cli", lambda: "/bin/bugcorpus")
    monkeypatch.setattr(
        bugcorpus_adapter,
        "_run",
        lambda *a, **k: (
            0,
            json.dumps(
                {
                    "findings": [
                        {
                            "bugcase": "BC-1",
                            "family": "injection",
                            "detector": "D1",
                            "engine": "semgrep",
                            "state": "blocking",
                            "message": "bad",
                            "path": "a.py",
                            "line": 3,
                            "severity": "error",
                        },
                        "junk",
                    ],
                },
            ),
        ),
    )
    findings = bugcorpus_adapter.scan(tmp_path, "pr")
    assert len(findings) == 1
    item = findings[0]
    assert item["code"] == "D1"
    assert "injection/D1/semgrep/blocking" in str(item["message"])
    assert "BC-1" in str(item["message"])


def test_missing_cli_is_error_not_clean(monkeypatch, tmp_path: Path) -> None:
    from bughunt import bugcorpus_adapter

    _ = (tmp_path / ".bugcorpus").mkdir()
    monkeypatch.setattr(bugcorpus_adapter, "_cli", lambda: None)
    ok, errors = bugcorpus_adapter.verify(tmp_path)
    assert ok is False
    assert errors
    assert errors[0]["code"] == "BHBUGC001"
    assert bugcorpus_adapter.scan(tmp_path, "fast") == []


def test_corrupt_scan_output_is_error(monkeypatch, tmp_path: Path) -> None:
    from bughunt import bugcorpus_adapter

    _ = (tmp_path / ".bugcorpus").mkdir()
    monkeypatch.setattr(bugcorpus_adapter, "_cli", lambda: "/bin/bugcorpus")
    monkeypatch.setattr(bugcorpus_adapter, "_run", lambda *a, **k: (0, "not json"))
    findings = bugcorpus_adapter.scan(tmp_path, "fast")
    assert findings
    assert findings[0]["code"] == "BHBUGC001"


def test_main_end_to_end_on_real_corpus(capsys) -> None:
    from bughunt.bugcorpus_adapter import main

    root = Path(__file__).resolve().parent.parent
    assert main([str(root), "fast"]) in (0, 1)
    payload = json.loads(capsys.readouterr().out)
    assert "findings" in payload


def test_run_oserror_is_structured(monkeypatch, tmp_path: Path) -> None:
    import subprocess

    from bughunt import bugcorpus_adapter

    def _boom(*args, **kwargs):
        raise OSError("nope")

    monkeypatch.setattr(subprocess, "run", _boom)
    code, payload = bugcorpus_adapter._run("/bin/bugcorpus", tmp_path, "verify")
    assert code == 127
    assert "nope" in payload


def test_verify_unparseable_and_failing(monkeypatch, tmp_path: Path) -> None:
    from bughunt import bugcorpus_adapter

    _ = (tmp_path / ".bugcorpus").mkdir()
    monkeypatch.setattr(bugcorpus_adapter, "_cli", lambda: "/bin/bugcorpus")
    monkeypatch.setattr(bugcorpus_adapter, "_run", lambda *a, **k: (0, "not json"))
    ok, errors = bugcorpus_adapter.verify(tmp_path)
    assert ok is False
    assert errors and errors[0]["code"] == "BHBUGC001"
    monkeypatch.setattr(
        bugcorpus_adapter,
        "_run",
        lambda *a, **k: (
            1,
            '{"ok": false, "detectors": [{"id": "D", "status": "failed"}]}',
        ),
    )
    ok, errors = bugcorpus_adapter.verify(tmp_path)
    assert ok is False
    assert any("D" in str(item["message"]) for item in errors)


def test_scan_failure_without_findings(monkeypatch, tmp_path: Path) -> None:
    from bughunt import bugcorpus_adapter

    _ = (tmp_path / ".bugcorpus").mkdir()
    monkeypatch.setattr(bugcorpus_adapter, "_cli", lambda: "/bin/bugcorpus")
    monkeypatch.setattr(
        bugcorpus_adapter, "_run", lambda *a, **k: (1, '{"findings": []}')
    )
    findings = bugcorpus_adapter.scan(tmp_path, "fast")
    assert findings and findings[0]["code"] == "BHBUGC001"
