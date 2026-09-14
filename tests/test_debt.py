# Copyright (c) 2026 Carter LaSalle
"""Accepted-debt ledger: marking, guards, snapshot/review roundtrip."""

from pathlib import Path


def _finding(
    tool: str = "mypy",
    code: str | None = "misc",
    message: str = 'Expression has type "Any"',
):
    from bughunt.cli import Finding

    return Finding(
        tool=tool,
        message=message,
        path="src/pkg/mod.py",
        line=10,
        code=code,
    )


def test_mark_accepted_flags_only_matching_signal_and_path() -> None:
    from bughunt.cli import DebtEntry, Result, Status, mark_accepted

    target = _finding()
    other_signal = _finding(message="Something else entirely")
    other_path = _finding()
    other_path.path = "src/other.py"
    results = [
        Result(
            "mypy",
            "types",
            Status.FINDINGS,
            findings=[target, other_signal, other_path],
        )
    ]
    ledger = [
        DebtEntry(
            signal=target.signal_key,
            paths=["src/pkg/mod.py"],
            count=1,
            reason="test",
        )
    ]
    mark_accepted(results, ledger)
    assert target.accepted is True
    assert other_signal.accepted is False
    assert other_path.accepted is False


def test_consumers_exclude_accepted_findings() -> None:
    from bughunt.cli import (
        DebtEntry,
        Result,
        Status,
        agent_queue,
        hotspot_files,
        mark_accepted,
        signal_groups,
    )

    live = _finding()
    debt = _finding()
    results = [Result("mypy", "types", Status.FINDINGS, findings=[live, debt])]
    mark_accepted(
        results,
        [
            DebtEntry(
                signal=debt.signal_key, paths=["src/pkg/mod.py"], count=1, reason="t"
            )
        ],
    )
    assert debt.signal_key not in {g["key"] for g in signal_groups(results)}
    assert all(p != "src/pkg/mod.py" for p, _ in hotspot_files(results))
    assert all(item["message"] != debt.message for item in agent_queue(results))


def test_malformed_ledger_fails_open(tmp_path: Path, capsys) -> None:
    from bughunt.cli import load_debt_ledger

    (tmp_path / "debt.toml").write_text("[[debt]\nthis is not toml = = =\n")
    assert load_debt_ledger(tmp_path) == []
    assert "warning" in capsys.readouterr().err
    assert load_debt_ledger(tmp_path / "nonexistent") == []


def test_snapshot_review_roundtrip(tmp_path: Path) -> None:
    import json

    from bughunt.cli import debt_review, debt_snapshot

    target = _finding()
    report_dir = tmp_path / ".bughunt" / "reports" / "20240101-000000"
    report_dir.mkdir(parents=True)
    (report_dir / "report.json").write_text(
        json.dumps(
            {
                "results": [
                    {
                        "name": "mypy",
                        "findings": [
                            {
                                "tool": "mypy",
                                "message": target.message,
                                "path": "src/pkg/mod.py",
                                "line": 10,
                                "code": "misc",
                                "severity": "error",
                            }
                        ],
                    }
                ]
            }
        )
    )
    rc = debt_snapshot(tmp_path, [target.signal_key], "test debt")
    assert rc == 0
    assert (tmp_path / "debt.toml").exists()
    assert debt_review(tmp_path) == 0
    report = json.loads((report_dir / "report.json").read_text())
    report["results"][0]["findings"].append(
        {
            "tool": "mypy",
            "message": target.message,
            "path": "src/pkg/mod.py",
            "line": 20,
            "code": "misc",
            "severity": "error",
        }
    )
    (report_dir / "report.json").write_text(json.dumps(report))
    assert debt_review(tmp_path) == 1
