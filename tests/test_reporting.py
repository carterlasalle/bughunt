from pathlib import Path

from bughunt.cli import Config, Finding, Result, Status, signal_groups, write_reports


def test_signal_groups_repeated_rule():
    results = [
        Result(
            "ruff",
            "lint",
            Status.FINDINGS,
            findings=[
                Finding(
                    "ruff", "Undefined name `foo`", path="a.py", line=1, code="F821"
                ),
                Finding(
                    "ruff", "Undefined name `bar`", path="b.py", line=9, code="F821"
                ),
            ],
        )
    ]
    groups = signal_groups(results)
    assert groups[0]["count"] == 2
    assert groups[0]["code"] == "F821"


def test_agent_report_artifacts(tmp_path: Path):
    cfg = Config(tmp_path, {"execution": {}})
    result = Result(
        "ruff",
        "lint",
        Status.FINDINGS,
        command=["ruff", "check", "."],
        findings=[
            Finding(
                "ruff", "Undefined name `foo`", path="src/a.py", line=7, code="F821"
            )
        ],
    )
    md, js = write_reports(cfg, [result], "all", 1.2)
    assert md.exists() and js.exists()
    agent = md.parent / "agent"
    assert (agent / "queue.json").exists()
    assert (agent / "FIX_QUEUE.md").exists()
    assert (agent / "AGENT_INSTRUCTIONS.md").exists()
    assert list((agent / "tasks").glob("*.md"))


def test_report_counts_autofixes(tmp_path: Path):
    from bughunt.cli import autofix_summary

    results = [
        Result(
            "ruff",
            "lint",
            Status.FINDINGS,
            findings=[
                Finding(
                    "ruff",
                    "safe",
                    path="a.py",
                    line=1,
                    code="F401",
                    fixable=True,
                    fix_safety="safe",
                ),
                Finding(
                    "ruff",
                    "unsafe",
                    path="a.py",
                    line=2,
                    code="X",
                    fixable=True,
                    fix_safety="unsafe",
                ),
            ],
        )
    ]
    summary = autofix_summary(results)
    assert summary["total"] == 2
    assert summary["safe"] == 1
    assert summary["unsafe"] == 1
    cfg = Config(tmp_path, {"execution": {}})
    md, _ = write_reports(cfg, results, "all", 1.0)
    agent = md.parent / "agent"
    assert (agent / "AUTOFIX.md").exists()
    assert "2 deterministic auto-fixes" in (agent / "FIX_QUEUE.md").read_text()
