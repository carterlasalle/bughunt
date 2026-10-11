# Copyright (c) 2026 Carter LaSalle
from pathlib import Path

from bughunt.cli import Config, Finding, Result, Status, signal_groups, write_reports


def test_signal_groups_repeated_rule() -> None:
    results = [
        Result(
            "ruff",
            "lint",
            Status.FINDINGS,
            findings=[
                Finding(
                    "ruff",
                    "Undefined name `foo`",
                    path="a.py",
                    line=1,
                    code="F821",
                ),
                Finding(
                    "ruff",
                    "Undefined name `bar`",
                    path="b.py",
                    line=9,
                    code="F821",
                ),
            ],
        ),
    ]
    groups = signal_groups(results)
    assert groups[0]["count"] == 2
    assert groups[0]["code"] == "F821"


# trace:v1 id=test.tests-test-reporting.test-agent-report-artifacts work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_agent_report_artifacts(tmp_path: Path) -> None:
    cfg = Config(tmp_path, {"execution": {}})
    result = Result(
        "ruff",
        "lint",
        Status.FINDINGS,
        command=["ruff", "check", "."],
        findings=[
            Finding(
                "ruff",
                "Undefined name `foo`",
                path="src/a.py",
                line=7,
                code="F821",
            ),
        ],
    )
    md, js = write_reports(cfg, [result], "all", 1.2)
    assert md.exists()
    assert js.exists()
    agent = md.parent / "agent"
    assert (agent / "queue.json").exists()
    assert (agent / "FIX_QUEUE.md").exists()
    assert (agent / "AGENT_INSTRUCTIONS.md").exists()
    assert list((agent / "tasks").glob("*.md"))


# trace:v1 id=test.tests-test-reporting.test-report-counts-autofixes work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_report_counts_autofixes(tmp_path: Path) -> None:
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
        ),
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


# trace:v1 id=test.tests-test-reporting.test-installer-failures-reported-as-blind-spots work=WORK-BUG-4ABH9VEY satisfies=REQ-BUG-KZG483AX
def test_installer_failures_reported_as_blind_spots(tmp_path: Path) -> None:
    """A failed engine install is a blind spot, never silent console text.

    Regression for the dropped `pact-python` failure: install outcomes must
    surface as ERROR rows in report.json, the defense table, and
    BLIND_SPOTS.md.
    """
    import json

    from bughunt.installers import InstallResult

    installs = [
        InstallResult(
            "pact-python", "ERROR", ["uv", "add", "--dev", "pact-python"], "boom"
        ),
        InstallResult("ruff", "PASS", [], "already available"),
    ]
    cfg = Config(tmp_path, {"execution": {}})
    md, js = write_reports(cfg, [], "all", 1.0, installs=installs)
    payload = json.loads(js.read_text())
    assert "pact-python" in json.dumps(payload)
    assert payload["summary"]["errors"] == 1
    assert [r["name"] for r in payload["results"]] == ["install:pact-python"]
    assert "install:pact-python" in md.read_text()
    blind = (md.parent / "agent" / "BLIND_SPOTS.md").read_text()
    assert "install:pact-python" in blind
