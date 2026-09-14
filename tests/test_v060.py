# Copyright (c) 2026 Carter LaSalle
from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from bughunt.cli import (
    Check,
    Config,
    Finding,
    Result,
    Status,
    build_checks,
    correlated_issue_groups,
    local_schema_pairs,
    logical_issue_groups,
    risk_map,
    run_process,
    type_disagreement_result,
    write_reports,
)
from bughunt.coverage_tools import parse_coverage_json
from bughunt.seam_scan import scan_seams


def _python_repo(root: Path) -> None:
    (root / "src/pkg").mkdir(parents=True)
    (root / "src/pkg/__init__.py").write_text("")
    (root / "tests").mkdir()
    (root / "tests/test_ok.py").write_text("def test_ok() -> None:\n    assert True\n")
    (root / "pyproject.toml").write_text(
        '[project]\nname="pkg"\nversion="0"\nrequires-python=">=3.11"\n',
    )


# trace:v1 id=test.tests-test-v060.test-coverage-parser-reports-line-and-branch-gaps work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_coverage_parser_reports_line_and_branch_gaps(tmp_path: Path) -> None:
    report = tmp_path / "coverage.json"
    report.write_text(
        json.dumps(
            {
                "totals": {
                    "percent_covered": 80,
                    "covered_lines": 8,
                    "missing_lines": 2,
                    "num_branches": 4,
                    "missing_branches": 1,
                },
                "files": {
                    "src/a.py": {"missing_lines": [7, 8], "missing_branches": [[6, 9]]},
                },
            },
        ),
    )
    findings, summary = parse_coverage_json(report)
    assert {f.code for f in findings} == {"BHCOV001", "BHCOV002"}
    assert summary["missing_branches"] == 1


def test_coverage_parser_skips_non_dict_files(tmp_path: Path) -> None:
    import json

    from bughunt.coverage_tools import _ranges, parse_coverage_json

    assert _ranges([]) == []
    assert _ranges([5]) == [(5, 5)]
    assert _ranges([1, 2, 3, 7]) == [(1, 3), (7, 7)]
    report = tmp_path / "coverage.json"
    report.write_text(json.dumps({"files": {"src/a.py": [1, 2]}}))
    findings, _ = parse_coverage_json(report)
    assert findings == []


# trace:v1 id=test.tests-test-v060.test-seam-scanner-finds-producer-consumer-key-drift work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_seam_scanner_finds_producer_consumer_key_drift(tmp_path: Path) -> None:
    _python_repo(tmp_path)
    (tmp_path / "src/pkg/a.py").write_text(
        "def produce() -> dict[str, object]:\n"
        "    return {'name': 'x'}\n\n"
        "def consume() -> object:\n"
        "    payload = produce()\n"
        "    return payload['nmae']\n",
    )
    findings = scan_seams(tmp_path, ["src"], ["tests"])
    assert any(f.code == "BHSEAM003" and "nmae" in f.message for f in findings)


# trace:v1 id=test.tests-test-v060.test-seam-scanner-finds-schema-model-drift work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_seam_scanner_finds_schema_model_drift(tmp_path: Path) -> None:
    _python_repo(tmp_path)
    (tmp_path / "src/pkg/models.py").write_text(
        "class User:\n    id: int\n    name: str\n",
    )
    (tmp_path / "user.schema.json").write_text(
        json.dumps(
            {
                "title": "User",
                "type": "object",
                "properties": {"id": {"type": "integer"}, "email": {"type": "string"}},
            },
        ),
    )
    findings = scan_seams(tmp_path, ["src"], ["tests"])
    assert any(f.code == "BHSEAM004" for f in findings)


# trace:v1 id=test.tests-test-v060.test-local-schema-pairs-refuses-remote-and-resolves-local work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_local_schema_pairs_refuses_remote_and_resolves_local(tmp_path: Path) -> None:
    (tmp_path / "schema.json").write_text('{"type":"object"}')
    (tmp_path / "local.json").write_text('{"$schema":"schema.json","x":1}')
    (tmp_path / "remote.json").write_text(
        '{"$schema":"https://example.com/schema.json","x":1}',
    )
    assert local_schema_pairs(tmp_path, ["local.json", "remote.json"]) == [
        ("local.json", "schema.json"),
    ]


# trace:v1 id=test.tests-test-v060.test-correctness-floors-are-not-omitted-by-old-config work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_correctness_floors_are_not_omitted_by_old_config(tmp_path: Path) -> None:
    cfg = Config(
        tmp_path,
        {
            "profiles": {
                "pr": {"tools": ["pytest"]},
                "deep": {"tools": ["pytest"]},
                "all": {"tools": ["pytest"]},
            },
        },
    )
    assert {"coverage", "seam", "packaging", "runtime-types"} <= set(cfg.tools("pr"))
    assert {"pytest-random", "hypofuzz", "griffe", "type-disagreement"} <= set(
        cfg.tools("deep"),
    )
    assert {"python-matrix", "timezone-matrix", "version-diff", "pynguin"} <= set(
        cfg.tools("all"),
    )


def test_type_disagreement_is_first_class() -> None:
    results = [
        Result(
            "mypy",
            "types",
            Status.FINDINGS,
            findings=[Finding("mypy", "bad", path="a.py", line=4)],
        ),
        Result("basedpyright", "types", Status.PASS),
    ]
    result = type_disagreement_result(results)
    assert result is not None
    assert result.status == Status.FINDINGS
    assert result.findings[0].code == "BHDIS001"


# trace:v1 id=test.tests-test-v060.test-budgeted-search-timeout-is-not-infrastructure-error work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_budgeted_search_timeout_is_not_infrastructure_error(tmp_path: Path) -> None:
    check = Check(
        "budget",
        "fuzz",
        [sys.executable, "-c", "import time; time.sleep(2)"],
        lambda _o, _e, _c: [],
        1,
        tmp_path,
        timeout_is_success=True,
    )
    result = asyncio.run(run_process(check, 10000))
    assert result.status == Status.PASS
    assert "search budget exhausted" in (result.note or "")


# trace:v1 id=test.tests-test-v060.test-main-pytest-seed-is-recorded-not-hard-pinned-zero work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_main_pytest_seed_is_recorded_not_hard_pinned_zero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _python_repo(tmp_path)
    from bughunt import cli

    monkeypatch.setattr(
        cli,
        "executable",
        lambda *names: sys.executable if names and names[0] == "pytest" else None,
    )
    monkeypatch.setattr(
        cli,
        "python_module_available",
        lambda name: name in {"hypothesis", "pytest_timeout", "pytest_randomly"},
    )
    cfg = Config(
        tmp_path,
        {
            "project": {
                "source_paths": ["src"],
                "test_paths": ["tests"],
                "python_paths": ["src", "tests"],
            },
            "profiles": {"deep": {"tools": ["pytest", "pytest-random"]}},
            "tests": {"repro_seed": 17, "timeout_seconds": 30},
        },
    )
    checks, _ = build_checks(cfg, "deep")
    canonical = next(c for c in checks if c.name == "pytest")
    randomized = next(c for c in checks if c.name == "pytest-random")
    assert canonical.env and canonical.env["PYTHONHASHSEED"] == "17"
    assert randomized.env and randomized.env["PYTHONHASHSEED"] != "0"
    assert "--randomly-seed=" in " ".join(randomized.command)


# trace:v1 id=test.tests-test-v060.test-correlations-and-risk-map-preserve-independent-evidence work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_correlations_and_risk_map_preserve_independent_evidence(
    tmp_path: Path,
) -> None:
    results = [
        Result(
            "coverage",
            "coverage/branches",
            Status.FINDINGS,
            findings=[
                Finding("coverage", "branch", path="src/a.py", line=5, code="BHCOV002"),
            ],
        ),
        Result(
            "mypy",
            "types",
            Status.FINDINGS,
            findings=[
                Finding("mypy", "type", path="src/a.py", line=5, code="arg-type"),
            ],
        ),
        Result(
            "ruff",
            "lint",
            Status.FINDINGS,
            findings=[Finding("ruff", "bug", path="src/a.py", line=5, code="B012")],
        ),
    ]
    correlated = correlated_issue_groups(results)
    assert correlated and correlated[0]["tool_count"] == 3
    risks = risk_map(results)
    assert risks[0]["path"] == "src/a.py"
    assert risks[0]["branch_gaps"] == 1
    cfg = Config(tmp_path, {"execution": {}})
    md, _ = write_reports(cfg, results, "all", 1.0)
    agent = md.parent / "agent"
    assert "ci-fix-dont-freeze" in (agent / "AGENT_INSTRUCTIONS.md").read_text()
    assert (agent / "RISK_MAP.md").exists()


# trace:v1 id=test.tests-test-v060.test-managed-mutmut-uses-covered-lines work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_managed_mutmut_uses_covered_lines(tmp_path: Path) -> None:
    from bughunt.configurator import configure_all

    _python_repo(tmp_path)
    configure_all(tmp_path, ["src", "tests"], ["src"], ["tests"])
    text = (tmp_path / "pyproject.toml").read_text()
    assert "mutate_only_covered_lines = true" in text


# trace:v1 id=test.tests-test-v060.test-version-differential-finds-observable-change work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_version_differential_finds_observable_change(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    if shutil.which("git") is None:
        pytest.skip("git unavailable")
    (tmp_path / "src").mkdir()
    file = tmp_path / "src/api.py"
    file.write_text("def score(x: int) -> int:\n    return x + 1\n")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "bughunt@example.invalid"],
        cwd=tmp_path,
        check=True,
    )
    subprocess.run(["git", "config", "user.name", "BugHunt"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=tmp_path, check=True)
    base = subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path,
        text=True,
    ).strip()
    file.write_text("def score(x: int) -> int:\n    return x + 2\n")
    from bughunt.version_diff_runner import main

    assert main([str(tmp_path), base, "src"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"][0]["code"] == "BHDIFF001"


def test_logical_dedup_preserves_raw_evidence() -> None:
    results = [
        Result(
            "mypy",
            "types",
            Status.FINDINGS,
            findings=[
                Finding("mypy", "bad type", path="src/a.py", line=9, code="arg-type"),
            ],
        ),
        Result(
            "basedpyright",
            "types",
            Status.FINDINGS,
            findings=[
                Finding(
                    "basedpyright",
                    "bad type too",
                    path="src/a.py",
                    line=9,
                    code="reportArgumentType",
                ),
            ],
        ),
    ]
    groups = logical_issue_groups(results)
    assert len(groups) == 1
    assert groups[0]["tool_count"] == 2
    assert groups[0]["finding_count"] == 2
    assert len(results[0].findings) + len(results[1].findings) == 2


# trace:v1 id=test.tests-test-v060.test-report-writes-checklist-and-deduplicated-queue work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_report_writes_checklist_and_deduplicated_queue(tmp_path: Path) -> None:
    cfg = Config(tmp_path, {"execution": {}})
    results = [
        Result(
            "mypy",
            "types",
            Status.FINDINGS,
            findings=[Finding("mypy", "bad", path="src/a.py", line=3)],
        ),
        Result(
            "basedpyright",
            "types",
            Status.FINDINGS,
            findings=[Finding("basedpyright", "bad", path="src/a.py", line=3)],
        ),
    ]
    md, _ = write_reports(cfg, results, "pr", 1.0)
    agent = md.parent / "agent"
    assert (agent / "CHECKLIST.md").exists()
    assert (agent / "DEDUPLICATED_QUEUE.md").exists()
    assert "ci-fix-dont-freeze" in (agent / "CHECKLIST.md").read_text()


# trace:v1 id=test.tests-test-v060.test-guarded-generators-do-not-reduce-health work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_guarded_generators_do_not_reduce_health(tmp_path: Path) -> None:
    _python_repo(tmp_path)
    cfg = Config(
        tmp_path,
        {
            "project": {
                "source_paths": ["src"],
                "test_paths": ["tests"],
                "python_paths": ["src", "tests"],
            },
            "profiles": {"all": {"tools": ["ghostwriter", "pynguin"]}},
        },
    )
    _checks, precomputed = build_checks(cfg, "all")
    states = {r.name: r.status for r in precomputed}
    assert states["ghostwriter"] == Status.NA
    assert states["pynguin"] == Status.NA


# trace:v1 id=test.tests-test-v060.test-typescript-eslint-config-is-type-aware work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_typescript_eslint_config_is_type_aware(tmp_path: Path) -> None:
    from bughunt.configurator import configure_all

    (tmp_path / "src").mkdir()
    (tmp_path / "src/app.ts").write_text("export const x: number = 1;\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "package.json").write_text('{"devDependencies":{"typescript":"*"}}')
    (tmp_path / "tsconfig.json").write_text('{"compilerOptions":{"strict":true}}')
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="mixed"\nversion="0"\nrequires-python=">=3.11"\n',
    )
    configure_all(tmp_path, ["src", "tests"], ["src"], ["tests"])
    eslint = (tmp_path / ".bughunt/configs/eslint.config.mjs").read_text()
    assert "typescript-eslint" in eslint
    assert "strictTypeChecked" in eslint
    assert "projectService: true" in eslint


# trace:v1 id=test.tests-test-v060.test-odoo-capability-detected work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_odoo_capability_detected(tmp_path: Path) -> None:
    from bughunt.technology import discover_technologies

    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="odoo-addon"\nversion="0"\ndependencies=["odoo>=18"]\n',
    )
    inventory = discover_technologies(tmp_path, persist=False)
    assert inventory.has("odoo")
