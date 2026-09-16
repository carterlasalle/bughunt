# Copyright (c) 2026 Carter LaSalle
from __future__ import annotations

import argparse
import asyncio
import dataclasses
import datetime as dt
import hashlib
import json
import os
import re
import secrets as secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections import Counter
from collections.abc import Sequence
from functools import partial as partial
from pathlib import Path
from typing import Any

from rich import box
from rich.live import Live
from rich.markup import escape
from rich.panel import Panel
from rich.progress_bar import ProgressBar
from rich.table import Table
from rich.text import Text

from bughunt.default_rules import DEFAULT_RULES

from . import __version__
from .configurator import JS_TOOL_IGNORES as JS_TOOL_IGNORES
from .configurator import configure_all, configure_custom_checks
from .models import Result as Result, Status as Status
from .models import Check as Check, DebtEntry as DebtEntry, Finding as Finding
from .debt import (
    debt_report as debt_report,
    debt_review as debt_review,
    debt_snapshot as debt_snapshot,
    load_debt_ledger as load_debt_ledger,
    mark_accepted as mark_accepted,
)
from .config import CACHE_DIR, REPORT_DIR, Config as Config, load_config as load_config
from .checkctx import CheckBuildCx
from .doctor_engines import _doctor_engine_rows, _doctor_guarded_rows
from .doctor_tables import _doctor_capability_rows, _doctor_coverage_rows
from .checks_python import _build_python_checks
from .checks_quality import _build_quality_checks
from .checks_structural import _build_structural_checks
from .checks_runtime import _build_runtime_checks
from .checks_matrices import _build_matrix_checks
from .checks_native_a import _build_native_a_checks
from .checks_native_b import _build_native_b_checks
from .probes import _optional_cmd as _optional_cmd
from .probes import _publishable_package_json as _publishable_package_json
from .probes import _pylint_disables as _pylint_disables
from .probes import _supports_flag as _supports_flag
from .probes import analysis_scope as analysis_scope
from .probes import ast_grep_executable as ast_grep_executable
from .probes import atheris_available as atheris_available
from .probes import executable as executable
from .probes import existing_paths as existing_paths
from .probes import generated_config as generated_config
from .probes import import_linter_configured as import_linter_configured
from .probes import local_schema_pairs as local_schema_pairs
from .probes import pact_json_files as pact_json_files
from .probes import python_module_available as python_module_available
from .probes import python_package_names as python_package_names
from .probes import pysa_executable as pysa_executable
from .parsers import ESLINT_EMPTY_SCOPE as ESLINT_EMPTY_SCOPE
from .parsers import OXLINT_EMPTY_SCOPE as OXLINT_EMPTY_SCOPE
from .parsers import parse_actionlint as parse_actionlint
from .parsers import parse_ast_grep as parse_ast_grep
from .parsers import parse_bandit as parse_bandit
from .parsers import parse_basedpyright as parse_basedpyright
from .parsers import parse_buf_json_lines as parse_buf_json_lines
from .parsers import parse_bughunt_helper as parse_bughunt_helper
from .parsers import parse_clippy as parse_clippy
from .parsers import parse_complexipy as parse_complexipy
from .parsers import parse_cppcheck as parse_cppcheck
from .parsers import parse_deal as parse_deal
from .parsers import parse_deptry as parse_deptry
from .parsers import parse_eslint as parse_eslint
from .parsers import parse_golangci as parse_golangci
from .parsers import parse_hadolint as parse_hadolint
from .parsers import parse_json_list
from .parsers import parse_lizard as parse_lizard
from .parsers import parse_oxlint as parse_oxlint
from .parsers import parse_phpstan as parse_phpstan
from .parsers import parse_pylint as parse_pylint
from .parsers import parse_pyrefly as parse_pyrefly
from .parsers import parse_radon_mi as parse_radon_mi
from .parsers import parse_ruff as parse_ruff
from .parsers import parse_sarif
from .parsers import parse_semgrep as parse_semgrep
from .parsers import parse_shellcheck as parse_shellcheck
from .parsers import parse_sqlfluff as parse_sqlfluff
from .parsers import parse_squawk as parse_squawk
from .parsers import parse_tflint as parse_tflint
from .parsers import text_findings as text_findings
from .discovery import discover_all, load_generated_targets
from .installers import install_all
from .technology import (
    ENGINE_CAPABILITY,
    ENGINE_CATEGORY,
    discover_technologies,
    git_path_exists as git_path_exists,
    load_technology_inventory,
    project_executable as project_executable,
    target_executable,
    target_has_module,
    target_python,
    TECH_DEEP_TOOLS as TECH_DEEP_TOOLS,
    TECH_PR_TOOLS as TECH_PR_TOOLS,
)
from .ui import console as console

# These defenses operate specifically on Python source or Python's runtime/test
# ecosystem. They are N/A in repositories where no first-party Python capability
# exists; N/A never lowers defense health. Lizard and Semgrep are intentionally
# excluded because they can analyze multiple languages, while Schemathesis can
# exercise an OpenAPI contract independently of the implementation language.


# trace:v1 id=impl.src-bughunt-cli.type-disagreement-result work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def type_disagreement_result(results: list[Result]) -> Result | None:
    """Make cross-checker disagreement a first-class, deduplicated signal."""
    checker_names = {"mypy", "basedpyright", "pyrefly", "ty"}
    by_location: dict[tuple[str, int], dict[str, list[Finding]]] = {}
    present = {
        r.name
        for r in results
        if r.name in checker_names
        and r.status not in {Status.SKIPPED, Status.NA, Status.ERROR}
    }
    if len(present) < 2:
        return None
    for result in results:
        if result.name not in checker_names:
            continue
        for f in result.findings:
            if f.accepted:
                continue
            if f.path and f.line:
                by_location.setdefault((f.path, f.line), {}).setdefault(
                    result.name,
                    [],
                ).append(f)
    findings: list[Finding] = []
    for (path, line), tools in by_location.items():
        reporters = set(tools)
        if not reporters or reporters == present:
            continue
        silent = sorted(present - reporters)
        loud = sorted(reporters)
        findings.append(
            Finding(
                tool="type-disagreement",
                code="BHDIS001",
                path=path,
                line=line,
                severity="warning",
                message=(
                    f"type-checker disagreement: {', '.join(loud)} reports a problem "
                    f"here while {', '.join(silent)} does not; inspect erased/dynamic "
                    "typing at this seam"
                ),
            ),
        )
    if not findings:
        return Result(
            "type-disagreement",
            "cross-tool-correlation",
            Status.PASS,
            note="type checkers agreed on diagnostic locations",
        )
    return Result(
        "type-disagreement",
        "cross-tool-correlation",
        Status.FINDINGS,
        findings=findings,
        note=f"{len(findings)} disagreement location(s)",
    )


# trace:v1 id=impl.src-bughunt-cli.correlated-issue-groups work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def correlated_issue_groups(results: list[Result]) -> list[dict[str, Any]]:
    """Correlate independent tools per source location; keep raw evidence."""
    buckets: dict[tuple[str, int], list[Finding]] = {}
    for r in results:
        for f in r.findings:
            if f.accepted:
                continue
            if f.path and f.line:
                buckets.setdefault((f.path, f.line), []).append(f)
    out: list[dict[str, Any]] = []
    for (path, line), findings in buckets.items():
        tools = sorted({f.tool for f in findings})
        if len(tools) < 2:
            continue
        out.append(
            {
                "path": path,
                "line": line,
                "tools": tools,
                "tool_count": len(tools),
                "finding_count": len(findings),
                "codes": sorted({str(f.code) for f in findings if f.code}),
                "severity": min((f.severity for f in findings), key=severity_priority),
            },
        )
    return sorted(
        out,
        key=lambda x: (
            -int(x["tool_count"]),
            -int(x["finding_count"]),
            str(x["path"]),
            int(x["line"]),
        ),
    )


# trace:v1 id=impl.src-bughunt-cli.logical-issue-groups work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def logical_issue_groups(results: list[Result]) -> list[dict[str, Any]]:
    """Build a non-destructive logical dedup view.

    Raw analyzer findings remain untouched. Findings at the same source location
    and ODC class are grouped into one logical issue so agents can fix the seam/
    statement once while preserving every independent analyzer as evidence.
    Findings without a stable location retain their own fingerprint-backed group.
    """
    buckets: dict[tuple[str, int, str], list[tuple[Result, Finding]]] = {}
    for result in results:
        for finding in result.findings:
            if finding.accepted:
                continue
            if finding.path and finding.line:
                key = (
                    finding.path,
                    int(finding.line),
                    odc_class(result.category, finding),
                )
            else:
                key = (
                    f"<unlocated:{finding.fingerprint}>",
                    0,
                    odc_class(result.category, finding),
                )
            buckets.setdefault(key, []).append((result, finding))

    groups: list[dict[str, Any]] = []
    for (path, line, defect_class), items in buckets.items():
        findings = [item[1] for item in items]
        tools = sorted({f.tool for f in findings})
        primary = min(
            findings,
            key=lambda f: (
                severity_priority(f.severity),
                0 if f.code and str(f.code).startswith("BH") else 1,
                f.tool,
            ),
        )
        groups.append(
            {
                "id": "LOG-"
                + hashlib.sha256(f"{path}|{line}|{defect_class}".encode())
                .hexdigest()[:12]
                .upper(),
                "path": None if path.startswith("<unlocated:") else path,
                "line": line or None,
                "odc_class": defect_class,
                "finding_count": len(findings),
                "tool_count": len(tools),
                "tools": tools,
                "codes": sorted({str(f.code) for f in findings if f.code}),
                "severity": primary.severity,
                "primary_message": primary.message,
                "finding_ids": [f.finding_id for f in findings],
            },
        )
    return sorted(
        groups,
        key=lambda g: (
            severity_priority(str(g["severity"])),
            -int(g["tool_count"]),
            -int(g["finding_count"]),
            str(g.get("path") or ""),
            int(g.get("line") or 0),
        ),
    )


# trace:v1 id=impl.src-bughunt-cli.odc-class work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def odc_class(category: str, finding: Finding | None = None) -> str:
    text = (category + " " + (finding.code or "") if finding else category).lower()
    if any(
        x in text
        for x in ("seam", "api", "schema", "architecture", "contract", "migration")
    ):
        return "interface"
    if any(x in text for x in ("concurrency", "async", "time", "random", "matrix")):
        return "timing/serialization"
    if any(x in text for x in ("package", "build", "dependency", "ci-")):
        return "build/package/merge"
    if any(x in text for x in ("doc", "doctest")):
        return "documentation"
    if any(x in text for x in ("complexity", "performance", "benchmark", "memory")):
        return "algorithm"
    if any(
        x in text for x in ("type", "coverage", "test", "validation", "lint", "static")
    ):
        return "checking"
    return "function"


# trace:v1 id=impl.src-bughunt-cli.build-checks work=WORK-BUG-4ABH9VEY satisfies=REQ-BUG-KZG483AX implements=PLAN-BUG-560GXA79
def build_checks(
    cfg: Config,
    profile: str,
    *,
    excluded: set[str] | None = None,
) -> tuple[list[Check], list[Result]]:
    root = cfg.root
    timeout = cfg.timeout(profile)
    profile_tools = cfg.tools(profile)
    excluded = set(excluded or ())
    wanted = [name for name in profile_tools if name not in excluded]
    py = analysis_scope(root, cfg.python_paths)
    src = analysis_scope(root, cfg.source_paths)
    tests = analysis_scope(root, cfg.test_paths)
    config_dir = root / ".bughunt" / "configs"
    checks: list[Check] = []
    skipped: list[Result] = []
    generated_targets = load_generated_targets(root)
    technology = load_technology_inventory(root)
    category_by_tool = {
        "codeql": "whole-program",
        "pysa": "taint",
        "mutmut": "mutation",
        "semgrep": "semantic-static",
        "ast-grep": "structural",
        "bandit": "security",
        "atheris": "coverage-fuzz",
        "schemathesis": "api-fuzz",
        "bugcorpus": "historical/custom-static",
        **ENGINE_CATEGORY,
    }
    _target_py = target_python(root)
    pytest = target_executable(root, "pytest")
    hypothesis_plugin = generated_config(root, "hypothesis_plugin.py")
    repro_seed = int(cfg.raw.get("tests", {}).get("repro_seed", 1))
    test_timeout = int(cfg.raw.get("tests", {}).get("timeout_seconds", 300))
    pytest_env = {"HYPOTHESIS_PROFILE": "bughunt", "PYTHONHASHSEED": str(repro_seed)}
    pytest_cmd = (
        [
            pytest,
            "-q",
            "--tb=short",
            "--strict-config",
            "--strict-markers",
            "-o",
            "xfail_strict=true",
        ]
        if pytest
        else None
    )
    if pytest_cmd and target_has_module(_target_py, "pytest_timeout"):
        pytest_cmd += ["--timeout", str(test_timeout)]
    if pytest_cmd and profile in {"deep", "all"}:
        # Resource/deprecation/runtime warnings are often latent bugs. Developer
        # mode also enables faulthandler and extra CPython runtime checks.
        pytest_cmd += ["-W", "error"]
        pytest_env["PYTHONDEVMODE"] = "1"
        pytest_env["PYTHONASYNCIODEBUG"] = "1"
    if pytest_cmd and hypothesis_plugin and target_has_module(_target_py, "hypothesis"):
        pytest_cmd += ["-p", "hypothesis_plugin"]
        pytest_env["PYTHONPATH"] = (
            str(hypothesis_plugin.parent)
            + os.pathsep
            + os.environ.get("PYTHONPATH", "")
        )
    if pytest_cmd:
        pytest_cmd += tests
    cx = CheckBuildCx(
        cfg=cfg,
        profile=profile,
        root=root,
        timeout=timeout,
        wanted=wanted,
        excluded=excluded,
        py=py,
        src=src,
        tests=tests,
        config_dir=config_dir,
        checks=checks,
        skipped=skipped,
        generated_targets=generated_targets,
        technology=technology,
        category_by_tool=category_by_tool,
        _target_py=_target_py,
        pytest=pytest,
        hypothesis_plugin=hypothesis_plugin,
        repro_seed=repro_seed,
        test_timeout=test_timeout,
        pytest_env=pytest_env,
        pytest_cmd=pytest_cmd,
    )
    if not cx.technology.has("python"):
        for name, category in (
            ("codeql", "whole-program"),
            ("pysa", "taint"),
            ("mutmut", "mutation"),
        ):
            if name in cx.wanted:
                cx.skipped.append(
                    Result(
                        name,
                        category,
                        Status.NA,
                        note=(
                            "not applicable: no first-party Python capability detected"
                        ),
                    ),
                )
    cx.skipped.extend(
        Result(
            name=name,
            category=category_by_tool.get(name, "excluded"),
            status=Status.SKIPPED,
            note="explicitly skipped by user",
        )
        for name in sorted(cx.excluded & set(profile_tools))
    )
    _build_python_checks(cx)
    _build_quality_checks(cx)
    _build_structural_checks(cx)
    _build_runtime_checks(cx)
    _build_matrix_checks(cx)
    _build_native_a_checks(cx)
    _build_native_b_checks(cx)
    return cx.checks, cx.skipped


# trace:v1 id=impl.src-bughunt-cli.liverunstate work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
class LiveRunState:
    """Live heartbeat for long scans; state is updated by async check tasks."""

    def __init__(self, total: int) -> None:
        self.total = total
        self.started_at = time.perf_counter()
        self.running: dict[str, dict[str, Any]] = {}
        self.completed: list[Result] = []

    def start(self, check: Check) -> None:
        now = time.perf_counter()
        self.running[check.name] = {
            "category": check.category,
            "started": now,
            "timeout": check.timeout,
            "last_activity": now,
            "last_line": "spawned process",
            "output_lines": 0,
        }

    def activity(self, name: str, line: str) -> None:
        entry = self.running.get(name)
        if not entry:
            return
        cleaned = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", line).strip()
        if not cleaned:
            return
        entry["last_activity"] = time.perf_counter()
        entry["last_line"] = cleaned[-180:]
        entry["output_lines"] = int(entry.get("output_lines", 0)) + 1

    def finish(self, result: Result) -> None:
        _ = self.running.pop(result.name, None)
        if result.name == "codeql":
            _ = self.running.pop("codeql-db", None)
        self.completed.append(result)

    # trace:v1 id=impl.src-bughunt-cli-liverunstate.render work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
    def render(self) -> Table:
        elapsed = time.perf_counter() - self.started_at
        table = Table(
            title=f"[bold bright_cyan]LIVE BUG HUNT[/]  [dim]{elapsed:.1f}s elapsed[/]",
            box=box.ROUNDED,
            expand=True,
        )
        table.add_column("STATE", width=12)
        table.add_column("DEFENSE", min_width=22)
        table.add_column("CLASS", min_width=16)
        table.add_column("ELAPSED", justify="right", width=10)
        table.add_column("ACTIVITY", ratio=3)

        now = time.perf_counter()
        for name, entry in sorted(
            self.running.items(),
            key=lambda kv: float(kv[1]["started"]),
        ):
            age = now - float(entry["started"])
            quiet = now - float(entry["last_activity"])
            timeout = int(entry["timeout"])
            ratio = age / timeout if timeout else 0
            last = escape(str(entry.get("last_line") or ""))
            if ratio >= 0.9:
                state = "[bold red]▶ RUNNING[/]"
                activity = f"[bold red]near timeout[/] • quiet {quiet:.0f}s • {last}"
            elif quiet >= 120:
                state = "[bold yellow]▶ QUIET[/]"
                activity = f"[yellow]no output for {quiet:.0f}s[/] • last: {last}"
            elif quiet >= 30:
                state = "[cyan]▶ RUNNING[/]"
                activity = f"[yellow]quiet {quiet:.0f}s[/] • last: {last}"
            else:
                state = "[bold cyan]▶ RUNNING[/]"
                activity = f"[cyan]● output {quiet:.0f}s ago[/] • {last}"
            table.add_row(state, name, str(entry["category"]), f"{age:.1f}s", activity)

        for result in self.completed[-8:]:
            glyph = {
                Status.PASS: "[green]✓ PASS[/]",
                Status.FINDINGS: "[yellow]◆ FOUND[/]",
                Status.ERROR: "[red]✕ ERROR[/]",
                Status.SKIPPED: "[dim]○ SKIP[/]",
                Status.NA: "[dim cyan]— N/A[/]",
            }[result.status]
            detail = result.note or (
                f"{result.count} finding(s)" if result.count else "complete"
            )
            table.add_row(
                glyph,
                result.name,
                result.category,
                f"{result.duration_s:.1f}s",
                escape(detail[:120]),
            )

        completed = len(self.completed)
        queued = max(0, self.total - completed - len(self.running))
        table.caption = (
            f"completed {completed}/{self.total}  •  running {len(self.running)}  •  "
            f"queued {queued}"
        )
        return table


_STOP_REQUESTED = False
_LIVE_PROCS: set[asyncio.subprocess.Process] = set()


# trace:v1 id=impl.src-bughunt-cli.stop-requested work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _stop_requested() -> bool:
    """True after the first SIGINT; new work must not start."""
    return _STOP_REQUESTED


# trace:v1 id=impl.src-bughunt-cli.-handle-sigint work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _handle_sigint(signum: int, frame: object) -> None:
    """First Ctrl-C stops gracefully; a second one aborts immediately."""
    global _STOP_REQUESTED
    _ = (signum, frame)
    if _STOP_REQUESTED:
        for proc in list(_LIVE_PROCS):
            try:
                proc.kill()
            except (OSError, ProcessLookupError):
                continue
        raise SystemExit(130)
    _STOP_REQUESTED = True
    for proc in list(_LIVE_PROCS):
        try:
            proc.terminate()
        except (OSError, ProcessLookupError):
            continue
    console.print(
        "[yellow]Interrupted — finishing current checks and writing the "
        "partial report (press Ctrl-C again to abort immediately).[/]"
    )


# trace:v1 id=impl.src-bughunt-cli.-interrupted-result work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _interrupted_result(name: str, category: str) -> Result:
    """Synthetic ERROR result so partial reports read INCOMPLETE."""
    return Result(
        name,
        category,
        Status.ERROR,
        note="interrupted by user (SIGINT); partial output preserved",
    )


# trace:v1 id=impl.src-bughunt-cli.run-process work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
async def run_process(
    check: Check,
    raw_limit: int,
    progress: LiveRunState | None = None,
) -> Result:
    started = time.perf_counter()

    def finish(result: Result) -> Result:
        if progress:
            _ = progress.running.pop(check.name, None)
            if check.record_progress:
                progress.finish(result)
        return result

    if _stop_requested():
        return finish(_interrupted_result(check.name, check.category))
    if progress:
        progress.start(check)

    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []

    # trace:v1 id=impl.src-bughunt-cli-run-process.drain work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
    async def drain(stream: asyncio.StreamReader | None, chunks: list[bytes]) -> None:
        if stream is None:
            return
        # Never use readline() here. Several analyzers emit giant single-line JSON
        # payloads; asyncio's StreamReader has a separator limit and used to crash
        # BugHunt itself with LimitOverrunError. Fixed-size reads have no line limit.
        activity_tail = ""
        while True:
            chunk = await stream.read(64 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
            if progress:
                text = activity_tail + chunk.decode(errors="replace")
                parts = text.splitlines()
                if text and not text.endswith(("\n", "\r")):
                    activity_tail = parts.pop()[-300:] if parts else text[-300:]
                else:
                    activity_tail = ""
                meaningful = next(
                    (line.strip() for line in reversed(parts) if line.strip()),
                    "",
                )
                if not meaningful and activity_tail.strip():
                    meaningful = activity_tail.strip()
                if meaningful:
                    progress.activity(check.name, meaningful[-500:])
        if progress and activity_tail.strip():
            progress.activity(check.name, activity_tail.strip()[-500:])

    try:
        child_env = {**os.environ, **(check.env or {})}
        for name in check.env_scrub:
            _ = child_env.pop(name, None)
        proc = await asyncio.create_subprocess_exec(
            *check.command,
            cwd=str(check.cwd),
            env=child_env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _LIVE_PROCS.add(proc)
        out_task = asyncio.create_task(drain(proc.stdout, stdout_chunks))
        err_task = asyncio.create_task(drain(proc.stderr, stderr_chunks))
        try:
            await asyncio.wait_for(proc.wait(), timeout=check.timeout)
            # Drains normally end at EOF once the child exits, but a leaked
            # pipe writer (double-forked grandchild, inherited fd) holds EOF
            # open forever. Cap the wait, cancel, and keep chunks collected
            # so far: one stuck defense must never wedge the whole scan.
            # Receipt: skipmutmut self-scan wedged with zero CPU, no children.
            try:
                await asyncio.wait_for(asyncio.gather(out_task, err_task), 30)
            except TimeoutError:
                for pending in (out_task, err_task):
                    pending.cancel()
                await asyncio.gather(out_task, err_task, return_exceptions=True)
            _LIVE_PROCS.discard(proc)
        except (TimeoutError, asyncio.CancelledError):
            proc.kill()
            try:
                await asyncio.wait_for(proc.wait(), 30)
            except TimeoutError:
                pass  # kernel did not reap after SIGKILL; proceed regardless
            for pending in (out_task, err_task):
                pending.cancel()
            await asyncio.gather(out_task, err_task, return_exceptions=True)
            _LIVE_PROCS.discard(proc)
            if _stop_requested():
                return finish(_interrupted_result(check.name, check.category))
            stdout = b"".join(stdout_chunks).decode(errors="replace")
            stderr = b"".join(stderr_chunks).decode(errors="replace")
            timeout_findings: list[Finding] = []
            try:
                timeout_findings = check.parser(stdout, stderr, 0)
            except Exception:  # noqa: BLE001 - parser isolation: a parser crash must not kill the runner
                timeout_findings = []
            status = (
                (Status.FINDINGS if timeout_findings else Status.PASS)
                if check.timeout_is_success
                else Status.ERROR
            )
            note = (
                f"search budget exhausted after {check.timeout}s"
                if check.timeout_is_success
                else f"timed out after {check.timeout}s"
            )
            return finish(
                Result(
                    name=check.name,
                    category=check.category,
                    status=status,
                    duration_s=time.perf_counter() - started,
                    command=check.command,
                    stdout=stdout[-raw_limit:],
                    stderr=stderr[-raw_limit:],
                    findings=timeout_findings,
                    note=note,
                ),
            )
    except (FileNotFoundError, PermissionError, OSError) as exc:
        return finish(
            Result(
                name=check.name,
                category=check.category,
                status=Status.ERROR,
                duration_s=time.perf_counter() - started,
                command=check.command,
                note=f"could not execute: {exc}",
            ),
        )

    stdout = b"".join(stdout_chunks).decode(errors="replace")
    stderr = b"".join(stderr_chunks).decode(errors="replace")
    exit_code = int(proc.returncode or 0)
    findings: list[Finding] = []
    parse_error: str | None = None
    try:
        findings = check.parser(stdout, stderr, exit_code)
    except Exception as exc:  # noqa: BLE001 - parser isolation: failure is recorded in the result note
        parse_error = f"output parser failed: {type(exc).__name__}: {exc}"

    if parse_error:
        status = Status.ERROR
    elif not findings and any(
        m in stdout or m in stderr for m in check.empty_scope_markers
    ):
        status = Status.SKIPPED
        parse_error = f"exited {exit_code}: nothing in scope"
    elif exit_code == 0:
        status = Status.FINDINGS if findings else Status.PASS
    elif exit_code in check.findings_exit_codes:
        status = Status.FINDINGS
        if not findings:
            findings = [
                Finding(
                    tool=check.name,
                    message=f"{check.name} exited {exit_code} with findings",
                ),
            ]
    elif exit_code in check.skip_exit_codes:
        status = Status.SKIPPED
        parse_error = f"exited {exit_code}: nothing collected"
    else:
        status = Status.ERROR

    return finish(
        Result(
            name=check.name,
            category=check.category,
            status=status,
            duration_s=time.perf_counter() - started,
            exit_code=exit_code,
            findings=findings,
            command=check.command,
            stdout=stdout[-raw_limit:],
            stderr=stderr[-raw_limit:],
            note=parse_error,
        ),
    )


# trace:v1 id=impl.src-bughunt-cli.run-parallel work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
async def run_parallel(
    checks: list[Check],
    max_parallel: int,
    raw_limit: int,
    progress: LiveRunState | None = None,
) -> list[Result]:
    sem = asyncio.Semaphore(max_parallel)

    # trace:v1 id=impl.src-bughunt-cli-run-parallel.one work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    async def one(check: Check) -> Result:
        async with sem:
            if _stop_requested():
                return _interrupted_result(check.name, check.category)
            return await run_process(check, raw_limit, progress)

    return await asyncio.gather(*(one(c) for c in checks))


# trace:v1 id=impl.src-bughunt-cli.reset-tool-dir work=WORK-BUG-4ABH9VEY satisfies=REQ-BUG-KZG483AX implements=PLAN-BUG-560GXA79
def _reset_tool_dir(path: Path) -> None:
    """Best-effort writable recursive delete for tool output trees.

    Analyzer database directories routinely contain read-only files that make
    the tool's own overwrite/delete step fail (observed: CodeQL
    MultiIOException on the second consecutive scan). Making the tree writable
    first lets our own removal succeed; leftovers are the tool's problem.
    """
    if not path.exists():
        return
    try:
        _ = subprocess.run(  # noqa: S603 - audited: argv list, no shell
            ["chmod", "-R", "u+w", str(path)],  # noqa: S607 - executable resolved via project env/PATH by design, E501
            capture_output=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        # Probe teardown failure is not a finding
        pass
    shutil.rmtree(path, ignore_errors=True)


# trace:v1 id=impl.src-bughunt-cli.run-codeql work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
async def run_codeql(
    cfg: Config,
    profile: str,
    raw_limit: int,
    progress: LiveRunState | None = None,
) -> Result:
    if "codeql" not in cfg.tools(profile):
        return Result("codeql", "whole-program", Status.SKIPPED, note="not in profile")
    ql = executable("codeql")
    if not ql:
        return Result(
            "codeql",
            "whole-program",
            Status.SKIPPED,
            note="codeql CLI not installed",
        )

    language = "python"
    db = cfg.root / CACHE_DIR / "codeql" / language
    sarif = cfg.root / CACHE_DIR / "codeql" / f"{language}.sarif"
    db.parent.mkdir(parents=True, exist_ok=True)
    _reset_tool_dir(db)

    suite = cfg.raw.get("codeql", {}).get(
        "python_suite",
        "codeql/python-queries:codeql-suites/python-security-and-quality.qls",
    )
    started = time.perf_counter()

    source_roots = [cfg.root / p for p in cfg.source_paths if (cfg.root / p).exists()]
    codeql_source_root = (
        source_roots[0]
        if len(source_roots) == 1 and source_roots[0].is_dir()
        else cfg.root
    )

    create = Check(
        "codeql-db",
        "whole-program",
        [
            ql,
            "database",
            "create",
            str(db),
            "--language=python",
            "--source-root",
            str(codeql_source_root),
            "--overwrite",
        ],
        lambda o, e, c: [],
        cfg.timeout(profile),
        cfg.root,
        findings_exit_codes=set(),
        record_progress=False,
    )
    cr = await run_process(create, raw_limit, progress)
    if cr.status == Status.ERROR:
        cr.name = "codeql"
        cr.note = "database creation failed" + (f": {cr.note}" if cr.note else "")
        return cr

    custom_query_dir = cfg.root / ".bughunt" / "configs" / "codeql" / "queries"
    custom_queries = (
        sorted(str(path) for path in custom_query_dir.rglob("*.ql"))
        if custom_query_dir.exists()
        else []
    )
    analyze_targets = [str(suite), *custom_queries]
    analyze = Check(
        "codeql",
        "whole-program",
        [
            ql,
            "database",
            "analyze",
            str(db),
            *analyze_targets,
            "--format=sarif-latest",
            f"--output={sarif}",
            "--download",
        ],
        lambda o, e, c: [],
        cfg.timeout(profile),
        cfg.root,
        findings_exit_codes=set(),
        record_progress=False,
    )
    ar = await run_process(analyze, raw_limit, progress)
    ar.duration_s = time.perf_counter() - started
    ar.artifacts.append(str(sarif))
    if ar.status == Status.ERROR:
        return ar
    ar.findings = parse_sarif(sarif, "codeql")
    ar.status = Status.FINDINGS if ar.findings else Status.PASS
    return ar


# Banner pyre prints when it cannot locate its Pyrefly type-provider binary.
# A missing provider means the defense cannot execute; the runner maps it to
# SKIPPED with the repair stated instead of reporting an analysis ERROR.
PYSA_NO_PROVIDER = "Cannot locate a Pyrefly binary"


# trace:v1 id=impl.src-bughunt-cli.run-pysa work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
async def run_pysa(
    cfg: Config,
    profile: str,
    raw_limit: int,
    progress: LiveRunState | None = None,
) -> Result:
    if "pysa" not in cfg.tools(profile):
        return Result("pysa", "taint", Status.SKIPPED, note="not in profile")
    pyre = pysa_executable(cfg.root)
    if not pyre:
        return Result(
            "pysa",
            "taint",
            Status.SKIPPED,
            note="Pysa/Pyre not installed; run `uv run bughunt install --only pysa`",
        )
    has_config = await asyncio.to_thread((cfg.root / ".pyre_configuration").exists)
    if not has_config:
        return Result(
            "pysa",
            "taint",
            Status.SKIPPED,
            note="no .pyre_configuration / Pysa models configured",
        )

    out_dir = cfg.root / CACHE_DIR / "pysa"
    await asyncio.to_thread(out_dir.mkdir, parents=True, exist_ok=True)
    # pyre-check's historical Click CLI has a known enum-default compatibility
    # failure with newer Click releases. Explicit values protect even fallback
    # project installs; the private runtime additionally pins Click<8.2.
    cmd = [
        pyre,
        "--version=none",
        "--noninteractive",
        "analyze",
        "--version=none",
        "--save-results-to",
        str(out_dir),
    ]

    check = Check(
        "pysa",
        "taint",
        cmd,
        lambda o, e, c: parse_json_list("pysa", o, e, c),
        cfg.timeout(profile),
        cfg.root,
        findings_exit_codes={1},
        record_progress=False,
        env={"PATH": str(Path(pyre).parent) + os.pathsep + os.environ.get("PATH", "")},
    )
    result = await run_process(check, raw_limit, progress)
    result.artifacts.append(str(out_dir))
    if PYSA_NO_PROVIDER in result.stdout + result.stderr:
        result.status = Status.SKIPPED
        result.findings = []
        result.note = (
            "Pyrefly type-provider binary not found by pyre; re-run "
            "`uv run bughunt install --only pysa`"
        )
        return result

    if not result.findings and result.stdout:
        text = result.stdout
        first, last = text.find("["), text.rfind("]")
        if 0 <= first < last:
            try:
                payload = json.loads(text[first : last + 1])
                result.findings = parse_json_list("pysa", json.dumps(payload), "", 0)
                if result.findings:
                    result.status = Status.FINDINGS
            except json.JSONDecodeError:
                # Malformed payload carries no data; skipped
                pass
    return result


# trace:v1 id=impl.src-bughunt-cli.run-mutmut work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
async def run_mutmut(
    cfg: Config,
    profile: str,
    raw_limit: int,
    progress: LiveRunState | None = None,
) -> Result:
    if "mutmut" not in cfg.tools(profile):
        return Result("mutmut", "mutation", Status.SKIPPED, note="not in profile")
    mm = target_executable(cfg.root, "mutmut")
    if not mm:
        return Result("mutmut", "mutation", Status.SKIPPED, note="mutmut not installed")
    if not cfg.raw.get("mutmut", {}).get("enabled", True):
        return Result(
            "mutmut",
            "mutation",
            Status.SKIPPED,
            note="disabled in bughunt.toml",
        )

    run = Check(
        "mutmut",
        "mutation",
        [mm, "run"],
        lambda o, e, c: [],
        cfg.timeout(profile),
        cfg.root,
        findings_exit_codes=set(),
        record_progress=False,
    )
    rr = await run_process(run, raw_limit, progress)
    if rr.status == Status.ERROR:
        return rr

    result_check = Check(
        "mutmut-results",
        "mutation",
        [mm, "results"],
        lambda o, e, c: [],
        120,
        cfg.root,
        findings_exit_codes=set(),
        record_progress=False,
    )
    rs = await run_process(result_check, raw_limit, progress)
    combined = (rs.stdout + "\n" + rs.stderr).strip()
    findings: list[Finding] = []

    # mutmut 3 output includes status groupings; conservatively treat survived
    # and suspicious mutants as findings.
    for line in combined.splitlines():
        low = line.lower()
        if "survived" in low or "suspicious" in low:
            findings.append(
                Finding(tool="mutmut", message=line.strip(), severity="warning"),
            )

    return Result(
        name="mutmut",
        category="mutation",
        status=Status.FINDINGS if findings else Status.PASS,
        duration_s=rr.duration_s + rs.duration_s,
        exit_code=rr.exit_code,
        findings=findings,
        command=rr.command,
        stdout=(rr.stdout + "\n\n--- mutmut results ---\n" + combined)[-raw_limit:],
        stderr=rr.stderr[-raw_limit:],
    )


def status_style(status: Status) -> str:
    return {
        Status.PASS: "bold green",
        Status.FINDINGS: "bold yellow",
        Status.ERROR: "bold red",
        Status.SKIPPED: "dim",
        Status.NA: "dim cyan",
    }[status]


def overall_score(results: list[Result]) -> int:
    applicable = [result for result in results if result.status != Status.NA]
    if not applicable:
        return 100
    # N/A defenses do not count against a repository: Rust tooling is not a
    # blind spot in a Python-only project. Skipped *applicable* defenses are.
    weight = {
        Status.PASS: 1.0,
        Status.FINDINGS: 0.65,
        Status.SKIPPED: 0.20,
        Status.ERROR: 0.0,
    }
    return round(100 * sum(weight[r.status] for r in applicable) / len(applicable))


# trace:v1 id=impl.src-bughunt-cli.canonical-finding-path work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def canonical_finding_path(root: Path, raw: str | None) -> str | None:
    """Canonicalize tool paths so absolute/relative spellings collapse together."""
    if not raw:
        return raw
    value = raw.removeprefix("file://")
    path = Path(value)
    try:
        if path.is_absolute():
            return (
                path.resolve(strict=False)
                .relative_to(root.resolve(strict=False))
                .as_posix()
            )
    except ValueError:
        return path.as_posix()
    normalized = path.as_posix().lstrip("./")
    if (root / normalized).exists():
        return normalized
    # CodeQL databases rooted at `src/` can emit package-relative paths.
    candidate = Path("src") / normalized
    if (root / candidate).exists():
        return candidate.as_posix()
    return normalized


_TRACE_MARKER_LINE = re.compile(r"^\s*(?:#\s*|<!--\s*)trace:(?:v1|exempt)\b")


# trace:v1 id=impl.src-bughunt-cli.finding-on-trace-marker work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _finding_on_trace_marker(
    root: Path,
    finding: Finding,
    cache: dict[str, list[str]],
) -> bool:
    """Return True when a finding points at a TraceLayer marker line.

    Marker lines carry trace identity, never product logic, so no analyzer
    verdict about them is actionable. The scan exempts them centrally here
    instead of scattering per-tool suppressions.
    """
    if not finding.path or not finding.line:
        return False
    lines = cache.get(finding.path)
    if lines is None:
        try:
            lines = (root / finding.path).read_text(errors="replace").splitlines()
        except OSError:
            lines = []
        cache[finding.path] = lines
    if not 1 <= finding.line <= len(lines):
        return False
    return _TRACE_MARKER_LINE.match(lines[finding.line - 1]) is not None


# trace:v1 id=impl.src-bughunt-cli.canonicalize-findings work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def canonicalize_findings(root: Path, results: list[Result]) -> None:
    cache: dict[str, list[str]] = {}
    for result in results:
        kept = []
        for finding in result.findings:
            finding.path = canonical_finding_path(root, finding.path)
            if _finding_on_trace_marker(root, finding, cache):
                continue
            kept.append(finding)
        result.findings = kept


# trace:v1 id=impl.src-bughunt-cli.severity-priority work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def severity_priority(value: str) -> int:
    return {
        "critical": 0,
        "high": 0,
        "error": 0,
        "warning": 1,
        "medium": 1,
        "note": 2,
        "low": 2,
        "info": 3,
    }.get(value.lower(), 1)


# trace:v1 id=impl.src-bughunt-cli.signal-groups work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def signal_groups(results: list[Result]) -> list[dict[str, Any]]:
    grouped: dict[str, list[Finding]] = {}
    for result in results:
        for finding in result.findings:
            if finding.accepted:
                continue
            grouped.setdefault(finding.signal_key, []).append(finding)
    out: list[dict[str, Any]] = []
    for key, findings in grouped.items():
        first = findings[0]
        locations = [f"{f.path}:{f.line or '?'}" for f in findings[:8] if f.path]
        out.append(
            {
                "key": key,
                "count": len(findings),
                "tool": first.tool,
                "code": first.code,
                "message": first.message,
                "severity": first.severity,
                "locations": locations,
                "finding_ids": [f.finding_id for f in findings],
            },
        )
    return sorted(
        out,
        key=lambda g: (
            severity_priority(str(g["severity"])),
            -g["count"],
            g["tool"],
            g.get("code") or g["message"],
        ),
    )


# trace:v1 id=impl.src-bughunt-cli.signal-label work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def signal_label(group: dict[str, Any], max_len: int = 88) -> str:
    base = (
        f"{group['tool']}:{group['code']}" if group.get("code") else str(group["tool"])
    )
    key = str(group.get("key") or base)
    label = key if key != base else base
    return label if len(label) <= max_len else label[: max_len - 1] + "…"


# trace:v1 id=impl.src-bughunt-cli.hotspot-files work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def hotspot_files(results: list[Result]) -> list[tuple[str, int]]:
    counter: Counter[str] = Counter()
    for result in results:
        for finding in result.findings:
            if finding.accepted:
                continue
            if finding.path:
                counter[finding.path] += 1
    return counter.most_common(20)


# trace:v1 id=impl.src-bughunt-cli.autofix-summary work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def autofix_summary(results: list[Result]) -> dict[str, Any]:
    fixable = [
        finding
        for result in results
        for finding in result.findings
        if finding.fixable and not finding.accepted
    ]
    safe = [
        finding for finding in fixable if (finding.fix_safety or "").lower() == "safe"
    ]
    unsafe = [
        finding for finding in fixable if (finding.fix_safety or "").lower() == "unsafe"
    ]
    review = [
        finding for finding in fixable if finding not in safe and finding not in unsafe
    ]
    by_tool = Counter(finding.tool for finding in fixable)
    return {
        "total": len(fixable),
        "safe": len(safe),
        "unsafe": len(unsafe),
        "review": len(review),
        "by_tool": dict(by_tool.most_common()),
        "finding_ids": [finding.finding_id for finding in fixable],
    }


# trace:v1 id=impl.src-bughunt-cli.agent-queue work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def agent_queue(results: list[Result]) -> list[dict[str, Any]]:
    command_by_tool: dict[str, list[str]] = {}
    correlations = correlated_issue_groups(results)
    correlation_ids = {
        (str(g["path"]), int(g["line"])): f"CORR-{i:04d}"
        for i, g in enumerate(correlations, 1)
    }
    for result in results:
        command_by_tool[result.name] = result.command
        _ = command_by_tool.setdefault(result.name.split(":", 1)[0], result.command)
    severity_rank = {
        "error": 0,
        "high": 0,
        "warning": 1,
        "medium": 1,
        "note": 2,
        "low": 2,
    }
    items: list[dict[str, Any]] = []
    for result in results:
        for finding in result.findings:
            if finding.accepted:
                continue
            verify = (
                command_by_tool.get(result.name)
                or command_by_tool.get(finding.tool)
                or []
            )
            items.append(
                {
                    "id": finding.finding_id,
                    "state": "todo",
                    "tool": finding.tool,
                    "result": result.name,
                    "category": result.category,
                    "odc_class": odc_class(result.category, finding),
                    "signal_key": finding.signal_key,
                    "severity": finding.severity,
                    "code": finding.code,
                    "path": finding.path,
                    "line": finding.line,
                    "column": finding.column,
                    "message": finding.message,
                    "fingerprint": finding.fingerprint,
                    "correlation_id": correlation_ids.get(
                        (finding.path or "", finding.line or 0),
                    ),
                    "fixable": finding.fixable,
                    "fix_safety": finding.fix_safety,
                    "fix_preview": finding.fix_preview,
                    "verification_command": verify,
                    "workflow": [
                        "inspect the finding and surrounding code",
                        (
                            "determine whether it is a true defect, "
                            "duplicate, or analyzer false positive"
                        ),
                        "fix the root cause rather than suppressing the symptom",
                        "run verification_command",
                        "run the narrowest relevant tests",
                        (
                            "if this is a real escaped bug, teach "
                            "Bug Corpus the bug family/detector"
                        ),
                    ],
                },
            )
    return sorted(
        items,
        key=lambda x: (
            severity_rank.get(str(x["severity"]).lower(), 1),
            x["path"] or "",
            x["line"] or 0,
            x["tool"],
        ),
    )


# trace:v1 id=impl.src-bughunt-cli.coverage-summary-from-results work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def coverage_summary_from_results(results: list[Result]) -> dict[str, Any]:
    result = next((r for r in results if r.name == "coverage"), None)
    if not result or not result.stdout:
        return {}
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {}
    return (
        dict(payload.get("summary", {}))
        if isinstance(payload, dict) and isinstance(payload.get("summary"), dict)
        else {}
    )


# trace:v1 id=impl.src-bughunt-cli.risk-map work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def risk_map(results: list[Result]) -> list[dict[str, Any]]:
    """Coverage-weighted per-file risk map for agents/V2.

    This is prioritization, not a probability model: uncovered code, branch gaps,
    independent-tool agreement and complexity raise a file's attention score.
    """
    by_file: dict[str, dict[str, Any]] = {}
    sev_weight = {
        "critical": 8,
        "high": 8,
        "error": 6,
        "warning": 3,
        "medium": 3,
        "note": 1,
        "low": 1,
        "info": 1,
    }
    for result in results:
        for f in result.findings:
            if f.accepted:
                continue
            if not f.path:
                continue
            row = by_file.setdefault(
                f.path,
                {
                    "path": f.path,
                    "score": 0,
                    "findings": 0,
                    "tools": set(),
                    "coverage_gaps": 0,
                    "branch_gaps": 0,
                    "complexity_signals": 0,
                    "odc": Counter(),
                },
            )
            row["findings"] += 1
            row["tools"].add(f.tool)
            row["score"] += sev_weight.get(f.severity.lower(), 3)
            row["odc"][odc_class(result.category, f)] += 1
            if f.code == "BHCOV001":
                row["coverage_gaps"] += 1
                row["score"] += 12
            elif f.code == "BHCOV002":
                row["branch_gaps"] += 1
                row["score"] += 16
            if "complex" in result.category or str(f.code or "").startswith("BHCX"):
                row["complexity_signals"] += 1
                row["score"] += 5
    out: list[dict[str, Any]] = []
    for row in by_file.values():
        diversity = len(row["tools"])
        row["score"] += max(0, diversity - 1) * 8
        row["tools"] = sorted(row["tools"])
        row["tool_count"] = diversity
        row["odc"] = dict(row["odc"].most_common())
        out.append(row)
    return sorted(
        out,
        key=lambda x: (-int(x["score"]), -int(x["tool_count"]), str(x["path"])),
    )


# trace:v1 id=impl.src-bughunt-cli.render-terminal work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def render_terminal(
    results: list[Result],
    profile: str,
    elapsed: float,
    report_md: Path,
    report_json: Path,
) -> None:
    counts = Counter(r.status for r in results)
    findings_total = sum(r.count for r in results)
    score = overall_score(results)
    groups = signal_groups(results)
    hotspots = hotspot_files(results)
    fixes = autofix_summary(results)
    correlations = correlated_issue_groups(results)
    logical = logical_issue_groups(results)
    coverage_summary = coverage_summary_from_results(results)

    title = Text()
    _ = title.append("◈ ", style="bold bright_cyan")
    _ = title.append("ZERO-BUG HUNT", style="bold white")
    _ = title.append("  //  ", style="dim")
    _ = title.append(profile.upper(), style="bold bright_magenta")

    subtitle = (
        f"[bold]{len(results)}[/] defenses  •  "
        f"[green]{counts[Status.PASS]} passed[/]  •  "
        f"[yellow]{counts[Status.FINDINGS]} with findings[/]  •  "
        f"[red]{counts[Status.ERROR]} failed[/]  •  "
        f"[dim]{counts[Status.SKIPPED]} unavailable[/]  •  "
        f"[cyan]{counts[Status.NA]} not applicable[/]\n"
        f"[bold]{findings_total}[/] raw normalized findings  •  "
        f"[bold]{len(logical)}[/] logical issue clusters  •  "
        f"[bold]{len(groups)}[/] distinct signals  •  "
        f"[bold]{len(correlations)}[/] cross-tool correlated locations  •  "
        f"{elapsed:.1f}s\n"
        f"[bold green]{fixes['safe']} safe auto-fixable[/]  •  "
        f"[yellow]{fixes['unsafe'] + fixes['review']} review/unsafe "
        "auto-fixable[/]  •  "
        f"[bold]{fixes['total']} total deterministic fixes[/]"
        + (
            f" [dim]({fixes['total'] / findings_total * 100:.1f}% of findings)[/]"
            if findings_total
            else ""
        )
        + (
            f"\n[bold]Coverage[/] "
            f"{float(coverage_summary.get('percent_covered', 0.0)):.1f}%"
            f"  •  {coverage_summary.get('missing_lines', '?')} missing lines"
            f"  •  {coverage_summary.get('missing_branches', '?')} missing branch edges"
            if coverage_summary.get("percent_covered") is not None
            else ""
        )
    )
    console.print()
    console.print(
        Panel(subtitle, title=title, border_style="bright_cyan", padding=(1, 2)),
    )

    bar = ProgressBar(total=100, completed=score, width=60)
    health = Table.grid(expand=True)
    health.add_column(ratio=1)
    health.add_column(justify="right")
    health.add_row(
        Text("DEFENSE HEALTH", style="bold"),
        Text(f"{score}/100", style="bold bright_cyan"),
    )
    health.add_row(
        bar,
        Text("execution coverage, not bug-free probability", style="dim italic"),
    )
    console.print(Panel(health, border_style="blue"))

    table = Table(
        title="Defense Rings",
        box=box.ROUNDED,
        header_style="bold bright_cyan",
        expand=True,
    )
    table.add_column("STATUS", width=11)
    table.add_column("DEFENSE", min_width=16)
    table.add_column("CLASS", min_width=14)
    table.add_column("HITS", justify="right", width=7)
    table.add_column("FIX", justify="right", width=7)
    table.add_column("TIME", justify="right", width=9)
    table.add_column("NOTE", ratio=2)
    order = {
        Status.ERROR: 0,
        Status.FINDINGS: 1,
        Status.PASS: 2,
        Status.SKIPPED: 3,
        Status.NA: 4,
    }
    for r in sorted(results, key=lambda x: (order[x.status], x.category, x.name)):
        glyph = {
            Status.PASS: "✓ PASS",
            Status.FINDINGS: "◆ FOUND",
            Status.ERROR: "✕ ERROR",
            Status.SKIPPED: "○ SKIP",
            Status.NA: "— N/A",
        }[r.status]
        note = r.note or ""
        if r.status == Status.FINDINGS and r.findings:
            first = r.findings[0]
            where = (
                f"{first.path}:{first.line}"
                if first.path and first.line
                else (first.path or "")
            )
            note = f"{where} {first.message}".strip()
            if len(note) > 96:
                note = note[:93] + "..."
        fix_count = sum(
            1 for finding in r.findings if finding.fixable and not finding.accepted
        )
        table.add_row(
            Text(glyph, style=status_style(r.status)),
            r.name,
            r.category,
            str(r.count) if r.count else "—",
            str(fix_count) if fix_count else "—",
            f"{r.duration_s:.1f}s" if r.duration_s else "—",
            Text(
                note,
                style="dim" if r.status in {Status.SKIPPED, Status.NA} else "none",
            ),
        )
    console.print(table)

    if fixes["total"]:
        tool_bits = "  •  ".join(
            f"{count}× {tool}" for tool, count in list(fixes["by_tool"].items())[:6]
        )
        fix_text = (
            f"[bold green]{fixes['safe']} safe[/] can be applied by deterministic "
            "tool fixes  •  "
            f"[yellow]{fixes['unsafe']} unsafe[/]  •  [yellow]{fixes['review']} "
            "rule/review[/]\n"
            f"[dim]{tool_bits}[/]"
        )
        console.print(
            Panel(
                fix_text,
                title="[bold]Auto-fix Availability[/]",
                border_style="green",
            ),
        )

    if groups:
        freq = Table(
            title="Top Bug Signals (severity, then frequency)",
            box=box.SIMPLE_HEAVY,
            expand=True,
        )
        freq.add_column("COUNT", justify="right", style="bold yellow", width=7)
        freq.add_column("SIGNAL", min_width=28)
        freq.add_column("EXAMPLE", ratio=2)
        for g in groups[:10]:
            label = signal_label(g)
            example = g["message"]
            if g["locations"]:
                example += f"  [dim]({g['locations'][0]})[/]"
            freq.add_row(f"×{g['count']}", label, example[:160])
        console.print(freq)
        low = sorted(
            (g for g in groups if severity_priority(str(g["severity"])) >= 2),
            key=lambda g: (-g["count"], g["tool"]),
        )[:5]
        if low:
            noise = Table(
                title="Most Frequent Low-Priority / Style Diagnostics",
                box=box.SIMPLE,
                expand=True,
            )
            noise.add_column("COUNT", justify="right", width=7)
            noise.add_column("SIGNAL", min_width=28)
            noise.add_column("EXAMPLE", ratio=2)
            for g in low:
                label = signal_label(g)
                noise.add_row(f"×{g['count']}", label, str(g["message"])[:140])
            console.print(noise)

    if hotspots:
        hot = "  •  ".join(f"[bold]{count}×[/] {path}" for path, count in hotspots[:5])
        console.print(Panel(hot, title="[bold]Hot Files[/]", border_style="yellow"))

    failures = [r for r in results if r.status == Status.ERROR]
    if failures:
        errors = Table(title="Execution Failures", box=box.SIMPLE_HEAVY, expand=True)
        errors.add_column("DEFENSE")
        errors.add_column("DETAIL")
        for r in failures[:10]:
            errors.add_row(
                f"[red]{r.name}[/]",
                r.note
                or (
                    r.stderr.strip().splitlines()[-1]
                    if r.stderr.strip()
                    else "tool failed"
                ),
            )
        console.print(errors)
        console.print(
            "[yellow]CI/debugging hint:[/] if a tool/test is hanging, flaky, "
            "environment-dependent, or failing for unclear infrastructure reasons, "
            "use the [bold]ci-fix-dont-freeze[/] skill before weakening or "
            "disabling the defense.",
        )

    verdict = "CLEAN ACROSS EXECUTED DEFENSES"
    style = "bold green"
    if counts[Status.ERROR]:
        verdict = "INCOMPLETE — ONE OR MORE DEFENSES FAILED TO EXECUTE"
        style = "bold red"
    elif counts[Status.FINDINGS]:
        verdict = "BUG SIGNALS FOUND — AGENT FIX QUEUE READY"
        style = "bold yellow"
    elif counts[Status.SKIPPED]:
        verdict = "NO FINDINGS IN EXECUTED DEFENSES — BLIND SPOTS REMAIN"
        style = "bold yellow"

    footer = Text()
    _ = footer.append(verdict + "\n", style=style)
    _ = footer.append(f"Human report    {report_md}\n", style="dim")
    _ = footer.append(f"Machine report  {report_json}\n", style="dim")
    _ = footer.append(
        f"Agent queue     {report_md.parent / 'agent' / 'FIX_QUEUE.md'}",
        style="bold bright_cyan",
    )
    console.print(Panel(footer, border_style="bright_magenta", padding=(1, 2)))
    console.print(
        (
            "[dim]Debugging protocol:[/] if a defense is hanging, flaky, "
            "environment-dependent, or failing for unclear CI/infrastructure "
            "reasons, use the [bold]ci-fix-dont-freeze[/] skill before "
            "weakening, skipping, quarantining, or disabling it."
        ),
    )
    console.print()


def result_to_dict(r: Result) -> dict[str, Any]:
    d = dataclasses.asdict(r)
    d["status"] = r.status.value
    return d


# trace:v1 id=impl.src-bughunt-cli.write-reports work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def write_reports(
    cfg: Config,
    results: list[Result],
    profile: str,
    elapsed: float,
) -> tuple[Path, Path]:
    now = dt.datetime.now().astimezone()
    stamp = now.strftime("%Y%m%d-%H%M%S")
    out = cfg.root / REPORT_DIR / stamp
    agent_dir = out / "agent"
    tasks_dir = agent_dir / "tasks"
    tasks_dir.mkdir(parents=True, exist_ok=True)

    groups = signal_groups(results)
    queue = agent_queue(results)
    hotspots = hotspot_files(results)
    fixes = autofix_summary(results)
    correlations = correlated_issue_groups(results)
    logical_issues = logical_issue_groups(results)
    risks = risk_map(results)
    ledger = load_debt_ledger(cfg.root)
    mark_accepted(results, ledger)
    debt = debt_report(ledger, results)
    accepted_total = sum(
        1 for result in results for finding in result.findings if finding.accepted
    )
    odc_counts: Counter[str] = Counter()
    for result in results:
        for finding in result.findings:
            if finding.accepted:
                continue
            odc_counts[odc_class(result.category, finding)] += 1
    payload: dict[str, Any] = {
        "schema_version": 3,
        "generated_at": now.isoformat(),
        "profile": profile,
        "root": str(cfg.root),
        "elapsed_seconds": elapsed,
        "defense_health": overall_score(results),
        "summary": {
            "tools": len(results),
            "passed": sum(r.status == Status.PASS for r in results),
            "with_findings": sum(r.status == Status.FINDINGS for r in results),
            "errors": sum(r.status == Status.ERROR for r in results),
            "skipped": sum(r.status == Status.SKIPPED for r in results),
            "not_applicable": sum(r.status == Status.NA for r in results),
            "findings": sum(r.count for r in results),
            "accepted": accepted_total,
            "distinct_signals": len(groups),
            "autofixable": fixes["total"],
            "safe_autofixable": fixes["safe"],
            "unsafe_autofixable": fixes["unsafe"],
            "review_autofixable": fixes["review"],
            "correlated_issue_locations": len(correlations),
            "logical_issue_clusters": len(logical_issues),
            "raw_to_logical_ratio": (
                sum(r.count for r in results) / len(logical_issues)
            )
            if logical_issues
            else 0.0,
        },
        "coverage": coverage_summary_from_results(results),
        "odc_taxonomy": dict(odc_counts.most_common()),
        "correlated_issues": correlations,
        "logical_issues": logical_issues,
        "risk_map": risks,
        "autofix": fixes,
        "top_signals": groups,
        "hotspots": [{"path": p, "count": c} for p, c in hotspots],
        "agent_queue": queue,
        "debt": debt,
        "results": [result_to_dict(r) for r in results],
    }

    json_path = out / "report.json"
    _ = json_path.write_text(json.dumps(payload, indent=2, default=str))
    _ = (out / "findings.jsonl").write_text(
        "\n".join(json.dumps(item, default=str) for item in queue)
        + ("\n" if queue else ""),
    )
    _ = (agent_dir / "queue.json").write_text(
        json.dumps(
            {
                "schema_version": 3,
                "autofix": fixes,
                "correlated_issues": correlations,
                "risk_map": risks,
                "items": queue,
            },
            indent=2,
        ),
    )
    _ = (agent_dir / "risk-map.json").write_text(
        json.dumps({"schema_version": 1, "files": risks}, indent=2),
    )
    risk_lines = [
        "# BugHunt Coverage-weighted Risk Map",
        "",
        (
            "This is a prioritization score, not a probability "
            "of bugs. Coverage/branch gaps, complexity and independent-tool "
            "agreement raise priority."
        ),
        "",
        "| Rank | Score | File | Tools | Findings | Coverage | Branch |",
        "|---:|---:|---|---:|---:|---:|---:|",
    ]
    for i, item in enumerate(risks[:200], 1):
        risk_lines.append(
            (
                f"| {i} | {item['score']} | `{item['path']}` | {item['tool_count']} | "
                f"{item['findings']} | {item['coverage_gaps']} | "
                f"{item['branch_gaps']} |"
            ),
        )
    _ = (agent_dir / "RISK_MAP.md").write_text("\n".join(risk_lines) + "\n")

    agent_instructions = """# BugHunt Agent Instructions

You are fixing a BugHunt report. Treat `queue.json` as the machine-readable source of
truth.

Work in this order:

1. Start with execution errors because an analyzer that did not run leaves a blind spot.
2. Then process `queue.json` in order. Fix one finding or coherent repeated-signal
cluster at a time.
3. Inspect the surrounding code before editing. Do not blindly obey analyzer text.
4. Fix root causes. Do not add `noqa`, type ignores, Semgrep suppressions, or
broad exclusions unless the finding is proven false-positive and the suppression
is narrowly justified.
5. Run each item's `verification_command` after the fix, then the narrowest
relevant tests.
6. Re-run BugHunt after a cluster is cleared; line movement can make stale
report locations inaccurate.
7. If a finding reveals a genuine bug that escaped existing defenses, add it
to Bug Corpus / create a permanent detector or property test.
8. Never interpret a missing/crashed analyzer as clean.
9. If CI, a tool, or a test is hanging, flaky, environment-dependent, or failing
infrastructure reasons, use the `ci-fix-dont-freeze` skill before weakening, skipping,
quarantining, or disabling that defense. Preserve the failure evidence and
root-cause it.
10. Use `RISK_MAP.md` and cross-tool correlations to prioritize code with
uncovered branches plus independent analyzer agreement.

Useful files:

- `queue.json`: one item per finding, sorted for repair, including deterministic autofix
metadata.
- `AUTOFIX.md`: exactly which findings have safe or review-required deterministic fixes.
- `FIX_QUEUE.md`: human/agent readable queue.
- `BLIND_SPOTS.md`: analyzers that errored or never ran.
- `RISK_MAP.md` / `risk-map.json`: coverage-weighted file priority for repair and V2
exploration.
- `tasks/`: repeated-signal clusters with all known locations.
- `../findings.jsonl`: streaming-friendly one-record-per-finding representation.
- `../report.json`: full scan facts, commands, raw outputs, and statuses.
"""
    _ = (agent_dir / "AGENT_INSTRUCTIONS.md").write_text(agent_instructions)

    autofix_lines = [
        "# BugHunt Deterministic Auto-fixes",
        "",
        f"- Safe: **{fixes['safe']}**",
        f"- Unsafe: **{fixes['unsafe']}**",
        f"- Rule/review: **{fixes['review']}**",
        f"- Total: **{fixes['total']}**",
        "",
        (
            "BugHunt does not apply these automatically during "
            "a scan. Safe Ruff fixes are the strongest auto-apply "
            "candidates; unsafe Ruff fixes and Semgrep rule fixes "
            "require review."
        ),
        "",
        "## Findings",
        "",
    ]
    for item in queue:
        if not item.get("fixable"):
            continue
        loc = (
            f"{item['path'] or '<unknown>'}:{item['line'] or '?'}:"
            f"{item['column'] or '?'}"
        )
        autofix_lines.append(
            (
                f"- `{item['id']}` **{item['tool']}** `{item.get('code') or ''}` — "
                f"`{loc}` — safety `{item.get('fix_safety') or 'review'}`"
            ),
        )
        if item.get("fix_preview"):
            autofix_lines.append(
                (
                    f"  - Preview: "
                    f"`{str(item['fix_preview']).replace(chr(96), chr(39))[:300]}`"
                ),
            )
    _ = (agent_dir / "AUTOFIX.md").write_text("\n".join(autofix_lines) + "\n")

    blindspots = [r for r in results if r.status in {Status.ERROR, Status.SKIPPED}]
    blind_lines = [
        "# BugHunt Blind Spots",
        "",
        (
            "These defenses did not provide a trusted clean result. "
            "Fix execution errors first; configure/install skipped "
            "defenses when they are relevant to this repository."
        ),
        "",
        (
            "If a defense is hanging, flaky, environment-dependent, "
            "or failing for unclear CI/infrastructure reasons, "
            "use the `ci-fix-dont-freeze` skill before weakening "
            "or disabling it."
        ),
        "",
    ]
    for r in blindspots:
        blind_lines += [
            f"## {r.status.value}: {r.name}",
            "",
            f"- Category: `{r.category}`",
            f"- Reason: {r.note or 'no trusted result'}",
        ]
        if r.command:
            blind_lines += [f"- Command: `{' '.join(r.command)}`"]
        blind_lines.append("")
    if not blindspots:
        blind_lines += ["_No execution blind spots were recorded in this run._", ""]
    _ = (agent_dir / "BLIND_SPOTS.md").write_text("\n".join(blind_lines))

    checklist_lines = [
        "# BugHunt Repair Checklist",
        "",
        "Use this checklist before weakening any defense.",
        "",
        (
            "- [ ] Read `RISK_MAP.md` and start with uncovered/complex/high-agreement "
            "code."
        ),
        (
            "- [ ] Read `DEDUPLICATED_QUEUE.md`; fix one logical "
            "issue rather than independently chasing duplicate "
            "analyzer messages."
        ),
        (
            "- [ ] Apply only deterministic **safe** autofixes "
            "first; review unsafe/review fixes."
        ),
        "- [ ] Re-run the narrow verification command after each root-cause fix.",
        (
            "- [ ] Re-run relevant tests under the canonical seed "
            "and at least one randomized seed."
        ),
        (
            "- [ ] Treat branch coverage gaps, seam drift, migration/API "
            "drift, and mutation survivors as different bug classes."
        ),
        (
            "- [ ] If CI, an analyzer, fuzzing, concurrency, or "
            "environment-matrix execution hangs or behaves inconsistently, "
            "use the `ci-fix-dont-freeze` skill before weakening, "
            "skipping, quarantining, or disabling it."
        ),
        (
            "- [ ] If a real escaped bug is confirmed, add a "
            "regression/property/detector and teach Bug Corpus when "
            "available."
        ),
        "",
    ]
    _ = (agent_dir / "CHECKLIST.md").write_text("\n".join(checklist_lines))

    dedup_lines = [
        "# Deduplicated Logical Issue Queue",
        "",
        (
            f"Raw analyzer findings are preserved elsewhere. "
            f"These {len(logical_issues)} clusters group "
            "same-location/same-defect-class evidence for repair."
        ),
        "",
    ]
    for index, issue in enumerate(logical_issues[:2000], 1):
        loc = f"{issue.get('path') or '<unknown>'}:{issue.get('line') or '?'}"
        dedup_lines += [
            (
                f"- [ ] **{index}. `{issue['id']}`** — `{loc}` — "
                f"**{issue['tool_count']} tool(s), "
                f"{issue['finding_count']} raw finding(s)** — `{issue['odc_class']}`"
            ),
            f"  - Tools: {', '.join(issue['tools'])}",
            f"  - Codes: {', '.join(issue['codes']) or '—'}",
            f"  - Representative: {issue['primary_message']}",
        ]
    _ = (agent_dir / "DEDUPLICATED_QUEUE.md").write_text("\n".join(dedup_lines) + "\n")

    # One task per repeated semantic/rule signal. Agents can often fix these much
    # faster as a coherent family while still validating individual locations.
    for index, group in enumerate(groups[:500], 1):
        safe = (
            re.sub(r"[^A-Za-z0-9_.-]+", "-", (group.get("code") or group["tool"]))[
                :60
            ].strip("-")
            or "signal"
        )
        relevant = [q for q in queue if q["signal_key"] == group["key"]]
        lines = [
            f"# Task {index:04d}: {group['tool']} {group.get('code') or ''}".rstrip(),
            "",
            f"**Occurrences:** {group['count']}",
            f"**Severity:** {group['severity']}",
            f"**Signal key:** `{group['key']}`",
            "",
            "## Representative message",
            "",
            group["message"],
            "",
            "## Locations",
            "",
        ]
        lines.extend(
            (
                f"- `{item['id']}` — `{item['path'] or '<unknown>'}:"
                f"{item['line'] or '?'}:{item['column'] or '?'}:`"
            )
            for item in relevant
        )
        lines += [
            "",
            "## Repair protocol",
            "",
            (
                "Fix the root cause, run the verification command "
                "for the affected analyzer, then re-run BugHunt "
                "to refresh the queue."
            ),
            "",
        ]
        if relevant and relevant[0]["verification_command"]:
            lines += [
                "```bash",
                " ".join(relevant[0]["verification_command"]),
                "```",
                "",
            ]
        _ = (tasks_dir / f"{index:04d}-{safe}.md").write_text("\n".join(lines))

    fix_lines = [
        "# BugHunt Fix Queue",
        "",
        f"Generated `{now.isoformat()}` from profile `{profile}`.",
        "",
        f"**{len(queue)} findings** across **{len(groups)} repeated-signal groups**.",
        (
            f"**{fixes['total']} deterministic auto-fixes available**: {fixes['safe']} "
            "safe, "
            f"{fixes['unsafe']} unsafe, {fixes['review']} review-required."
        ),
        "",
        (
            "Read `AGENT_INSTRUCTIONS.md` and `CHECKLIST.md` first. "
            "`queue.json` is authoritative."
        ),
        (
            "`DEDUPLICATED_QUEUE.md` is the preferred repair view; "
            "raw findings remain available for evidence."
        ),
        "",
        (
            "Also inspect `BLIND_SPOTS.md`; analyzer execution "
            "errors should be repaired before claiming coverage."
        ),
        (
            "Prioritize `RISK_MAP.md`, especially files combining "
            "uncovered branches, complexity, and cross-tool agreement."
        ),
        (
            "If debugging a hanging/flaky/CI-dependent defense, "
            "use the `ci-fix-dont-freeze` skill before weakening "
            "it."
        ),
        "",
        "## Highest-priority repeated signals",
        "",
        "| # | Count | Signal | Example |",
        "|---:|---:|---|---|",
    ]
    for i, g in enumerate(groups[:100], 1):
        label = signal_label(g)
        msg = g["message"].replace("|", "\\|").replace("\n", " ")
        fix_lines.append(f"| {i} | {g['count']} | `{label}` | {msg[:180]} |")
    fix_lines += ["", "## One-by-one queue", ""]
    for i, item in enumerate(queue[:2000], 1):
        loc = (
            f"{item['path'] or '<unknown>'}:{item['line'] or '?'}:"
            f"{item['column'] or '?'}"
        )
        code = f"/{item['code']}" if item["code"] else ""
        fix_lines.append(
            f"- [ ] **{i}. `{item['id']}`** `{item['tool']}{code}` — `{loc}` — "
            f"{item['message']}",
        )
    if len(queue) > 2000:
        fix_lines += [
            "",
            (
                f"_Queue truncated in Markdown at 2000 items; all {len(queue)} items "
                "remain in `queue.json` and `../findings.jsonl`._"
            ),
        ]
    _ = (agent_dir / "FIX_QUEUE.md").write_text("\n".join(fix_lines) + "\n")

    md_path = out / "report.md"
    lines = [
        "# BugHunt Report",
        "",
        f"- Generated: `{now.isoformat()}`",
        f"- Profile: `{profile}`",
        (
            f"- Defense health: **{payload['defense_health']}/100** (execution/defense "
            "health, not probability of bug-freedom)"
        ),
        f"- Elapsed: **{elapsed:.1f}s**",
        f"- Raw normalized findings: **{payload['summary']['findings']}**",
        (
            f"- Logical issue clusters: **{len(logical_issues)}** "
            "(non-destructive dedup view)"
        ),
        f"- Distinct repeated signals: **{len(groups)}**",
        f"- Cross-tool correlated locations: **{len(correlations)}**",
        (
            f"- Deterministic auto-fixes: **{fixes['total']}** total "
            f"(**{fixes['safe']} safe**, "
            f"{fixes['unsafe']} unsafe, {fixes['review']} review-required)"
        ),
        "- Agent repair queue: [`agent/FIX_QUEUE.md`](agent/FIX_QUEUE.md)",
        "- Auto-fix inventory: [`agent/AUTOFIX.md`](agent/AUTOFIX.md)",
        "- Coverage-weighted risk map: [`agent/RISK_MAP.md`](agent/RISK_MAP.md)",
        (
            "- Deduplicated repair queue: "
            "[`agent/DEDUPLICATED_QUEUE.md`](agent/DEDUPLICATED_QUEUE.md)"
        ),
        "- Repair checklist: [`agent/CHECKLIST.md`](agent/CHECKLIST.md)",
        "",
        "## ODC-style defect taxonomy",
        "",
        *[f"- **{count}** — `{kind}`" for kind, count in odc_counts.most_common()],
        "",
        "## Highest-priority repeated signals",
        "",
        "| Count | Tool / rule | Representative message |",
        "|---:|---|---|",
    ]
    for g in groups[:25]:
        label = signal_label(g)
        message = g["message"].replace("|", "\\|").replace(chr(10), " ")[:200]
        lines.append(f"| {g['count']} | `{label}` | {message} |")
    lines += ["", "## Hot files", ""]
    for path, count in hotspots[:20]:
        lines.append(f"- **{count}** findings — `{path}`")
    lines += [
        "",
        "## Defense results",
        "",
        "| Status | Tool | Class | Findings | Time | Note |",
        "|---|---|---|---:|---:|---|",
    ]
    for r in results:
        note = (r.note or "").replace("|", "\\|").replace("\n", " ")
        lines.append(
            (
                f"| {r.status.value} | `{r.name}` | {r.category} | {r.count} | "
                f"{r.duration_s:.1f}s | {note} |"
            ),
        )
    lines += ["", "## Findings", ""]
    if queue:
        for item in queue:
            loc = (
                f"{item['path'] or '<unknown>'}:{item['line'] or '?'}:"
                f"{item['column'] or '?'}"
            )
            lines += [
                (
                    f"### {item['id']} — {item['tool']}"
                    f"{' / ' + item['code'] if item['code'] else ''}"
                ),
                "",
                f"- Location: `{loc}`",
                f"- Severity: `{item['severity']}`",
                f"- Signal: `{item['signal_key']}`",
                f"- Fingerprint: `{item['fingerprint']}`",
                "",
                item["message"],
                "",
            ]
    else:
        lines += [
            "_No normalized findings from defenses that successfully executed._",
            "",
        ]
    lines += ["## Accepted debt", ""]
    if debt:
        lines += [
            "_Known debt, excluded from the fix queue and top signals. "
            "A positive delta means new findings since the snapshot — investigate._",
            "",
            "| Signal | Files | Recorded | Live | Delta | Reason |",
            "|---|---|---:|---:|---:|---|",
        ]
        for row in debt:
            files = ", ".join(f"`{p}`" for p in row["paths"][:3])
            if len(row["paths"]) > 3:
                files += f" (+{len(row['paths']) - 3} more)"
            lines.append(
                f"| `{row['signal']}` | {files} | {row['recorded']} "
                f"| {row['live']} | {row['delta']:+d} | {row['reason']} |",
            )
        lines += [""]
    else:
        lines += ["_No accepted debt recorded in debt.toml._", ""]
    lines += ["## Execution failures / unavailable defenses", ""]
    for r in results:
        if r.status in {Status.ERROR, Status.SKIPPED}:
            lines.append(
                f"- **{r.name}** — {r.status.value}: {r.note or 'see raw output'}",
            )
    lines += ["", "## Raw output", ""]
    for r in results:
        if r.stdout or r.stderr:
            lines += [
                f"### {r.name}",
                "",
                "```text",
                (r.stdout + ("\n[stderr]\n" + r.stderr if r.stderr else "")).strip(),
                "```",
                "",
            ]
    _ = md_path.write_text("\n".join(lines))
    return md_path, json_path


# trace:v1 id=impl.src-bughunt-cli.show-default-rules work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def show_default_rules() -> int:
    table = Table(
        title=f"BugHunt Default Rule Pack — {len(DEFAULT_RULES)} rules",
        box=box.ROUNDED,
        expand=True,
    )
    table.add_column("CODE", style="cyan", no_wrap=True)
    table.add_column("SEVERITY", width=14)
    table.add_column("CLASS", width=22)
    table.add_column("RULE", ratio=3)
    table.add_column("REDUNDANCY", ratio=2)
    for rule in DEFAULT_RULES:
        style = (
            "red"
            if "error" in rule.severity
            else ("yellow" if "warning" in rule.severity else "dim")
        )
        table.add_row(
            rule.code,
            f"[{style}]{rule.severity}[/]",
            rule.category,
            rule.summary,
            rule.overlap or "—",
        )
    console.print(table)
    console.print(
        (
            "[dim]These are BugHunt-native defaults. Ruff ALL, "
            "type checkers, Pylint extensions, Semgrep packs, CodeQL, "
            "and other analyzers add their own rule sets on top.[/]"
        ),
    )
    return 0


# trace:v1 id=impl.src-bughunt-cli.doctor work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def doctor(cfg: Config) -> int:
    technology = discover_technologies(cfg.root, persist=True)

    rows = _doctor_engine_rows(cfg, technology)
    engines = Table(title="BugHunt Engines", box=box.ROUNDED, expand=True)
    engines.add_column("ENGINE", min_width=24)
    engines.add_column("STATUS", width=13)
    engines.add_column("EXECUTABLE / MODULE", ratio=2)
    styles = {
        "READY": "green",
        "MISSING": "red",
        "BROKEN": "red",
        "DEGRADED": "yellow",
        "N/A": "cyan",
    }
    for label, state, detail in rows:
        engines.add_row(
            label,
            f"[{styles.get(state, 'yellow')}]{state}[/]",
            escape(detail),
        )
    console.print(engines)

    guarded = Table(
        title="Guarded / Advisory Correctness Helpers",
        box=box.ROUNDED,
        expand=True,
    )
    guarded.add_column("HELPER", min_width=26)
    guarded.add_column("STATE", width=13)
    guarded.add_column("ROLE / WHY GUARDED", ratio=3)

    _doctor_guarded_rows(cfg, technology, guarded)
    console.print(guarded)

    capability_table = Table(
        title="Repository Capabilities",
        box=box.ROUNDED,
        expand=True,
    )
    capability_table.add_column("CAPABILITY", min_width=24)
    capability_table.add_column("STATE", width=12)
    capability_table.add_column("EVIDENCE", ratio=3)
    _doctor_capability_rows(cfg, technology, capability_table)
    console.print(capability_table)

    manifest_path = cfg.root / ".bughunt" / "configs" / "manifest.json"
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text())
            configured = Table(
                title="Strict Analyzer Configuration",
                box=box.ROUNDED,
                expand=True,
            )
            configured.add_column("STATE", width=11)
            configured.add_column("TOOL", min_width=20)
            configured.add_column("CONFIG", min_width=25)
            configured.add_column("DETAIL", ratio=2)
            for item in manifest.get("artifacts", []):
                state = str(item.get("state", "UNKNOWN"))
                style = "green" if state in {"READY", "EXISTING", "AUTO"} else "yellow"
                configured.add_row(
                    f"[{style}]{state}[/]",
                    str(item.get("name", "?")),
                    str(item.get("path") or "—"),
                    str(item.get("detail") or ""),
                )
            console.print(configured)
        except (OSError, json.JSONDecodeError, TypeError):
            console.print(
                (
                    "[yellow]Strict config manifest is unreadable; "
                    "run `uv run bughunt configure --auto`.[/]"
                ),
            )
    else:
        console.print(
            (
                "[yellow]Strict analyzer overlays are not generated "
                "yet. Run `uv run bughunt configure --auto`.[/]"
            ),
        )

    coverage = Table(title="Repository-Specific Coverage", box=box.ROUNDED, expand=True)
    coverage.add_column("DEFENSE", min_width=34)
    coverage.add_column("CONFIG", width=18)
    coverage.add_column("DETAIL", ratio=2)
    _doctor_coverage_rows(cfg, technology, coverage)
    console.print(coverage)
    return 0


# trace:v1 id=impl.src-bughunt-cli.auto-configure work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def auto_configure(cfg: Config, *, quiet: bool = False) -> list[Any]:
    autod = cfg.raw.get("autodiscovery", {})
    schemathesis_examples = max(1000, int(autod.get("schemathesis_max_examples", 1000)))
    artifacts = configure_all(
        cfg.root,
        cfg.python_paths,
        cfg.source_paths,
        cfg.test_paths,
        schemathesis_examples=schemathesis_examples,
    )
    targets = discover_all(
        cfg.root,
        cfg.source_paths,
        atheris_runs=max(500_000, int(autod.get("atheris_runs", 500_000))),
        schemathesis_examples=schemathesis_examples,
    )
    custom_artifact = configure_custom_checks(cfg.root, targets)
    artifacts.append(custom_artifact)
    pysa_evidence = cfg.root / ".bughunt" / "generated" / "pysa-models.json"
    pysa_count = 0
    if pysa_evidence.exists():
        try:
            pysa_count = len(json.loads(pysa_evidence.read_text()).get("models", []))
        except (OSError, json.JSONDecodeError, TypeError):
            pysa_count = 0
    artifacts.append(
        type(custom_artifact)(
            "Pysa inferred semantic models",
            ".bughunt/configs/pysa/bughunt.pysa",
            "READY",
            (
                f"{pysa_count} high-confidence direct source/sink wrapper model(s) "
                "inferred; evidence in .bughunt/generated/pysa-models.json"
            ),
        ),
    )
    generated_checks = [
        {
            "name": target.name,
            "category": target.kind.removeprefix("custom-"),
            "profile": "deep",
            "command": list(target.command),
            "timeout": int((target.metadata or {}).get("timeout", 3600)),
            "generated": True,
            "confidence": target.confidence,
        }
        for target in targets
        if target.kind.startswith("custom-")
        and target.runnable
        and target.command
        and target.confidence == "high"
    ]
    existing_checks = [
        x for x in cfg.raw.get("custom", {}).get("checks", []) if not x.get("generated")
    ]
    cfg.raw.setdefault("custom", {})["checks"] = [*existing_checks, *generated_checks]
    manifest_path = cfg.root / ".bughunt" / "configs" / "manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    _ = manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 3,
                "artifacts": [dataclasses.asdict(item) for item in artifacts],
            },
            indent=2,
        )
        + "\n",
    )
    if not quiet:
        ctable = Table(
            title="Strict Analyzer Configuration",
            box=box.ROUNDED,
            expand=True,
        )
        ctable.add_column("STATE", width=11)
        ctable.add_column("TOOL", min_width=18)
        ctable.add_column("CONFIG", min_width=24)
        ctable.add_column("DETAIL", ratio=2)
        for item in artifacts:
            style = "green" if item.state in {"READY", "EXISTING", "AUTO"} else "yellow"
            ctable.add_row(
                f"[{style}]{item.state}[/]",
                item.name,
                item.path or "—",
                item.detail,
            )
        console.print(ctable)

        inventory = discover_technologies(cfg.root, persist=True)
        cap_table = Table(
            title="Repository Capability Auto-selection",
            box=box.ROUNDED,
            expand=True,
        )
        cap_table.add_column("CAPABILITY", min_width=24)
        cap_table.add_column("STATE", width=12)
        cap_table.add_column("APPLICABLE ENGINES", ratio=2)
        cap_table.add_column("EVIDENCE", ratio=3)
        for capability in inventory.capabilities.values():
            engines = [
                name for name, cap in ENGINE_CAPABILITY.items() if cap == capability.id
            ]
            evidence = ", ".join(capability.evidence[:3])
            if len(capability.evidence) > 3:
                evidence += f" (+{len(capability.evidence) - 3} more)"
            cap_table.add_row(
                capability.id,
                "[green]DETECTED[/]" if capability.detected else "[dim cyan]N/A[/]",
                ", ".join(engines) or "—",
                escape(evidence or capability.detail),
            )
        console.print(cap_table)

        table = Table(
            title="Auto-discovered Targets & Campaigns",
            box=box.ROUNDED,
            expand=True,
        )
        table.add_column("STATE", width=11)
        table.add_column("ENGINE", width=18)
        table.add_column("TARGET", min_width=28)
        table.add_column("CONF", width=8)
        table.add_column("WHY", ratio=2)
        for target in targets:
            state = "[green]READY[/]" if target.runnable else "[yellow]REVIEW[/]"
            engine = (
                "schemathesis"
                if target.kind.startswith("schemathesis")
                else target.kind.removeprefix("custom-")
            )
            table.add_row(state, engine, target.name, target.confidence, target.reason)
        if not targets:
            table.add_row(
                "[dim]NONE[/]",
                "—",
                "—",
                "—",
                "No high-confidence fuzz/API/semantic targets discovered",
            )
        console.print(table)
        console.print(
            f"[dim]Registry: {cfg.root / '.bughunt' / 'generated' / 'targets.json'}[/]",
        )
    return targets


# trace:v1 id=impl.src-bughunt-cli.run-all work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
async def run_all(
    cfg: Config,
    profile: str,
    *,
    auto_discover: bool = True,
    excluded: set[str] | None = None,
) -> tuple[list[Result], float]:
    global _STOP_REQUESTED
    _STOP_REQUESTED = False
    started = time.perf_counter()
    raw_limit = int(cfg.raw.get("execution", {}).get("raw_output_limit_kb", 512)) * 1024
    if auto_discover and cfg.raw.get("autodiscovery", {}).get("enabled", True):
        _ = auto_configure(cfg, quiet=True)

    excluded = set(excluded or ())
    checks, skipped = build_checks(cfg, profile, excluded=excluded)
    effective_tools = set(cfg.tools(profile)) - excluded
    if not load_technology_inventory(cfg.root).has("python"):
        effective_tools -= {"codeql", "pysa", "mutmut"}
    # Count logical defenses, not internal CodeQL database/mutmut-results phases.
    special_names = [
        name for name in ("codeql", "pysa", "mutmut") if name in effective_tools
    ]
    progress = LiveRunState(total=len(checks) + len(skipped) + len(special_names))
    for item in skipped:
        progress.finish(item)

    stop_refresh = asyncio.Event()

    # trace:v1 id=impl.src-bughunt-cli-run-all.refresher work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
    async def refresher(live: Live) -> None:
        last_heartbeat = time.perf_counter()
        while not stop_refresh.is_set():
            live.update(progress.render(), refresh=True)
            now = time.perf_counter()
            if now - last_heartbeat >= 60:
                last_heartbeat = now
                stuck = sorted(
                    (name, now - float(e["started"]), now - float(e["last_activity"]))
                    for name, e in progress.running.items()
                )
                print(
                    f"[bughunt heartbeat] {now - progress.started_at:.0f}s elapsed, "
                    f"{len(progress.completed)} done, {len(stuck)} running: "
                    + ", ".join(f"{n}({int(a)}s)" for n, a, _ in stuck[:12]),
                    file=sys.stderr,
                    flush=True,
                )
            try:
                await asyncio.wait_for(stop_refresh.wait(), timeout=0.5)
            except TimeoutError:
                # Shutdown race; the loop is already stopping
                pass

    results: list[Result] = []
    with Live(
        progress.render(),
        console=console,
        refresh_per_second=4,
        transient=False,
    ) as live:
        # Signals are delivered to the main thread only; installing a handler
        # off the main thread raises ValueError and could never fire there.
        main_thread = threading.current_thread() is threading.main_thread()
        previous_handler = signal.getsignal(signal.SIGINT)
        if main_thread:
            signal.signal(signal.SIGINT, _handle_sigint)
        refresh_task = asyncio.create_task(refresher(live))
        try:
            normal = await run_parallel(checks, cfg.max_parallel, raw_limit, progress)
            special = []
            for runner, logical_name in (
                (run_codeql, "codeql"),
                (run_pysa, "pysa"),
                (run_mutmut, "mutmut"),
            ):
                if logical_name not in effective_tools:
                    continue
                if _stop_requested():
                    categories = {
                        "codeql": "whole-program",
                        "pysa": "taint",
                        "mutmut": "mutation",
                    }
                    result = _interrupted_result(
                        logical_name, categories.get(logical_name, logical_name)
                    )
                    progress.finish(result)
                    special.append(result)
                    continue
                result = await runner(cfg, profile, raw_limit, progress)
                # Internal subprocesses never count as finished defenses. Record
                # exactly one logical result here, regardless of how many phases ran.
                _ = progress.running.pop("codeql-db", None)
                _ = progress.running.pop("mutmut-results", None)
                progress.finish(result)
                special.append(result)
            results = normal + skipped
            for r in special:
                if r.note == "not in profile":
                    continue
                results.append(r)
        finally:
            stop_refresh.set()
            await refresh_task
            live.update(progress.render(), refresh=True)
            if main_thread:
                signal.signal(signal.SIGINT, previous_handler)

    canonicalize_findings(cfg.root, results)
    mark_accepted(results, load_debt_ledger(cfg.root))
    if "type-disagreement" in effective_tools:
        disagreement = type_disagreement_result(results)
        if disagreement is not None:
            results = [r for r in results if r.name != "type-disagreement"] + [
                disagreement,
            ]
    by_name = {result.name: result for result in results}
    _reconcile_pysa_provider(by_name)
    return results, time.perf_counter() - started


# trace:v1 id=impl.src-bughunt-cli.-reconcile-pysa-provider work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _reconcile_pysa_provider(by_name: dict[str, Result]) -> None:
    pysa_result = by_name.get("pysa")
    pyrefly_result = by_name.get("pyrefly")
    if (
        pysa_result
        and pyrefly_result
        and pyrefly_result.status in {Status.FINDINGS, Status.ERROR}
    ):
        dependency_note = (
            f"Pysa type-provider coverage degraded: Pyrefly is "
            f"{pyrefly_result.status.value.lower()}"
        ) + (f" with {pyrefly_result.count} finding(s)" if pyrefly_result.count else "")
        pysa_result.note = (
            f"{pysa_result.note}; {dependency_note}"
            if pysa_result.note
            else dependency_note
        )
        # A provider that reported diagnostics still ran and still provides
        # types; only a provider that FAILED to execute degrades a clean taint
        # result into an error. Downgrading on mere findings would keep this
        # ring permanently red on any dynamic codebase (cry-wolf), while the
        # note above preserves the caveat visibly.
        if pysa_result.status == Status.PASS and pyrefly_result.status == Status.ERROR:
            pysa_result.status = Status.ERROR


def exit_code_for(cfg: Config, results: list[Result]) -> int:
    policy = str(cfg.raw.get("execution", {}).get("fail_on", "findings"))
    if policy == "never":
        return 0
    if any(r.status == Status.ERROR for r in results):
        return 2
    if policy == "findings" and any(r.status == Status.FINDINGS for r in results):
        return 1
    return 0


# trace:v1 id=impl.src-bughunt-cli.main work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def main(argv: Sequence[str] | None = None) -> int:
    print(f"bughunt v{__version__}", file=sys.stderr)
    parser = argparse.ArgumentParser(
        prog="bughunt",
        description=(
            "Run independent bug-finding defenses and compile one agent-ready report."
        ),
    )
    _ = parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="repository root",
    )
    _ = parser.add_argument("--config", type=Path, help="path to bughunt.toml")

    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="run a bug-hunting profile")
    _ = run_p.add_argument(
        "profile_positional",
        nargs="?",
        choices=("fast", "pr", "deep", "all"),
        help="profile (also accepted as --profile)",
    )
    _ = run_p.add_argument(
        "--profile",
        choices=("fast", "pr", "deep", "all"),
        default=None,
    )
    _ = run_p.add_argument(
        "--skip",
        action="append",
        default=[],
        metavar="DEFENSE",
        help="skip a defense while keeping the selected profile (repeatable)",
    )
    _ = run_p.add_argument(
        "--skip-mutmut",
        action="store_true",
        help="skip mutation testing",
    )
    _ = run_p.add_argument(
        "--no-auto-config",
        action="store_true",
        help="do not refresh strict configs or auto-discovered targets",
    )

    for alias, help_text in (
        ("quick", "run the fast feedback profile"),
        ("pr", "run the pull-request profile"),
        ("deep", "run the deep profile"),
    ):
        alias_p = sub.add_parser(alias, help=help_text)
        _ = alias_p.add_argument("--no-auto-config", action="store_true")

    # trace:v1 id=impl.src-bughunt-cli-main.add-all-options work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
    def add_all_options(target: argparse.ArgumentParser) -> None:
        _ = target.add_argument(
            "--install-missing",
            action=argparse.BooleanOptionalAction,
            default=True,
            help="install missing analyzers before running (default: true)",
        )
        _ = target.add_argument(
            "--skip",
            action="append",
            default=[],
            metavar="DEFENSE",
            help="skip a defense while keeping all other all-profile defenses",
        )
        _ = target.add_argument(
            "--skip-mutmut",
            action="store_true",
            help="skip mutation testing (same as --skip mutmut)",
        )
        _ = target.add_argument("--no-auto-config", action="store_true")

    all_p = sub.add_parser(
        "all",
        help="bootstrap, auto-configure, and run every available defense",
    )
    add_all_options(all_p)

    full_p = sub.add_parser(
        "full",
        help="alias for `all`: bootstrap, configure, and run everything",
    )
    add_all_options(full_p)

    skipmutmut_p = sub.add_parser(
        "skipmutmut",
        help="run the all profile but explicitly skip mutation testing",
    )
    add_all_options(skipmutmut_p)

    install_p = sub.add_parser(
        "install",
        help="auto-install the analysis stack using uv (plus CodeQL/Watchman on macOS)",
    )
    _ = install_p.add_argument("--dry-run", action="store_true")
    _ = install_p.add_argument(
        "--only",
        action="append",
        metavar="COMPONENT",
        help="install/repair only this component (repeatable; e.g. --only atheris)",
    )

    config_p = sub.add_parser(
        "configure",
        help="discover and generate safe deep-analysis targets",
    )
    _ = config_p.add_argument("--auto", action="store_true", default=True)

    _ = sub.add_parser(
        "rules",
        help="list the shipped BugHunt-native default rule pack",
    )
    _ = sub.add_parser(
        "doctor",
        help="show available defenses and missing configuration",
    )
    debt_p = sub.add_parser(
        "debt",
        help="snapshot or review accepted finding debt",
    )
    debt_sub = debt_p.add_subparsers(dest="debt_command", required=True)
    snap_p = debt_sub.add_parser(
        "snapshot",
        help="record current findings as accepted debt in debt.toml",
    )
    _ = snap_p.add_argument("--signal", action="append", default=[])
    _ = snap_p.add_argument("--reason", default="")
    _ = snap_p.add_argument(
        "--path",
        action="append",
        default=[],
        help="only record entries under these paths (exact file or directory prefix)",
    )
    _ = debt_sub.add_parser(
        "review",
        help="diff debt.toml against the latest report",
    )

    args = parser.parse_args(argv)
    root = args.root.resolve()
    cfg = load_config(root, args.config)

    if args.command == "rules":
        return show_default_rules()

    if args.command == "doctor":
        return doctor(cfg)
    if args.command == "debt":
        if args.debt_command == "snapshot":
            return debt_snapshot(
                root,
                list(args.signal or []),
                str(args.reason or ""),
                list(args.path or []),
            )
        return debt_review(root)

    if args.command == "configure":
        _ = auto_configure(cfg)
        return 0

    if args.command == "install":
        selected = ", ".join(args.only) if args.only else "full analysis stack"
        console.print(
            Panel.fit(
                f"[bold bright_cyan]Installing BugHunt: {escape(selected)} with uv[/]",
                border_style="bright_cyan",
            ),
        )
        results = install_all(
            root,
            dry_run=args.dry_run,
            emit=lambda line: console.print(f"[dim]{line}[/]"),
            only=set(args.only) if args.only else None,
        )
        table = Table(title="Installation", box=box.ROUNDED, expand=True)
        table.add_column("STATUS", width=12)
        table.add_column("COMPONENT", min_width=24)
        table.add_column("DETAIL", ratio=2)
        for item in results:
            style = (
                "green"
                if item.status == "PASS"
                else ("yellow" if item.status in {"SKIPPED", "DRY-RUN"} else "red")
            )
            table.add_row(f"[{style}]{item.status}[/]", item.name, item.note)
        console.print(table)
        return 1 if any(item.status == "ERROR" for item in results) else 0

    alias_profiles = {"quick": "fast", "pr": "pr", "deep": "deep"}
    if args.command in {"all", "full", "skipmutmut"}:
        profile = "all"
    elif args.command == "run":
        profile = (
            getattr(args, "profile_positional", None)
            or getattr(args, "profile", None)
            or "pr"
        )
    else:
        profile = alias_profiles.get(args.command, "pr")
    excluded = set(cfg.skip) | set(getattr(args, "skip", []) or [])
    if bool(getattr(args, "skip_mutmut", False)) or args.command == "skipmutmut":
        excluded.add("mutmut")
    known_defenses = (
        set(cfg.tools(profile))
        | set(TECH_DEEP_TOOLS)
        | {
            "mutmut",
            "codeql",
            "pysa",
            "atheris",
            "schemathesis",
            "semgrep",
            "ast-grep",
            "bandit",
            "bugcorpus",
            "custom",
            "pylint-tests",
        }
    )
    unknown_skips = sorted(excluded - known_defenses)
    if unknown_skips:
        parser.error(
            "unknown defense(s) for --skip / execution.skip: "
            + ", ".join(unknown_skips),
        )

    if args.command in {"all", "full", "skipmutmut"} and args.install_missing:
        suffix = " (mutmut skipped)" if "mutmut" in excluded else ""
        inventory = discover_technologies(root, persist=True)
        detected = sum(1 for item in inventory.capabilities.values() if item.detected)
        console.print(
            (
                f"[bold]Detected {detected} repository capability class(es); "
                f"installing only applicable analysis engines{suffix}...[/]"
            ),
        )
        try:
            if excluded:
                install_results = install_all(
                    root,
                    dry_run=False,
                    emit=lambda line: console.print(f"[dim]{line}[/]"),
                    exclude=excluded,
                )
            else:
                install_results = install_all(
                    root,
                    dry_run=False,
                    emit=lambda line: console.print(f"[dim]{line}[/]"),
                )
        except KeyboardInterrupt:
            console.print(
                "[yellow]Installation interrupted — aborting before "
                "the scan starts. Re-run to continue.[/]"
            )
            return 130
        if any(x.status == "ERROR" for x in install_results):
            console.print(
                (
                    "[yellow]Some installers failed; continuing "
                    "so the final report records the remaining "
                    "blind spots.[/]"
                ),
            )
        # Reload config/environment view after uv modified the project.
        cfg = load_config(root, args.config)

    no_auto = bool(getattr(args, "no_auto_config", False))
    if not no_auto:
        _ = auto_configure(cfg, quiet=True)

    profile_display = profile + (
        " - " + ", ".join(f"no {name}" for name in sorted(excluded)) if excluded else ""
    )
    console.print(
        Panel.fit(
            (
                f"[bold bright_cyan]Scanning[/] [bold]{root.name}[/] with "
                f"[bold bright_magenta]{profile_display}[/] defenses"
            ),
            border_style="bright_cyan",
        ),
    )
    if excluded:
        scan_results, elapsed = asyncio.run(
            run_all(cfg, profile, auto_discover=False, excluded=excluded),
        )
    else:
        scan_results, elapsed = asyncio.run(run_all(cfg, profile, auto_discover=False))
    md, js = write_reports(cfg, scan_results, profile, elapsed)
    render_terminal(scan_results, profile, elapsed, md, js)
    if _stop_requested():
        console.print("[yellow]Scan interrupted — partial report written above.[/]")
        return 130
    return exit_code_for(cfg, scan_results)


if __name__ == "__main__":
    raise SystemExit(main())
