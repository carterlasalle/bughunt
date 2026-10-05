# Copyright (c) 2026 Carter LaSalle
"""Async check execution: processes, runners, and provider reconciliation."""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Protocol

from rich import box
from rich.markup import escape
from rich.table import Table

from .config import CACHE_DIR, Config
from .models import Check, Finding, Result, Status
from .parsers import no_findings, parse_json_list, parse_sarif
from .probes import executable, pysa_executable
from .technology import pytest_executable
from .ui import console


# trace:v1 id=impl.src-bughunt-cli.liverunstate work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
class LiveRunState:
    """Live heartbeat for long scans; state is updated by async check tasks."""

    # trace:v1 id=impl.src-bughunt-runners.liverunstate-init work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    def __init__(self, total: int) -> None:
        self.total = total
        self.started_at = time.perf_counter()
        self.running: dict[str, dict[str, Any]] = {}
        self.completed: list[Result] = []

    # trace:v1 id=impl.src-bughunt-runners.liverunstate-start work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
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

    # trace:v1 id=impl.src-bughunt-runners.liverunstate-activity work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
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

    # trace:v1 id=impl.src-bughunt-runners.liverunstate-finish work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
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


# trace:exempt reason=interrupt-flag-wiring-no-behavior
_STOP = {"requested": False}


# trace:v1 id=impl.src-bughunt-runners.live-proc work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
class LiveProc(Protocol):
    """Anything the interrupt path can kill or terminate."""

    # trace:v1 id=impl.src-bughunt-runners.live-proc.kill work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    def kill(self) -> object: ...
    # trace:v1 id=impl.src-bughunt-runners.live-proc.terminate work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    def terminate(self) -> object: ...


LIVE_PROCS: set[LiveProc] = set()


# trace:v1 id=impl.src-bughunt-cli.stop-requested work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def stop_requested() -> bool:
    """True after the first SIGINT; new work must not start."""
    return _STOP["requested"]


# trace:v1 id=impl.src-bughunt-cli.-handle-sigint work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def handle_sigint(signum: int, frame: object) -> None:
    """First Ctrl-C stops gracefully; a second one aborts immediately."""
    _ = (signum, frame)
    if _STOP["requested"]:
        for proc in list(LIVE_PROCS):
            try:
                proc.kill()
            except OSError:
                continue
        raise SystemExit(130)
    _STOP["requested"] = True
    for proc in list(LIVE_PROCS):
        try:
            proc.terminate()
        except OSError:
            continue
    console.print(
        "[yellow]Interrupted — finishing current checks and writing the "
        "partial report (press Ctrl-C again to abort immediately).[/]"
    )


# trace:v1 id=impl.src-bughunt-cli.-interrupted-result work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def interrupted_result(name: str, category: str) -> Result:
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

    # trace:v1 id=impl.src-bughunt-runners.run-process-finish work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    def finish(result: Result) -> Result:
        if progress:
            _ = progress.running.pop(check.name, None)
            if check.record_progress:
                progress.finish(result)
        return result

    if stop_requested():
        return finish(interrupted_result(check.name, check.category))
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
        LIVE_PROCS.add(proc)
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
            LIVE_PROCS.discard(proc)
        except (TimeoutError, asyncio.CancelledError):
            proc.kill()
            try:
                await asyncio.wait_for(proc.wait(), 30)
            except TimeoutError:
                progress_note = f"{check.name}: drain timed out after SIGKILL; continuing with partial output"
                print(progress_note, file=sys.stderr)
            for pending in (out_task, err_task):
                pending.cancel()
            await asyncio.gather(out_task, err_task, return_exceptions=True)
            LIVE_PROCS.discard(proc)
            if stop_requested():
                return finish(interrupted_result(check.name, check.category))
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
    except OSError as exc:
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
            if stop_requested():
                return interrupted_result(check.name, check.category)
            return await run_process(check, raw_limit, progress)

    return await asyncio.gather(*(one(c) for c in checks))


# trace:v1 id=impl.src-bughunt-cli.reset-tool-dir work=WORK-BUG-4ABH9VEY satisfies=REQ-BUG-KZG483AX implements=PLAN-BUG-560GXA79
def reset_tool_dir(path: Path) -> None:
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
    reset_tool_dir(db)

    suite = cfg.raw_section("codeql").get(
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
        no_findings,
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
        no_findings,
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
    mm = pytest_executable(cfg.root, "mutmut")
    if not mm:
        return Result("mutmut", "mutation", Status.SKIPPED, note="mutmut not installed")
    if not cfg.raw_section("mutmut").get("enabled", True):
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
        no_findings,
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
        no_findings,
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


# trace:v1 id=impl.src-bughunt-cli.-reconcile-pysa-provider work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def reconcile_pysa_provider(by_name: dict[str, Result]) -> None:
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
