# Copyright (c) 2026 Carter LaSalle
"""Report shaping, terminal rendering, and report writing."""

from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from rich import box
from rich.panel import Panel
from rich.progress_bar import ProgressBar
from rich.table import Table
from rich.text import Text

from .config import REPORT_DIR, Config
from .debt import debt_report, load_debt_ledger, mark_accepted
from .models import Finding, Result, Status
from .ui import console


# trace:v1 id=impl.src-bughunt-reporting.reporting work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
# (module marker: finding/report shaping and writing)
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


# trace:v1 id=impl.src-bughunt-reporting.status-style work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def status_style(status: Status) -> str:
    return {
        Status.PASS: "bold green",
        Status.FINDINGS: "bold yellow",
        Status.ERROR: "bold red",
        Status.SKIPPED: "dim",
        Status.NA: "dim cyan",
    }[status]


# trace:v1 id=impl.src-bughunt-reporting.overall-score work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
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


# trace:v1 id=impl.src-bughunt-reporting.result-to-dict work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
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
