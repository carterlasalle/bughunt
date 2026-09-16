# Copyright (c) 2026 Carter LaSalle
"""Accepted-finding debt ledger: load, match, review."""

from __future__ import annotations

import json
import sys
import tomllib
from pathlib import Path
from typing import Any

from .config import REPORT_DIR
from .models import DebtEntry, Finding, Result


# trace:v1 id=impl.src-bughunt-debt.debt-ledger work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
# (module marker: ledger load/match/review)
# trace:v1 id=impl.src-bughunt-cli.load-debt-ledger work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def load_debt_ledger(root: Path) -> list[DebtEntry]:
    """Load debt.toml; fail open (mark nothing) with a loud warning."""
    path = root / "debt.toml"
    if not path.exists():
        return []
    try:
        data = tomllib.loads(path.read_text())
    except (OSError, tomllib.TOMLDecodeError) as exc:
        print(f"warning: ignoring unreadable debt.toml: {exc}", file=sys.stderr)
        return []
    entries: list[DebtEntry] = []
    raw = data.get("debt", [])
    if not isinstance(raw, list):
        print("warning: ignoring debt.toml with non-list debt", file=sys.stderr)
        return []
    for item in raw:
        if not isinstance(item, dict):
            continue
        try:
            entries.append(
                DebtEntry(
                    signal=str(item["signal"]),
                    paths=[str(p) for p in item.get("paths", [])],
                    count=int(item.get("count", 0)),
                    reason=str(item.get("reason", "")),
                ),
            )
        except (KeyError, ValueError, TypeError):
            print(
                f"warning: skipping malformed debt entry: {item!r:.80}",
                file=sys.stderr,
            )
    return entries


# trace:v1 id=impl.src-bughunt-cli.mark-accepted work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def mark_accepted(results: list[Result], ledger: list[DebtEntry]) -> dict[str, int]:
    """Flag ledger-matching findings; return live counts per entry index."""
    live: dict[str, int] = {}
    for result in results:
        for finding in result.findings:
            for i, entry in enumerate(ledger):
                if (
                    finding.signal_key == entry.signal
                    and (finding.path or "") in entry.paths
                ):
                    finding.accepted = True
                    live[str(i)] = live.get(str(i), 0) + 1
                    break
    return live


# trace:v1 id=impl.src-bughunt-cli.debt-report work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def debt_report(ledger: list[DebtEntry], results: list[Result]) -> list[dict[str, Any]]:
    """Per-entry recorded-vs-live counts; growth means new findings."""
    rows: list[dict[str, Any]] = []
    for entry in ledger:
        live = sum(
            1
            for result in results
            for finding in result.findings
            if finding.accepted
            and finding.signal_key == entry.signal
            and (finding.path or "") in entry.paths
        )
        rows.append(
            {
                "signal": entry.signal,
                "paths": entry.paths.copy(),
                "recorded": entry.count,
                "live": live,
                "delta": live - entry.count,
                "reason": entry.reason,
            },
        )
    return rows


# trace:v1 id=impl.src-bughunt-cli.debt-latest-report work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _debt_latest_report(root: Path) -> Path | None:
    """Newest report dir containing a report.json, if any."""
    reports = root / REPORT_DIR
    if not reports.exists():
        return None
    candidates = sorted(
        (p for p in reports.iterdir() if (p / "report.json").exists()),
        key=lambda p: p.stat().st_mtime,
    )
    return candidates[-1] if candidates else None


# trace:v1 id=impl.src-bughunt-cli.debt-snapshot work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def debt_snapshot(
    root: Path,
    signals: list[str],
    reason: str,
    paths: list[str] | None = None,
) -> int:
    """Record per-signal-per-file counts from the latest report into debt.toml."""
    if not signals:
        print("error: snapshot needs at least one --signal", file=sys.stderr)
        return 2
    if not reason:
        print("error: snapshot needs a --reason (why is this debt?)", file=sys.stderr)
        return 2
    report_dir = _debt_latest_report(root)
    if report_dir is None:
        print("error: no report.json found; run a scan first", file=sys.stderr)
        return 1
    report = json.loads((report_dir / "report.json").read_text())
    counts: dict[tuple[str, str], int] = {}
    for result in report.get("results", []):
        for item in result.get("findings", []) or []:
            finding = Finding(
                tool=str(item.get("tool", "")),
                message=str(item.get("message", "")),
                path=item.get("path"),
                line=item.get("line"),
                column=item.get("column"),
                code=item.get("code"),
                severity=str(item.get("severity", "error")),
            )
            if finding.signal_key in signals and (
                not paths
                or any(
                    (finding.path or "") == p or (finding.path or "").startswith(p)
                    for p in paths
                )
            ):
                key = (finding.signal_key, finding.path or "")
                counts[key] = counts.get(key, 0) + 1
    if not counts:
        print("no findings match the given signals; nothing recorded")
        return 1
    ledger = load_debt_ledger(root)
    wanted = set(signals)
    ledger = [e for e in ledger if e.signal not in wanted]
    for (sig, path), count in sorted(counts.items()):
        ledger.append(
            DebtEntry(signal=sig, paths=[path], count=count, reason=reason),
        )
    lines = [
        "# Accepted finding debt. Entries here stay visible in the report's",
        "# debt section but leave the fix queue, top signals, hotspots, and",
        "# risk map. Growth beyond the recorded count surfaces in `debt review`.",
        "# Re-snapshot with `bughunt debt snapshot`; inspect with `bughunt debt review`.",
        "",
    ]
    for entry in ledger:
        lines += [
            "[[debt]]",
            f"signal = {entry.signal!r}",
            f"paths = {[entry.paths[0]]!r}"
            if len(entry.paths) == 1
            else f"paths = {entry.paths!r}",
            f"count = {entry.count}",
            f"reason = {entry.reason!r}",
            "",
        ]
    (root / "debt.toml").write_text("\n".join(lines))
    print(f"recorded {len(counts)} debt entries from {report_dir.name}")
    return 0


# trace:v1 id=impl.src-bughunt-cli.debt-review work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def debt_review(root: Path) -> int:
    """Diff the ledger against the latest report; exit 1 on growth."""
    ledger = load_debt_ledger(root)
    if not ledger:
        print("no debt recorded in debt.toml")
        return 0
    report_dir = _debt_latest_report(root)
    if report_dir is None:
        print("error: no report.json found; run a scan first", file=sys.stderr)
        return 1
    report = json.loads((report_dir / "report.json").read_text())
    live: dict[tuple[str, str], int] = {}
    for result in report.get("results", []):
        for item in result.get("findings", []) or []:
            finding = Finding(
                tool=str(item.get("tool", "")),
                message=str(item.get("message", "")),
                path=item.get("path"),
                line=item.get("line"),
                column=item.get("column"),
                code=item.get("code"),
                severity=str(item.get("severity", "error")),
            )
            key = (finding.signal_key, finding.path or "")
            live[key] = live.get(key, 0) + 1
    grew = 0
    for entry in ledger:
        for path in entry.paths:
            current = live.get((entry.signal, path), 0)
            delta = current - entry.count
            state = "GREW" if delta > 0 else ("SHRANK" if delta < 0 else "OK")
            if delta > 0:
                grew += 1
            print(
                f"{state}: {entry.signal} @ {path} recorded={entry.count} live={current}",
            )
    return 1 if grew else 0
