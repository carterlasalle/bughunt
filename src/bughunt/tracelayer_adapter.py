# Copyright (c) 2026 Carter LaSalle
"""TraceLayer adapter: consume direct-verification evidence as a defense ring.

BugHunt does not rebuild a requirements/work/test graph. This module is a
narrow subprocess/JSON boundary over the installed `trace` CLI:

- `trace verify --changed --format json` yields blocking diagnostics
  (untraced behavior, stale implementations, missing verification);
- `trace status --json` yields repository health (broken refs, stale
  traces, evidence runs).

A blocking verify or any broken reference is an error-grade finding, never
clean. No `.trace/` directory means the ring is not applicable (N/A).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path


# trace:v1 id=impl.src-bughunt-tracelayer-adapter.-cli work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _cli() -> str | None:
    return shutil.which("trace")


# trace:v1 id=impl.src-bughunt-tracelayer-adapter.-run work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _run(cli: str, root: Path, *args: str) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(  # noqa: S603 - audited: argv list, no shell
            [cli, "--root", str(root), *args],
            cwd=root,
            text=True,
            capture_output=True,
            check=False,
            timeout=600,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, "", str(exc)
    return proc.returncode, proc.stdout, proc.stderr


# trace:v1 id=impl.src-bughunt-tracelayer-adapter.verify work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def verify(root: Path) -> list[dict[str, object]]:
    """Changed-scope verification diagnostics as findings."""
    cli = _cli()
    if cli is None:
        return []
    code, stdout, stderr = _run(cli, root, "verify", "--changed", "--format", "json")
    if code not in (0, 1):
        return [
            {
                "tool": "tracelayer",
                "code": "BHVERIFY002",
                "message": (
                    f"trace verify failed to execute (exit {code}); "
                    f"verification health is unknown: {stderr[-500:]}"
                ),
                "severity": "error",
            }
        ]
    try:
        data = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        return [
            {
                "tool": "tracelayer",
                "code": "BHVERIFY002",
                "message": (
                    "trace verify emitted unparseable JSON; "
                    "verification health is unknown"
                ),
                "severity": "error",
            }
        ]
    out: list[dict[str, object]] = []
    diagnostics = data.get("diagnostics", [])
    for item in diagnostics if isinstance(diagnostics, list) else []:
        if not isinstance(item, dict):
            continue
        rule = str(item.get("rule", "unknown"))
        trace_id = item.get("trace_id")
        out.append(
            {
                "tool": "tracelayer",
                "code": f"trace:{rule}",
                "path": item.get("path"),
                "line": item.get("line"),
                "severity": str(item.get("severity", "error")).lower(),
                "message": (
                    f"[{rule}] {item.get('message', 'trace diagnostic')}"
                    + (f" (trace_id={trace_id})" if trace_id else "")
                ),
            }
        )
    return out


# trace:v1 id=impl.src-bughunt-tracelayer-adapter.health work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def health(root: Path) -> list[dict[str, object]]:
    """Repository health counters as findings when they indicate breakage."""
    cli = _cli()
    if cli is None:
        return []
    code, stdout, _ = _run(cli, root, "status", "--json")
    if code != 0:
        return []
    try:
        data = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        return []
    out: list[dict[str, object]] = []
    if not isinstance(data, dict):
        return []
    broken = data.get("broken_refs", 0)
    if isinstance(broken, int) and broken > 0:
        out.append(
            {
                "tool": "tracelayer",
                "code": "BHVERIFY003",
                "message": f"trace graph has {broken} broken reference(s)",
                "severity": "error",
            }
        )
    stale = data.get("blocking_stale", 0)
    if isinstance(stale, int) and stale > 0:
        out.append(
            {
                "tool": "tracelayer",
                "code": "BHVERIFY003",
                "message": f"trace graph has {stale} blocking stale trace(s)",
                "severity": "error",
            }
        )
    return out


# trace:v1 id=impl.src-bughunt-tracelayer-adapter.main work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def main(argv: list[str] | None = None) -> int:
    args = list(argv or sys.argv[1:])
    if not args:
        print(json.dumps({"error": "root required"}))
        return 2
    root = Path(args.pop(0)).resolve()
    if _cli() is None or not (root / ".trace").is_dir():
        print(json.dumps({"findings": [], "not_applicable": True}))
        return 0
    findings = [*verify(root), *health(root)]
    print(json.dumps({"findings": findings}))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
