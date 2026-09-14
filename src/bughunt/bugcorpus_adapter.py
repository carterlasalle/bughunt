# Copyright (c) 2026 Carter LaSalle
"""BugCorpus adapter: consume the real BugCorpus product as a defense ring.

BugHunt does not reimplement BugCase/detector promotion. This module is a
narrow subprocess/JSON boundary over the installed `bugcorpus` CLI:

- `bugcorpus --json verify` proves detector health (failures are findings,
  never clean);
- `bugcorpus --json scan` yields historical-bug findings, normalized into
  BugHunt's helper JSON while preserving BugCase, family, detector, engine,
  state, and provenance;
- `bugcorpus --json coverage` feeds blind-spot reporting.

No `.bugcorpus` directory means the ring is not applicable (N/A), never clean.
A missing CLI on a corpus-bearing repo is an error, never clean.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

PROFILE_MAP = {"fast": "fast", "pr": "pr", "deep": "full", "all": "full"}


# trace:v1 id=impl.src-bughunt-bugcorpus_adapter.-cli work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _cli() -> str | None:
    return shutil.which("bugcorpus")


# Upper bound (seconds) for BugCorpus CLI invocations. History verification
# must never stall a scan on a wedged subprocess.
_BUGCORPUS_TIMEOUT_S = 600


# trace:v1 id=impl.src-bughunt-bugcorpus_adapter.-run work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _run(cli: str, root: Path, *args: str) -> tuple[int, str]:
    try:
        proc = subprocess.run(  # noqa: S603 - audited: argv list, no shell
            [cli, "--json", *args],
            cwd=root,
            text=True,
            capture_output=True,
            check=False,
            timeout=_BUGCORPUS_TIMEOUT_S,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, json.dumps({"error": str(exc)})
    return proc.returncode, proc.stdout


# trace:v1 id=impl.src-bughunt-bugcorpus_adapter.verify work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def verify(root: Path) -> tuple[bool, list[dict[str, object]]]:
    """Run detector verification; return (ok, error findings)."""
    cli = _cli()
    if cli is None:
        return False, [
            {
                "tool": "bugcorpus",
                "code": "BHBUGC001",
                "message": (
                    "repo has .bugcorpus but the bugcorpus CLI is not installed; "
                    "historical-bug coverage is unverified"
                ),
                "severity": "error",
            },
        ]
    returncode, stdout = _run(cli, root, "verify")
    try:
        data = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        return False, [
            {
                "tool": "bugcorpus",
                "code": "BHBUGC001",
                "message": (
                    f"bugcorpus verify emitted unparseable JSON: {stdout[-500:]}"
                ),
                "severity": "error",
            },
        ]
    errors: list[dict[str, object]] = []
    if returncode != 0 or not data.get("ok", False):
        for item in data.get("schema_errors", []):
            errors.append(
                {
                    "tool": "bugcorpus",
                    "code": "BHBUGC001",
                    "message": f"bugcorpus detector schema error: {item}",
                    "severity": "error",
                },
            )
        for detector in data.get("detectors", []):
            if isinstance(detector, dict) and detector.get("status") not in (
                "pass",
                "passing",
                "ok",
                None,
            ):
                errors.append(
                    {
                        "tool": "bugcorpus",
                        "code": "BHBUGC001",
                        "message": (
                            f"bugcorpus detector {detector.get('id', '?')} "
                            f"verification status: {detector.get('status', '?')}"
                        ),
                        "severity": "error",
                    },
                )
        if not errors:
            errors.append(
                {
                    "tool": "bugcorpus",
                    "code": "BHBUGC001",
                    "message": (
                        f"bugcorpus verify failed (exit {returncode}) with no "
                        "itemized errors; historical-bug coverage is unverified"
                    ),
                    "severity": "error",
                },
            )
    return (not errors), errors


# trace:v1 id=impl.src-bughunt-bugcorpus_adapter.scan work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def scan(root: Path, profile: str) -> list[dict[str, object]]:
    """Run the corpus scan; normalize findings, preserving provenance."""
    cli = _cli()
    if cli is None:
        return []
    bugcorpus_profile = PROFILE_MAP.get(profile, "fast")
    returncode, stdout = _run(cli, root, "scan", "--profile", bugcorpus_profile)
    try:
        data = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        return [
            {
                "tool": "bugcorpus",
                "code": "BHBUGC001",
                "message": f"bugcorpus scan emitted unparseable JSON: {stdout[-500:]}",
                "severity": "error",
            },
        ]
    out: list[dict[str, object]] = []
    if returncode != 0 and not data.get("findings"):
        out.append(
            {
                "tool": "bugcorpus",
                "code": "BHBUGC001",
                "message": (
                    f"bugcorpus scan failed (exit {returncode}); "
                    "historical-bug coverage is unverified"
                ),
                "severity": "error",
            },
        )
    for item in data.get("findings", []) or []:
        if not isinstance(item, dict):
            continue
        provenance = "/".join(
            str(item.get(key, "?")) for key in ("family", "detector", "engine", "state")
        )
        out.append(
            {
                "tool": "bugcorpus",
                "code": str(item.get("detector") or item.get("bugcase") or "BHBUGC002"),
                "path": item.get("path"),
                "line": item.get("line"),
                "severity": str(item.get("severity", "warning")),
                "message": (
                    f"[{provenance}] bug {item.get('bugcase', '?')}: "
                    f"{item.get('message', 'historical-bug detector hit')}"
                ),
            },
        )
    return out


# trace:v1 id=impl.src-bughunt-bugcorpus_adapter.main work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def main(argv: list[str] | None = None) -> int:
    args = list(argv or sys.argv[1:])
    if not args:
        print(json.dumps({"error": "root required"}))
        return 2
    root = Path(args.pop(0)).resolve()
    profile = args.pop(0) if args else "fast"
    if not (root / ".bugcorpus").is_dir():
        print(json.dumps({"findings": [], "not_applicable": True}))
        return 0
    ok, errors = verify(root)
    findings = scan(root, profile) if ok else []
    print(json.dumps({"findings": [*errors, *findings]}))
    return 1 if (errors or findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
