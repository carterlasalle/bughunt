# Copyright (c) 2026 Carter LaSalle
"""System IR adapter: consume SCC as BugHunt's graph/dataflow backbone.

BugHunt does not reimplement call graphs. This module is a narrow
subprocess/JSON boundary over the installed `scc` CLI:

- `scc index` keeps the graph fresh (fast incremental);
- `scc export system-ir.json` lands a versioned cache under
  `.bughunt/cache/system-ir.json` keyed by repo root, git revision,
  scc version, and config hash;
- `scc drift --json` and `scc check-invariants` surface structural
  findings (dangling references, conflicting writers, invariant gaps)
  normalized without reinterpretation.

No `scc` CLI means the ring is not applicable (N/A), never clean.
A failing index/export is an error, never clean.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

CACHE_NAME = "system-ir.json"
EXPORT_FORMAT = "system-ir.json"


# trace:v1 id=impl.src-bughunt-system-ir-adapter.-cli work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _cli() -> str | None:
    return shutil.which("scc")


# trace:v1 id=impl.src-bughunt-system-ir-adapter.-run work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _run(cli: str, root: Path, *args: str) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(  # noqa: S603 - audited: argv list, no shell
            [cli, *args, "--root", str(root)],
            cwd=root,
            text=True,
            capture_output=True,
            check=False,
            timeout=900,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, "", str(exc)
    return proc.returncode, proc.stdout, proc.stderr


# trace:v1 id=impl.src-bughunt-system-ir-adapter.-cache-key work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _cache_key(root: Path, cli: str) -> str:
    parts: list[bytes] = [str(root).encode()]
    try:
        proc = subprocess.run(  # noqa: S603 - audited: argv list, no shell
            [  # noqa: S607 - PATH-resolved executable
                "git",
                "rev-parse",
                "HEAD",
            ],
            cwd=root,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        parts.append(proc.stdout.strip().encode())
    except (OSError, subprocess.SubprocessError):
        parts.append(b"nogit")
    try:
        proc = subprocess.run(  # noqa: S603 - audited: argv list, no shell
            [cli, "--version"],
            cwd=root,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        parts.append(proc.stdout.strip().encode())
    except (OSError, subprocess.SubprocessError):
        parts.append(b"noversion")
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part)
    return digest.hexdigest()[:16]


# trace:v1 id=impl.src-bughunt-system-ir-adapter.export work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def export(root: Path) -> tuple[Path | None, str | None]:
    """Refresh the cached System IR export. Returns (path, error)."""
    cli = _cli()
    if cli is None:
        return None, "scc CLI not installed"
    cache = root / ".bughunt" / "cache" / CACHE_NAME
    cache.parent.mkdir(parents=True, exist_ok=True)
    code, stdout, stderr = _run(cli, root, "index")
    if code != 0:
        return None, f"scc index failed (exit {code}): {stderr[-500:]}"
    code, stdout, stderr = _run(cli, root, "export", EXPORT_FORMAT)
    if code != 0:
        return None, f"scc export failed (exit {code}): {stderr[-500:]}"
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return None, f"scc export emitted unparseable JSON: {stdout[-500:]}"
    payload = {"cache_key": _cache_key(root, cli), "system_ir": data}
    _ = cache.write_text(json.dumps(payload))
    return cache, None


# trace:v1 id=impl.src-bughunt-system-ir-adapter.graph-findings work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def graph_findings(root: Path) -> list[dict[str, object]]:
    """Surface SCC drift/invariant findings without reinterpretation."""
    cli = _cli()
    if cli is None:
        return []
    out: list[dict[str, object]] = []
    code, stdout, stderr = _run(cli, root, "drift", "--json")
    if code != 0:
        out.append(
            {
                "tool": "scc",
                "code": "BHGRAPH001",
                "message": f"scc drift failed (exit {code}): {stderr[-500:]}",
                "severity": "error",
            }
        )
    else:
        try:
            items = json.loads(stdout or "[]")
        except json.JSONDecodeError:
            items = []
        for item in items if isinstance(items, list) else []:
            if not isinstance(item, dict):
                continue
            out.append(
                {
                    "tool": "scc",
                    "code": f"scc:{item.get('kind', 'drift')}",
                    "message": (
                        f"[scc/{item.get('id', '?')}] "
                        f"{item.get('message', 'structural drift')}"
                    ),
                    "severity": str(item.get("severity", "warning")),
                }
            )
    code, stdout, stderr = _run(cli, root, "check-invariants")
    if code != 0:
        for line in (stdout + "\n" + stderr).splitlines():
            line = line.strip()
            if line:
                out.append(
                    {
                        "tool": "scc",
                        "code": "BHGRAPH002",
                        "message": f"[scc/invariant] {line}",
                        "severity": "error",
                    }
                )
    return out


# trace:v1 id=impl.src-bughunt-system-ir-adapter.main work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def main(argv: list[str] | None = None) -> int:
    args = list(argv or sys.argv[1:])
    if not args:
        print(json.dumps({"error": "root required"}))
        return 2
    root = Path(args.pop(0)).resolve()
    if _cli() is None:
        print(json.dumps({"findings": [], "not_applicable": True}))
        return 0
    if not (root / ".scc").is_dir():
        print(json.dumps({"findings": [], "not_applicable": True}))
        return 0
    cache, error = export(root)
    findings: list[dict[str, object]] = []
    if error is not None:
        findings.append(
            {
                "tool": "scc",
                "code": "BHGRAPH001",
                "message": error,
                "severity": "error",
            }
        )
    else:
        findings.extend(graph_findings(root))
    print(json.dumps({"findings": findings, "cache": str(cache) if cache else None}))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
