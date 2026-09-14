# Copyright (c) 2026 Carter LaSalle
"""Semantic defense entry point: contradictions over sink contracts.

Loads the cached System IR export when present (interprocedural
edges) and always runs intraprocedural inference. Emits
``{"findings": [...]}`` JSON for the ``semantic`` defense.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from .detectors import concurrency
from .graph.facts import GraphFacts, load as load_facts
from .semantic import contradictions, crosshair_confirm

CACHE_NAME = "system-ir.json"


# trace:v1 id=impl.src-bughunt-semantic-scan.main work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def main(argv: list[str] | None = None) -> int:
    args = list(argv or sys.argv[1:])
    if not args:
        print(json.dumps({"error": "root required"}))
        return 2
    root = Path(args.pop(0)).resolve()
    source_paths = args[0].split(",") if args else ["src"]
    cache = root / ".bughunt" / "cache" / CACHE_NAME
    facts = load_facts(cache) if cache.exists() else GraphFacts()
    files: list[Path] = []
    for source in source_paths:
        base = root / source
        if base.is_file() and base.suffix == ".py":
            files.append(base)
        elif base.is_dir():
            files.extend(sorted(base.rglob("*.py")))
    found = contradictions.scan(root, files, facts)
    witnessed = crosshair_confirm.confirm(root, found)
    payload: list[dict[str, object]] = []
    for finding in found:
        upgraded = (finding.file, finding.caller) in witnessed
        if upgraded:
            finding.confidence = max(finding.confidence, 0.90)
        payload.append(
            {
                "tool": "semantic",
                "code": finding.code,
                "path": finding.file,
                "line": finding.lineno,
                "message": (
                    f"[{finding.caller} → {finding.sink}] {finding.message} "
                    + f"(confidence {finding.confidence:.2f})"
                    + (" [crosshair-witnessed]" if upgraded else "")
                ),
                "severity": "error" if finding.confidence >= 0.90 else "warning",
            }
        )
    for hit in concurrency.scan(root, source_paths, facts):
        payload.append(
            {
                "tool": "semantic",
                "code": hit.code,
                "path": hit.file,
                "line": hit.lineno,
                "message": f"{hit.message} (confidence {hit.confidence:.2f})",
                "severity": "error" if hit.confidence >= 0.90 else "warning",
            }
        )
    print(json.dumps({"findings": payload}))
    return 1 if payload else 0


if __name__ == "__main__":
    raise SystemExit(main())
