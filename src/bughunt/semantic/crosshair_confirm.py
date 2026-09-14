# Copyright (c) 2026 Carter LaSalle
"""CrossHair confirmation for semantic contradictions.

The engine decides semantics; CrossHair only confirms. For files
containing contradictions, `crosshair check` runs over the contracts
already present (asserts). A reported counterexample inside a
contradicted function is an independent witness and upgrades the
finding to error-grade. Anything else — missing binary, timeout,
unparseable output, no counterexample — keeps the engine's own
severity. CrossHair never invents a finding here.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .contradictions import Contradiction


TIMEOUT_S = 120


# trace:v1 id=impl.src-bughunt-semantic-crosshair-confirm.confirm work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def confirm(
    root: Path,
    findings: list[Contradiction],
    *,
    timeout: float = TIMEOUT_S,
) -> set[tuple[str, str]]:
    """(file, caller) pairs with a CrossHair counterexample witness."""
    cli = shutil.which("crosshair")
    if cli is None or not findings:
        return set()
    by_file: dict[str, list[str]] = {}
    for finding in findings:
        by_file.setdefault(finding.file, []).append(finding.caller.split("::")[-1])
    confirmed: set[tuple[str, str]] = set()
    for file, callers in by_file.items():
        try:
            proc = subprocess.run(  # noqa: S603 - audited: argv list, no shell
                [cli, "check", "--analysis_kind=asserts", str(root / file)],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        output = proc.stdout + proc.stderr
        for caller in callers:
            short = caller.split(".")[-1]
            if "Counterexample" in output and short in output:
                confirmed.add((file, caller))
    return confirmed
