# Copyright (c) 2026 Carter LaSalle
from __future__ import annotations

import json
import subprocess
import sys
from contextlib import suppress


# trace:v1 id=impl.src-bughunt-importtime_runner.main work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def main(argv: list[str] | None = None) -> int:
    args = list(argv or sys.argv[1:])
    if not args:
        return 0
    threshold_ms = float(args.pop(0))
    findings = []
    samples = []
    for module in args:
        # Module names flow from target-repo discovery into a `-c` code string.
        # A crafted directory name (e.g. `x;evil()`) would execute here, so
        # only valid dotted identifiers reach the interpreter.
        if not all(part.isidentifier() for part in module.split(".")):
            findings.append(
                {
                    "tool": "importtime",
                    "code": "BHPERF001",
                    "message": (
                        f"import {module} skipped: not a valid Python module name"
                    ),
                },
            )
            continue
        proc = subprocess.run(  # noqa: S603 - validated identifier input
            [sys.executable, "-X", "importtime", "-c", f"import {module}"],
            text=True,
            capture_output=True,
            check=False,
            timeout=120,
        )
        cumulative_us = 0
        for line in proc.stderr.splitlines():
            if line.startswith("import time:"):
                parts = line.split("|")
                if len(parts) >= 3 and parts[-1].strip() == module:
                    with suppress(ValueError):
                        cumulative_us = int(parts[1].strip())
        ms = cumulative_us / 1000.0
        samples.append({"module": module, "ms": ms, "returncode": proc.returncode})
        if proc.returncode != 0:
            findings.append(
                {
                    "tool": "importtime",
                    "code": "BHPERF001",
                    "message": (
                        f"import {module} failed during startup profiling: "
                        f"{proc.stderr[-1000:]}"
                    ),
                },
            )
        elif ms > threshold_ms:
            findings.append(
                {
                    "tool": "importtime",
                    "code": "BHPERF001",
                    "message": (
                        f"import {module} cumulative startup time {ms:.1f}ms exceeds "
                        f"{threshold_ms:.1f}ms budget"
                    ),
                    "severity": "warning",
                },
            )
    print(json.dumps({"findings": findings, "samples": samples}))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
