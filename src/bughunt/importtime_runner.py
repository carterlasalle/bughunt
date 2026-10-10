# Copyright (c) 2026 Carter LaSalle
from __future__ import annotations

import json
import subprocess
import sys
from contextlib import suppress


# Upper bound (seconds) for one import-profiling child. Startup profiling must
# never stall a scan on a pathological import.
_IMPORT_TIMEOUT_S = 120


# trace:v1 id=impl.src-bughunt-importtime_runner.main work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def main(argv: list[str] | None = None) -> int:
    args = list(argv or sys.argv[1:])
    # The profiling child must import the target's dependencies, which live
    # in the target's environment -- never assume the interpreter running
    # this module (BugHunt's own) can import them. The caller resolves the
    # target interpreter once (`technology.pytest_python`, same as
    # pytest/coverage) and passes it here, mirroring coverage_runner.
    python = sys.executable
    if "--python" in args:
        index = args.index("--python")
        try:
            python = args[index + 1]
        except IndexError:
            print(json.dumps({"error": "--python requires an interpreter path"}))
            return 2
        del args[index : index + 2]
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
            [python, "-X", "importtime", "-c", f"import {module}"],
            text=True,
            capture_output=True,
            check=False,
            timeout=_IMPORT_TIMEOUT_S,
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
            # `-X importtime` rows go to stderr ahead of the traceback, so a
            # raw tail starts mid-word (`ime:`) and buries the cause. Lead
            # with the traceback when one is present.
            detail_lines = [
                line
                for line in proc.stderr.splitlines()
                if not line.startswith("import time:")
            ]
            detail = "\n".join(detail_lines).strip() or proc.stderr.strip()
            findings.append(
                {
                    "tool": "importtime",
                    "code": "BHPERF001",
                    "message": (
                        f"import {module} failed during startup profiling: "
                        f"{detail[-1000:]}"
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
