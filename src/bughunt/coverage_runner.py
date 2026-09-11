from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from .coverage_tools import parse_coverage_json


# trace:v1 id=impl.src-bughunt-coverage_runner.main work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def main(argv: list[str] | None = None) -> int:
    args = list(argv or sys.argv[1:])
    if not args:
        print(json.dumps({"error": "root required"}))
        return 2
    root = Path(args.pop(0)).resolve()
    tests = args or ["tests"]
    cfg = root / ".bughunt" / "configs" / "coverage.ini"
    out = root / ".bughunt" / "cache" / "coverage.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    base = [sys.executable, "-m", "coverage"]
    subprocess.run(
        [*base, "erase", f"--rcfile={cfg}"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    test = subprocess.run(
        [*base, "run", f"--rcfile={cfg}", "-m", "pytest", "-q", "--tb=short", *tests],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    report = subprocess.run(
        [*base, "json", f"--rcfile={cfg}", "-o", str(out)],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    findings: list[dict[str, object]] = []
    summary: dict[str, object] = {}
    if out.exists():
        try:
            gaps, summary = parse_coverage_json(out)
            findings = [
                {
                    "tool": "coverage",
                    "code": g.code,
                    "path": g.path,
                    "line": g.line,
                    "message": g.message,
                    "severity": g.severity,
                }
                for g in gaps
            ]
        except Exception as exc:  # noqa: BLE001 - diagnostic-infra parse: failure is reported as JSON, never raised
            print(
                json.dumps(
                    {
                        "error": f"coverage JSON parse failed: {type(exc).__name__}: {exc}",
                        "test_stderr": test.stderr[-4000:],
                    }
                )
            )
            return 2
    payload = {
        "findings": findings,
        "summary": summary,
        "test_returncode": test.returncode,
        "test_stdout": test.stdout[-10000:],
        "test_stderr": test.stderr[-10000:],
        "report_returncode": report.returncode,
        "artifact": str(out),
    }
    print(json.dumps(payload))
    if test.returncode != 0:
        return 2
    if report.returncode != 0:
        return 2
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
