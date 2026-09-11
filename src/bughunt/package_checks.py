# Copyright (c) 2026 Carter LaSalle
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import TypedDict


# trace:v1 id=impl.src-bughunt-package_checks.-cmdresult work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
class _CmdResult(TypedDict):
    command: list[str]
    returncode: int
    stdout: str
    stderr: str


# trace:v1 id=impl.src-bughunt-package_checks.-run work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _run(cmd: list[str], root: Path) -> _CmdResult:
    try:
        p = subprocess.run(
            cmd,
            cwd=root,
            text=True,
            capture_output=True,
            timeout=600,
            check=False,
        )
        return {
            "command": cmd,
            "returncode": p.returncode,
            "stdout": p.stdout[-20000:],
            "stderr": p.stderr[-20000:],
        }
    except (OSError, subprocess.SubprocessError) as exc:
        return {"command": cmd, "returncode": 255, "stdout": "", "stderr": str(exc)}


# trace:v1 id=impl.src-bughunt-package_checks.main work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def main(argv: list[str] | None = None) -> int:
    root = Path(argv[0] if argv else ".").resolve()
    pyproject = root / "pyproject.toml"
    uv = shutil.which("uv")
    results: list[_CmdResult] = []
    if pyproject.exists():
        validate = shutil.which("validate-pyproject")
        if validate:
            results.append(_run([validate, str(pyproject)], root))
        if uv and (root / "uv.lock").exists():
            results.append(_run([uv, "lock", "--check"], root))
        if uv:
            results.append(_run([uv, "pip", "check", "--python", sys.executable], root))
        manifest = shutil.which("check-manifest")
        if manifest and (root / ".git").exists():
            results.append(_run([manifest, "-v"], root))
        twine = shutil.which("twine")
        if uv and twine:
            dist = root / ".bughunt" / "cache" / "dist"
            dist.mkdir(parents=True, exist_ok=True)
            results.append(_run([uv, "build", "--out-dir", str(dist)], root))
            artifacts = sorted(str(p) for p in dist.glob("*") if p.is_file())
            if artifacts:
                results.append(_run([twine, "check", *artifacts], root))
    findings: list[dict[str, object]] = []
    for item in results:
        if int(item.get("returncode", 0)) != 0:
            cmd = item.get("command", [])
            tool = (
                Path(str(cmd[0])).name if isinstance(cmd, list) and cmd else "packaging"
            )
            findings.append(
                {
                    "tool": tool,
                    "code": "BHPKG001",
                    "message": (
                        str(
                            item.get("stderr")
                            or item.get("stdout")
                            or f"{tool} failed",
                        )
                    ).strip()[-4000:],
                },
            )
    print(json.dumps({"findings": findings, "runs": results}))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
