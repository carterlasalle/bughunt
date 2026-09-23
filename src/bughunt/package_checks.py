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


# Upper bound (seconds) for packaging probes. Validation commands must never
# stall a scan on a wedged tool.
_PROBE_TIMEOUT_S = 600


# trace:v1 id=impl.src-bughunt-package_checks.-run work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _run(cmd: list[str], root: Path) -> _CmdResult:
    try:
        p = subprocess.run(  # noqa: S603 - audited: argv list, no shell
            cmd,
            cwd=root,
            text=True,
            capture_output=True,
            timeout=_PROBE_TIMEOUT_S,
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


# trace:v1 id=impl.src-bughunt-package-checks.wheel-smoke work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _wheel_smoke(root: Path, uv: str, wheels: list[str]) -> list[dict[str, object]]:
    """BHPKG002: install the built wheel isolated and import it elsewhere."""
    out: list[dict[str, object]] = []
    venv = root / ".bughunt" / "cache" / "wheel-smoke-venv"
    empty = root / ".bughunt" / "cache" / "wheel-smoke-cwd"
    try:
        probe = subprocess.run(  # noqa: S603 - audited: argv list, no shell
            [uv, "venv", str(venv)],
            cwd=root,
            text=True,
            capture_output=True,
            timeout=120,
            check=False,
        )
        if probe.returncode != 0:
            return out
        python = venv / "bin" / "python"
        install = subprocess.run(  # noqa: S603 - audited: argv list, no shell
            [uv, "pip", "install", "--python", str(python), "--no-deps", wheels[0]],
            cwd=root,
            text=True,
            capture_output=True,
            timeout=300,
            check=False,
        )
        if install.returncode != 0:
            out.append(
                {
                    "tool": "packaging",
                    "code": "BHPKG002",
                    "message": (
                        "wheel installs but not isolated-clean: "
                        + (install.stderr or install.stdout).strip()[-2000:]
                    ),
                }
            )
            return out
        empty.mkdir(parents=True, exist_ok=True)
        package = _top_package(root)
        checks = [f"import {package}"] if package else ["import importlib"]
        for stmt in checks:
            run = subprocess.run(  # noqa: S603 - audited: argv list, no shell
                [str(python), "-c", stmt],
                cwd=empty,
                text=True,
                capture_output=True,
                timeout=120,
                check=False,
            )
            if run.returncode != 0:
                out.append(
                    {
                        "tool": "packaging",
                        "code": "BHPKG002",
                        "message": f"installed wheel fails `{stmt}` from empty cwd (repo-layout resource?): {(run.stderr or run.stdout).strip()[-2000:]}",
                    }
                )
    except (OSError, subprocess.SubprocessError) as exc:
        out.append(
            {"tool": "packaging", "code": "BHPKG002", "message": f"smoke error: {exc}"}
        )
    return out


# trace:v1 id=impl.src-bughunt-package-checks.top-package work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _top_package(root: Path) -> str | None:
    """First importable top-level package under src/ or the root."""
    for base in (root / "src", root):
        if not base.is_dir():
            continue
        for child in sorted(base.iterdir()):
            if child.is_dir() and (child / "__init__.py").exists():
                return child.name
    return None


# trace:v1 id=impl.src-bughunt-package_checks.main work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def main(argv: list[str] | None = None) -> int:
    root = Path(argv[0] if argv else ".").resolve()
    pyproject = root / "pyproject.toml"
    uv = shutil.which("uv")
    results: list[_CmdResult] = []
    findings: list[dict[str, object]] = []
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
        wheels: list[str] = []
        if uv and twine:
            dist = root / ".bughunt" / "cache" / "dist"
            dist.mkdir(parents=True, exist_ok=True)
            results.append(_run([uv, "build", "--out-dir", str(dist)], root))
            artifacts = sorted(
                str(p)
                for p in dist.glob("*")
                if p.is_file() and p.suffix in {".whl", ".gz", ".zip", ".bz2", ".xz"}
            )
            if artifacts:
                results.append(_run([twine, "check", *artifacts], root))
            wheels = [a for a in artifacts if a.endswith(".whl")]
        if uv and wheels:
            findings.extend(_wheel_smoke(root, uv, wheels))
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
