# Copyright (c) 2026 Carter LaSalle
from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
from http.client import HTTPException
from pathlib import Path
from urllib.request import urlopen


def _port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


# trace:v1 id=impl.src-bughunt-pact-runner.-provider-name work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _provider_name(path: Path) -> str | None:
    try:
        data = json.loads(path.read_text(errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None
    provider = data.get("provider") if isinstance(data, dict) else None
    name = provider.get("name") if isinstance(provider, dict) else None
    return name if isinstance(name, str) else None


# trace:v1 id=impl.src-bughunt-pact_runner.-wait-http work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _wait_http(url: str, proc: subprocess.Popen[str], timeout_s: float = 20.0) -> bool:
    if not url.startswith(("http://", "https://")):
        return False
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        try:
            with urlopen(url, timeout=0.5):  # nosec B310 - scheme-guarded above
                return True
        except (OSError, HTTPException):
            time.sleep(0.15)
    return False


# trace:v1 id=impl.src-bughunt-pact_runner.main work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def main(argv: list[str] | None = None) -> int:
    args = list(argv or sys.argv[1:])
    if len(args) < 3:
        print(json.dumps({"error": "root, module:app, and pact file(s) required"}))
        return 2
    root = Path(args.pop(0)).resolve()
    app = args.pop(0)
    pacts = [root / value for value in args]
    providers: list[tuple[Path, str]] = []
    for path in pacts:
        name = _provider_name(path)
        if name is not None:
            providers.append((path, name))
    if not providers:
        print(json.dumps({"error": "no valid local Pact files with provider names"}))
        return 2
    try:
        from pact import Verifier
    except ImportError as exc:
        print(json.dumps({"error": f"pact-python not importable: {exc}"}))
        return 2

    try:
        port = _port()
    except OSError as exc:
        print(json.dumps({"error": f"no free loopback port: {exc}"}))
        return 2
    url = f"http://127.0.0.1:{port}"
    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        app,
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--log-level",
        "warning",
    ]
    proc = subprocess.Popen(  # noqa: S603 - audited: argv list, no shell
        cmd,
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    findings: list[dict[str, object]] = []
    try:
        if not _wait_http(url, proc):
            out, err = (
                proc.communicate(timeout=2) if proc.poll() is not None else ("", "")
            )
            print(
                json.dumps(
                    {
                        "error": "local provider failed to start",
                        "command": cmd,
                        "stdout": out[-4000:],
                        "stderr": err[-4000:],
                    },
                ),
            )
            return 2
        for pact_file, provider_name in providers:
            try:
                # verify() raises on contract failure; the chain result itself
                # carries nothing the caller needs.
                _ = (
                    Verifier(provider_name)
                    .add_source(str(pact_file))
                    .add_transport(url=url)
                    .verify()
                )
            except Exception as exc:  # noqa: BLE001 - third-party verify(): failure modes are the finding
                findings.append(
                    {
                        "tool": "pact-contracts",
                        "code": "BHSEAM007",
                        "path": str(pact_file.relative_to(root)),
                        "severity": "error",
                        "message": (
                            f"provider {provider_name!r} does not satisfy Pact "
                            f"contract: {type(exc).__name__}: {exc}"
                        ),
                    },
                )
    finally:
        proc.terminate()
        try:
            _ = proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            _ = proc.wait(timeout=5)
    print(
        json.dumps(
            {
                "findings": findings,
                "provider_url": url,
                "pacts": [str(p.relative_to(root)) for p, _ in providers],
            },
        ),
    )
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
