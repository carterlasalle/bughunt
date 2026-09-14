# Copyright (c) 2026 Carter LaSalle
"""Pact runner: provider probing, guards, and graceful degradation."""

import json
from pathlib import Path


def _pact(tmp_path: Path, name: str) -> Path:
    path = tmp_path / "p.json"
    _ = path.write_text(json.dumps({"provider": {"name": name}, "interactions": []}))
    return path


def test_provider_name_round_trip(tmp_path: Path) -> None:
    from bughunt.pact_runner import _provider_name

    assert _provider_name(_pact(tmp_path, "svc")) == "svc"
    assert _provider_name(tmp_path / "missing.json") is None
    _ = (tmp_path / "bad.json").write_text("not json")
    assert _provider_name(tmp_path / "bad.json") is None
    _ = (tmp_path / "list.json").write_text("[]")
    assert _provider_name(tmp_path / "list.json") is None


def test_port_binds_loopback() -> None:
    import socket

    from bughunt.pact_runner import _port

    port = _port()
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", port))


def test_wait_http_rejects_non_http_scheme() -> None:
    import subprocess

    from bughunt.pact_runner import _wait_http

    proc = subprocess.Popen(["true"], text=True)
    try:
        assert _wait_http("file:///etc/passwd", proc) is False
    finally:
        _ = proc.wait()


def test_main_needs_three_args() -> None:
    from bughunt.pact_runner import main

    assert main([]) == 2
    assert main(["only-root"]) == 2


def test_main_rejects_pact_without_provider(tmp_path: Path, capsys) -> None:
    from bughunt.pact_runner import main

    bad = tmp_path / "p.json"
    _ = bad.write_text("{}")
    assert main([str(tmp_path), "app:main", str(bad)]) == 2
    assert "no valid local Pact files" in capsys.readouterr().out


def test_main_without_pact_library(tmp_path: Path, monkeypatch, capsys) -> None:
    import sys

    from bughunt.pact_runner import main

    pact_file = _pact(tmp_path, "svc")
    monkeypatch.setitem(sys.modules, "pact", None)
    assert main([str(tmp_path), "app:main", str(pact_file)]) == 2
    assert "pact-python not importable" in capsys.readouterr().out


def test_wait_http_true_path_against_local_server() -> None:
    import subprocess
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from bughunt.pact_runner import _wait_http

    class _Quiet(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - http.server protocol name
            self.send_response(200)
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            _ = (format, args)

    server = HTTPServer(("127.0.0.1", 0), _Quiet)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    proc = subprocess.Popen(["sleep", "30"], text=True)
    try:
        url = f"http://127.0.0.1:{server.server_port}"
        assert _wait_http(url, proc, timeout_s=30.0) is True
    finally:
        server.shutdown()
        proc.terminate()
        _ = proc.wait()


def test_main_reports_provider_that_never_starts(tmp_path: Path, capsys) -> None:

    from bughunt.pact_runner import main

    pact_file = _pact(tmp_path, "svc")
    code = main([str(tmp_path), "no_such_module_xyz:app", str(pact_file)])
    assert code == 2
    assert "local provider failed to start" in capsys.readouterr().out


# trace:v1 id=test.tests-test-pact.test-wait-http-timeout work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_wait_http_timeout() -> None:
    import subprocess

    from bughunt.pact_runner import _wait_http

    proc = subprocess.Popen(["true"], text=True)
    try:
        assert _wait_http("http://127.0.0.1:1/", proc, timeout_s=0) is False
    finally:
        _ = proc.wait()
