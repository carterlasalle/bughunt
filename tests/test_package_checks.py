# Copyright (c) 2026 Carter LaSalle
"""Package-check runner: validation contracts and graceful degradation."""

from pathlib import Path


def test_empty_dir_passes_with_no_checks(tmp_path: Path, capsys) -> None:
    import json

    from bughunt.package_checks import main

    assert main([str(tmp_path)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"] == []


def test_missing_tools_degrade_to_no_findings(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    import json
    import shutil

    from bughunt.package_checks import main

    (tmp_path / "pyproject.toml").write_text('[project]\nname = "pkg"\n')
    monkeypatch.setattr(shutil, "which", lambda *_a, **_k: None)
    assert main([str(tmp_path)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"] == []


def test_tool_failures_become_structured_findings(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    import json

    from bughunt import package_checks

    (tmp_path / "pyproject.toml").write_text('[project]\nname = "pkg"\n')
    (tmp_path / "uv.lock").write_text("")
    (tmp_path / ".git").mkdir()
    dist = tmp_path / ".bughunt" / "cache" / "dist"
    dist.mkdir(parents=True)
    _ = (dist / "pkg-0.1-py3-none-any.whl").write_text("fake")

    def _fake_run(cmd: list[str], root: Path) -> dict[str, object]:
        name = cmd[0].split("/")[-1]
        if name == "twine":
            return {
                "command": cmd,
                "returncode": 1,
                "stdout": "",
                "stderr": "warning: missing long_description",
            }
        return {"command": cmd, "returncode": 0, "stdout": "ok", "stderr": ""}

    monkeypatch.setattr(package_checks, "_run", _fake_run)
    monkeypatch.setattr("shutil.which", lambda name, **_k: f"/bin/{name}")
    assert package_checks.main([str(tmp_path)]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"]
    assert all(item["code"] == "BHPKG001" for item in payload["findings"])


def test_run_failure_is_structured_error(monkeypatch) -> None:
    import subprocess

    from bughunt import package_checks

    def _boom(*_a, **_k):
        raise OSError("nope")

    monkeypatch.setattr(subprocess, "run", _boom)
    result = package_checks._run(["tool"], Path())
    assert result["returncode"] == 255


def test_empty_dist_skips_twine(monkeypatch, tmp_path: Path, capsys) -> None:
    import json

    from bughunt import package_checks

    (tmp_path / "pyproject.toml").write_text('[project]\nname = "pkg"\n')
    (tmp_path / "uv.lock").write_text("")
    (tmp_path / ".git").mkdir()

    def _ok(cmd: list[str], root) -> dict[str, object]:
        return {"command": cmd, "returncode": 0, "stdout": "ok", "stderr": ""}

    monkeypatch.setattr(package_checks, "_run", _ok)
    monkeypatch.setattr("shutil.which", lambda *_a, **_k: "/bin/tool")
    assert package_checks.main([str(tmp_path)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"] == []


# trace:v1 id=test.tests-test-package-checks.test-run-success-shape work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_run_success_shape(tmp_path: Path) -> None:
    from bughunt import package_checks

    result = package_checks._run(["true"], tmp_path)
    assert result["returncode"] == 0
    assert result["command"] == ["true"]
