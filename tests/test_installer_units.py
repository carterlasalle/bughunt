# Copyright (c) 2026 Carter LaSalle
"""Installer primitives: run outcomes, guards, managers, and uv-missing."""

import sys
from pathlib import Path


def test_run_outcomes() -> None:
    from bughunt.installers import _run

    assert _run(["true"], Path(), lambda line: None).status == "PASS"
    assert _run(["false"], Path(), lambda line: None).status == "ERROR"
    missing = _run(["/nonexistent-tool-xyz"], Path(), lambda line: None)
    assert missing.status == "ERROR"


def test_tail_prefers_stderr() -> None:
    from bughunt.installers import _tail

    assert _tail("out", "err") == "err"
    assert _tail("out", "") == "out"
    assert _tail("", "") == "no output"


def test_install_cmd_dry_run_and_note_rewrite() -> None:
    from bughunt.installers import _install_cmd

    dry = _install_cmd(
        "tool",
        ["true"],
        Path(),
        dry_run=True,
        emit=lambda line: None,
        note="would install tool",
    )
    assert (dry.status, dry.name) == ("DRY-RUN", "tool")
    live = _install_cmd(
        "tool",
        ["true"],
        Path(),
        dry_run=False,
        emit=lambda line: None,
        note="would install tool",
    )
    assert (live.status, live.note) == ("PASS", "install tool")


def test_inside_project_environment() -> None:
    from bughunt.installers import _inside_project_environment

    assert _inside_project_environment(str(Path(sys.prefix) / "bin")) is True
    assert _inside_project_environment("/nonexistent-tool-xyz") is False


def test_install_all_without_uv(monkeypatch, tmp_path: Path) -> None:
    import shutil

    from bughunt.installers import install_all

    monkeypatch.setattr(shutil, "which", lambda *_a, **_k: None)
    results = install_all(tmp_path, emit=lambda line: None)
    assert len(results) == 1
    assert results[0].status == "ERROR"


def test_package_manager_without_tools_is_none(monkeypatch, tmp_path: Path) -> None:
    import shutil

    from bughunt.installers import _package_manager

    monkeypatch.setattr(shutil, "which", lambda *_a, **_k: None)
    assert _package_manager(tmp_path) is None
    assert _package_manager(Path(__file__).resolve().parent.parent) is None


def test_brew_prefix_without_brew(tmp_path: Path) -> None:
    from bughunt.installers import _brew_prefix

    assert _brew_prefix("/nonexistent/brew", "llvm", tmp_path) is None


def test_pysa_runtime_paths(tmp_path: Path) -> None:
    from bughunt.installers import _pysa_runtime_pyre, _pysa_runtime_python

    runtime = tmp_path / "pysa-venv"
    assert _pysa_runtime_python(runtime).parent == runtime / "bin"
    assert _pysa_runtime_pyre(runtime).name == "pyre"


def test_install_technology_tools_dry_run(tmp_path: Path) -> None:
    from bughunt.installers import _install_technology_tools

    _ = (tmp_path / "Dockerfile").write_text("FROM python:3.12\n")
    _ = (tmp_path / "query.sql").write_text("SELECT 1\n")
    _ = (tmp_path / "main.go").write_text("package main\n")
    _ = (tmp_path / "go.mod").write_text("module x\n")
    _ = (tmp_path / "a.php").write_text("<?php echo 1;\n")
    _ = (tmp_path / "a.cpp").write_text("int main() { return 0; }\n")
    _ = (tmp_path / "Cargo.toml").write_text("[package]\nname = 'x'\n")
    _ = (tmp_path / "package.json").write_text('{"name": "x"}\n')
    _ = (tmp_path / "app.ts").write_text("const x: number = 1;\n")
    results = _install_technology_tools(
        tmp_path,
        "uv",
        dry_run=True,
        emit=lambda line: None,
        only=None,
        exclude=set(),
    )
    assert results
    assert {item.status for item in results} <= {"PASS", "DRY-RUN", "SKIPPED"}


def test_python_importable_probes(tmp_path: Path) -> None:
    from bughunt.installers import _project_component_ready, _python_importable

    assert _python_importable(tmp_path, "json") is True
    assert _python_importable(tmp_path, "no_such_mod_xyz") is False
    assert _python_importable(tmp_path, "x;evil()") is False
    assert _project_component_ready(tmp_path, "no-such-component-xyz") is False


def test_pysa_provider_probe(tmp_path: Path) -> None:
    from bughunt.installers import _pysa_provider_present

    runtime = tmp_path / "pysa-venv"
    assert _pysa_provider_present(runtime) is False
    binary = runtime / "bin"
    binary.mkdir(parents=True)
    _ = (binary / "pyrefly").write_text("")
    assert _pysa_provider_present(runtime) is True


# trace:v1 id=test.tests-test-installer-units.test-run-kills-hung-command work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_run_kills_hung_command(monkeypatch, tmp_path: Path) -> None:
    import bughunt.installers as installers

    monkeypatch.setattr(installers, "_INSTALL_CMD_TIMEOUT_S", 1)
    result = installers._run(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        tmp_path,
        lambda line: None,
    )
    assert result.status == "ERROR"
    assert "hung past" in result.note


# trace:v1 id=test.tests-test-installer-units.test-inside-target-venv work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_inside_target_venv(tmp_path: Path) -> None:
    from bughunt.installers import _inside_project_environment

    bindir = tmp_path / ".venv" / "bin"
    bindir.mkdir(parents=True)
    tool = bindir / "ruff"
    tool.write_text("#!/bin/sh\n")
    tool.chmod(0o755)
    assert _inside_project_environment(str(tool), tmp_path) is True
    assert _inside_project_environment(str(tool)) is False


# trace:v1 id=test.tests-test-installer-units.test-ready-without-path work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_ready_without_path(monkeypatch, tmp_path: Path) -> None:
    from bughunt import installers

    bindir = tmp_path / ".venv" / "bin"
    bindir.mkdir(parents=True)
    tool = bindir / "ruff"
    tool.write_text("#!/bin/sh\n")
    tool.chmod(0o755)
    monkeypatch.setattr(installers.shutil, "which", lambda _: None)
    assert installers._project_component_ready(tmp_path, "ruff") is True
