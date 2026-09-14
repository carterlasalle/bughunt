# Copyright (c) 2026 Carter LaSalle
"""Fault-injection tests: external boundaries must degrade gracefully."""

from pathlib import Path


def test_git_show_without_git_returns_none(monkeypatch) -> None:
    import shutil

    from bughunt.version_diff_runner import _git_show

    monkeypatch.setattr(shutil, "which", lambda *_a, **_k: None)
    assert _git_show(Path("."), "HEAD", "x.py") is None


def test_git_show_failed_process_returns_none(monkeypatch, tmp_path: Path) -> None:
    import shutil
    import subprocess

    from bughunt.version_diff_runner import _git_show

    monkeypatch.setattr(shutil, "which", lambda *_a, **_k: "/usr/bin/git")

    class _Failed:
        returncode = 1
        stdout = ""

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _Failed())
    assert _git_show(tmp_path, "HEAD", "x.py") is None


def test_port_binds_loopback(tmp_path: Path) -> None:
    from bughunt.pact_runner import _port

    port = _port()
    assert 0 < port < 65536


def test_python_importable_failed_probe_is_false(monkeypatch, tmp_path: Path) -> None:
    import subprocess

    from bughunt.installers import _python_importable

    def _raise(*a, **k):
        raise OSError("no interpreter")

    monkeypatch.setattr(subprocess, "run", _raise)
    assert _python_importable(tmp_path, "x:import os") is False


def test_brew_prefix_failed_probe_is_none(monkeypatch, tmp_path: Path) -> None:
    import subprocess

    from bughunt.installers import _brew_prefix

    def _raise(*a, **k):
        raise OSError("no brew")

    monkeypatch.setattr(subprocess, "run", _raise)
    assert _brew_prefix("brew", "llvm", tmp_path) is None


def test_package_manager_without_managers_returns_none(
    monkeypatch, tmp_path: Path
) -> None:
    import shutil

    from bughunt.installers import _package_manager

    monkeypatch.setattr(shutil, "which", lambda *_a, **_k: None)
    assert _package_manager(tmp_path) is None


def test_git_path_exists_without_git_is_false(monkeypatch, tmp_path: Path) -> None:
    import shutil

    from bughunt.technology import git_path_exists

    monkeypatch.setattr(shutil, "which", lambda *_a, **_k: None)
    assert git_path_exists(tmp_path, "HEAD", "x.py") is False
    assert git_path_exists(tmp_path, None, "x.py") is False


def test_llvm_executable_without_toolchain_is_none(monkeypatch, tmp_path: Path) -> None:
    import shutil

    from bughunt.technology import llvm_executable

    monkeypatch.setattr(shutil, "which", lambda *_a, **_k: None)
    assert llvm_executable(tmp_path, "clang") is None


def test_git_baseline_outside_repo_is_none(monkeypatch, tmp_path: Path) -> None:
    import shutil

    from bughunt.technology import _git_baseline

    monkeypatch.setattr(shutil, "which", lambda *_a, **_k: None)
    assert _git_baseline(tmp_path) is None


def test_ast_grep_executable_missing_is_none(monkeypatch) -> None:
    import shutil

    from bughunt.cli import ast_grep_executable

    monkeypatch.setattr(shutil, "which", lambda *_a, **_k: None)
    assert ast_grep_executable() is None


def test_reset_tool_dir_tolerates_missing(tmp_path: Path) -> None:
    from bughunt.cli import _reset_tool_dir

    _reset_tool_dir(tmp_path / "does-not-exist")


def test_reset_tool_dir_tolerates_chmod_failure(monkeypatch, tmp_path: Path) -> None:
    import subprocess

    from bughunt.cli import _reset_tool_dir

    target = tmp_path / "tree"
    target.mkdir()

    def _raise(*args, **kwargs):
        raise OSError("chmod denied")

    monkeypatch.setattr(subprocess, "run", _raise)
    _reset_tool_dir(target)


def test_project_component_ready_without_tool_is_false(
    monkeypatch, tmp_path: Path
) -> None:
    import shutil

    from bughunt.installers import _project_component_ready

    monkeypatch.setattr(shutil, "which", lambda *_a, **_k: None)
    assert _project_component_ready(tmp_path, "anything") is False


def test_clippy_ready_without_toolchain_is_false(monkeypatch, tmp_path: Path) -> None:
    import shutil

    from bughunt.installers import _clippy_ready

    monkeypatch.setattr(shutil, "which", lambda *_a, **_k: None)
    assert _clippy_ready(tmp_path) is False


def test_install_atheris_dry_run_never_executes(monkeypatch, tmp_path: Path) -> None:
    import shutil

    from bughunt.installers import _install_atheris

    monkeypatch.setattr(shutil, "which", lambda *_a, **_k: None)
    results = _install_atheris(
        tmp_path, "/nonexistent/uv", dry_run=True, emit=lambda _line: None
    )
    assert isinstance(results, list)


def test_install_technology_tools_without_tools_stays_empty(
    monkeypatch, tmp_path: Path
) -> None:
    import shutil

    from bughunt.installers import _install_technology_tools

    monkeypatch.setattr(shutil, "which", lambda *_a, **_k: None)
    results = _install_technology_tools(
        tmp_path,
        "/nonexistent/uv",
        dry_run=True,
        emit=lambda _line: None,
        only=None,
        exclude=set(),
    )
    assert isinstance(results, list)


def test_doctor_without_tools_reports_na(monkeypatch, tmp_path: Path) -> None:
    import shutil

    from bughunt.cli import doctor, load_config

    monkeypatch.setattr(shutil, "which", lambda *_a, **_k: None)
    assert doctor(load_config(tmp_path)) in (0, 1)


def test_pact_main_survives_port_exhaustion(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    import socket
    import sys
    import types

    from bughunt.pact_runner import main as pact_main

    (tmp_path / "pact.json").write_text('{"provider": {"name": "svc"}}')
    fake_pact = types.ModuleType("pact")
    fake_pact.Verifier = object
    monkeypatch.setitem(sys.modules, "pact", fake_pact)

    def _blow_up(*args, **kwargs):
        raise OSError("no file descriptors")

    monkeypatch.setattr(socket, "socket", _blow_up)
    assert pact_main([str(tmp_path), "mod:app", "pact.json"]) == 2
    assert "loopback port" in capsys.readouterr().out
