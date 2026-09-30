# Copyright (c) 2026 Carter LaSalle
"""Installer package-set compatibility (dry-run; executes nothing)."""

from pathlib import Path

import pytest

from bughunt.installers import install_all


# trace:v1 id=test.tests-test-installers.test-typescript-capped-below-7-with-eslint work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_typescript_capped_below_7_with_eslint(tmp_path: Path) -> None:
    # typescript-eslint v8 hard-errors on TypeScript >= 7
    # (typescript-eslint#10940); floating both specs resolved
    # typescript@7 + typescript-eslint@8 and crashed eslint with
    # "typescript-eslint does not support TS 7.0" (observed 2026-09-10).
    (tmp_path / "app.ts").write_text("export const x: number = 1;\n")
    results = install_all(tmp_path, dry_run=True, only={"eslint", "tsc"})
    specs = [c for r in results for c in r.command]
    ts_specs = [s for s in specs if s.split("@")[0] == "typescript"]
    assert ts_specs == ["typescript@<7"]


# trace:v1 id=test.tests-test-installers.test-typescript-capped-below-7-for-tsc-only work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_typescript_capped_below_7_for_tsc_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bughunt import installers

    # Same cap as the eslint branch: tsc ships inside the typescript
    # package, and an uncapped spec resolved typescript@7 on a fresh repo
    # (observed 2026-09-11). tsc is force-missed: it exists on this dev
    # machine's PATH, which would otherwise short-circuit the branch.
    monkeypatch.setattr(installers, "project_executable", lambda root, *names: None)
    (tmp_path / "app.ts").write_text("export const x: number = 1;\n")
    results = install_all(tmp_path, dry_run=True, only={"tsc"})
    specs = [c for r in results for c in r.command]
    ts_specs = [s for s in specs if s.split("@")[0] == "typescript"]
    assert ts_specs == ["typescript@<7"]


# trace:v1 id=test.tests-test-installers.test-pysa-provider-present-checks-binary work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_pysa_provider_present_checks_binary(tmp_path: Path) -> None:
    from bughunt.installers import _pysa_provider_present

    runtime = tmp_path / "pysa-venv"
    assert _pysa_provider_present(runtime) is False
    (runtime / "bin").mkdir(parents=True)
    (runtime / "bin" / "pyre").write_text("#!/bin/sh\n")
    assert _pysa_provider_present(runtime) is False
    (runtime / "bin" / "pyrefly").write_text("#!/bin/sh\n")
    assert _pysa_provider_present(runtime) is True


# trace:v1 id=test.tests-test-installers.test-python-importable-rejects-non-identifiers work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_python_importable_rejects_non_identifiers(tmp_path: Path) -> None:
    from bughunt.installers import _python_importable

    # The module name is interpolated into `-c` source; anything that is not
    # a dotted identifier must fail closed without spawning a subprocess.
    assert _python_importable(tmp_path, "x;import os") is False


# trace:v1 id=test.tests-test-installers.test-library-only-packages-never-use-tool-install work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_library_only_packages_never_use_tool_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`uv tool install` refuses packages with no console script.

    Regression: on a non-project target every pytest plugin/library in the
    stack (typeguard, pytest-randomly, deal, ...) was routed through
    `uv tool install`, which exits "No executables are provided by package"
    (observed 2026-09-30). They must install into a Python interpreter
    instead.
    """
    from bughunt import installers

    monkeypatch.setattr(installers, "_project_component_ready", lambda *a, **k: False)
    (tmp_path / "app.py").write_text("print('x')\n")
    results = installers.install_all(
        tmp_path,
        dry_run=True,
        only={"typeguard", "pytest-randomly", "ruff"},
    )
    for item in results:
        if item.name in {"typeguard", "pytest-randomly"}:
            assert item.command, item
            assert "tool" not in item.command, item.command
            assert "pip" in item.command, item.command
        elif item.name == "ruff":
            assert "tool" in item.command, item.command


# trace:v1 id=test.tests-test-installers.test-tool-install-pins-stable-python work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_tool_install_pins_stable_python(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Isolated tool envs must never land on a free-threaded interpreter.

    Regression: `uv tool install` picked the newest installed interpreter
    (3.14t), which has no wheels for C extensions (ruamel-yaml-clib,
    pact-python-ffi) and broke the stack install (observed 2026-09-30).
    """
    from bughunt import installers

    monkeypatch.setattr(installers, "_project_component_ready", lambda *a, **k: False)
    monkeypatch.delenv("BUGHUNT_TOOL_PYTHON", raising=False)
    (tmp_path / "app.py").write_text("print('x')\n")
    results = installers.install_all(tmp_path, dry_run=True, only={"ruff"})
    item = results[0]
    assert item.command[0].endswith("uv")
    idx = item.command.index("--python")
    assert item.command[idx + 1] == "3.12"
