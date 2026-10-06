# Copyright (c) 2026 Carter LaSalle
"""Check construction: wanted subsets, N/A branches, tech engines."""

import asyncio
from pathlib import Path

import pytest


def _cfg(root: Path):
    from bughunt.cli import load_config

    return load_config(root, root / "bughunt.toml")


def _project(root: Path, tools: list[str]) -> None:
    _ = (root / "bughunt.toml").write_text(
        '[project]\npython_paths = ["src"]\nsource_paths = ["src"]\n'
        + 'test_paths = ["tests"]\n[profiles.pr]\ntools = '
        + str(tools).replace("'", '"')
        + "\n",
    )


def test_excluded_tools_are_not_wanted(tmp_path: Path) -> None:
    from bughunt.cli import build_checks

    _project(tmp_path, ["compile", "ruff", "bandit"])
    src = tmp_path / "src"
    src.mkdir()
    _ = (src / "a.py").write_text("x = 1\n")
    checks, skipped = build_checks(_cfg(tmp_path), "pr", excluded={"ruff", "bandit"})
    check_names = {check.name for check in checks}
    skip_names = {item.name for item in skipped}
    assert "compile" in check_names
    assert "ruff" not in check_names
    assert "bandit" not in check_names
    assert {"ruff", "bandit"} <= skip_names


def test_no_python_capability_marks_python_only_na(tmp_path: Path) -> None:
    from bughunt.cli import Status, build_checks

    _project(tmp_path, ["compile", "ruff", "mypy"])
    _ = (tmp_path / "Dockerfile").write_text("FROM x\n")
    checks, skipped = build_checks(_cfg(tmp_path), "pr")
    by_name = {item.name: item for item in skipped}
    assert by_name["ruff"].status == Status.NA
    assert by_name["mypy"].status == Status.NA
    assert "compile" not in {check.name for check in checks}


def test_technology_engines_selected_when_applicable(tmp_path: Path) -> None:
    from bughunt.cli import build_checks

    _project(tmp_path, ["compile", "hadolint", "sqlfluff", "actionlint"])
    _ = (tmp_path / "Dockerfile").write_text("FROM x\n")
    _ = (tmp_path / "q.sql").write_text("SELECT 1\n")
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    _ = (workflows / "ci.yml").write_text("on: push\n")
    checks, skipped = build_checks(_cfg(tmp_path), "pr")
    names = {check.name for check in checks} | {item.name for item in skipped}
    assert {"hadolint", "sqlfluff", "actionlint"} <= names


# trace:v1 id=test.tests-test-build-checks.test-alembic-without-config-skips work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_alembic_without_config_skips(tmp_path: Path) -> None:
    from bughunt.cli import Status, build_checks

    _project(tmp_path, ["alembic-check"])
    _ = (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "0"\ndependencies = ["alembic"]\n'
    )
    _, skipped = build_checks(_cfg(tmp_path), "pr")
    by_name = {item.name: item for item in skipped}
    assert by_name["alembic-check"].status == Status.SKIPPED
    assert "no runnable migration config" in (by_name["alembic-check"].note or "")


# trace:v1 id=test.tests-test-build-checks.test-publint-names-missing-manifest-fields work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_publint_names_missing_manifest_fields(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from bughunt.cli import Status, build_checks

    _project(tmp_path, ["publint"])
    _ = (tmp_path / "package.json").write_text('{"name": "x"}\n')

    # trace:v1 id=test.tests-test-build-checks-test-publint-names-missing-manifest-fields.fake-executable work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    def _fake_executable(root: Path, *names: str) -> str | None:
        return "/usr/bin/publint" if "publint" in names else None

    import bughunt.checks_native_b as native_b

    monkeypatch.setattr(native_b, "project_executable", _fake_executable)
    _, skipped = build_checks(_cfg(tmp_path), "pr")
    by_name = {item.name: item for item in skipped}
    assert by_name["publint"].status == Status.SKIPPED
    assert "missing name/version" in (by_name["publint"].note or "")


# trace:v1 id=test.tests-test-build-checks.test-pythonpath-roots-mirror-package-layout work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_pythonpath_roots_mirror_package_layout(tmp_path: Path) -> None:
    from bughunt.probes import pythonpath_roots

    # src layout: the container dir goes on sys.path.
    srcroot = tmp_path / "python" / "pkg" / "src"
    (srcroot / "pkg").mkdir(parents=True)
    _ = (srcroot / "pkg" / "__init__.py").write_text("")
    assert pythonpath_roots(tmp_path, ["python/pkg/src"]) == [str(srcroot.resolve())]

    # flat layout: the package dir itself contributes its parent.
    flat = tmp_path / "flat"
    (flat / "mod").mkdir(parents=True)
    _ = (flat / "mod" / "__init__.py").write_text("")
    assert pythonpath_roots(tmp_path, ["flat/mod"]) == [str(flat.resolve())]


# trace:v1 id=test.tests-test-build-checks.test-target-python-checks-get-source-pythonpath work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_target_python_checks_get_source_pythonpath(tmp_path: Path) -> None:
    """Nested src-layout packages must import when tests/crosshair run.

    Regression: pytest/crosshair raised ModuleNotFoundError for the target's
    own package because its source root was not on PYTHONPATH, failing every
    test-running and symbolic defense in nested monorepos.
    """
    from bughunt.cli import build_checks

    srcroot = tmp_path / "python" / "seed_evolution" / "src"
    pkg = srcroot / "seed_evolution"
    pkg.mkdir(parents=True)
    _ = (pkg / "__init__.py").write_text("def add(a, b):\n    return a + b\n")
    tests = tmp_path / "python" / "seed_evolution" / "tests"
    tests.mkdir(parents=True)
    _ = (tests / "test_a.py").write_text("from seed_evolution import add\n")
    _ = (tmp_path / "bughunt.toml").write_text(
        '[project]\npython_paths = ["python/seed_evolution/src", '
        '"python/seed_evolution/tests"]\n'
        'source_paths = ["python/seed_evolution/src"]\n'
        'test_paths = ["python/seed_evolution/tests"]\n',
    )
    checks, _ = build_checks(_cfg(tmp_path), "all", excluded={"mutmut"})
    want = str(srcroot.resolve())
    target_python_checks = {"pytest", "crosshair", "coverage", "pytest-random"}
    seen = {c.name: (c.env or {}).get("PYTHONPATH", "") for c in checks}
    for name in target_python_checks:
        assert name in seen, f"{name} missing from checks"
        assert want in seen[name], f"{name} PYTHONPATH={seen[name]!r} lacks {want}"


# trace:v1 id=test.tests-test-build-checks.test-supports-subcommand-probes-leaf work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_supports_subcommand_probes_leaf(tmp_path: Path) -> None:
    import stat

    from bughunt.probes import supports_subcommand

    cli = tmp_path / "fake-hypothesis"
    _ = cli.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "fuzz" ]; then echo "coverage-guided fuzzing"; exit 0; fi\n'
        'echo "No such command: $1" >&2; exit 2\n',
    )
    cli.chmod(cli.stat().st_mode | stat.S_IXUSR)
    assert supports_subcommand(str(cli), "fuzz", tmp_path) is True
    assert supports_subcommand(str(cli), "nosuch", tmp_path) is False
    assert supports_subcommand(str(tmp_path / "absent"), "fuzz", tmp_path) is False


# trace:v1 id=test.tests-test-build-checks.test-hypofuzz-skips-without-fuzz-subcommand work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_hypofuzz_skips_without_fuzz_subcommand(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HypoFuzz adds `fuzz` to the Hypothesis CLI; without it the command is
    "No such command: fuzz". That must SKIP, not count as a failed defense."""
    import bughunt.checks_runtime as cr

    _project(tmp_path, ["hypofuzz"])
    src = tmp_path / "src"
    src.mkdir()
    _ = (src / "a.py").write_text("x = 1\n")
    (tmp_path / "tests").mkdir()

    # trace:v1 id=test.tests-test-build-checks-test-hypofuzz-skips-without-fuzz-subcommand.fake-target-executable work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    def _fake_target_executable(root: Path, *names: str) -> str | None:
        return "/usr/bin/hypothesis"

    # trace:v1 id=test.tests-test-build-checks-test-hypofuzz-skips-without-fuzz-subcommand.fake-supports-subcommand work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    def _fake_supports_subcommand(executable_path: str, sub: str, root: Path) -> bool:
        return False

    monkeypatch.setattr(cr, "target_executable", _fake_target_executable)
    monkeypatch.setattr(cr, "supports_subcommand", _fake_supports_subcommand)
    from bughunt.cli import build_checks

    checks, skipped = build_checks(_cfg(tmp_path), "all", excluded={"mutmut"})
    assert not any(c.name == "hypofuzz" for c in checks), "must not run without fuzz"
    note = " ".join(s.note or "" for s in skipped if s.name == "hypofuzz")
    assert "HypoFuzz" in note or "fuzz" in note


# trace:v1 id=test.tests-test-build-checks.test-vulture-excludes-generated-dirs work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_vulture_excludes_generated_dirs(tmp_path: Path) -> None:
    """vulture walks raw paths and ignores BugHunt scope excludes, so a broad
    scope would report dead code inside .bughunt/ generated configs and
    virtualenvs. It must carry the canonical ignore set via --exclude."""
    from bughunt.cli import build_checks

    (tmp_path / ".bughunt" / "configs").mkdir(parents=True)
    (tmp_path / "pkg").mkdir()
    _ = (tmp_path / "pkg" / "__init__.py").write_text("x = 1\n")
    checks, _ = build_checks(_cfg(tmp_path), "all", excluded={"mutmut"})
    vulture = next(c for c in checks if c.name == "vulture")
    assert "--exclude" in vulture.command
    excluded = vulture.command[vulture.command.index("--exclude") + 1]
    assert ".bughunt" in excluded
    assert "node_modules" in excluded


# trace:v1 id=test.tests-test-build-checks.test-script-interpreter-reads-shebang work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_script_interpreter_reads_shebang(tmp_path: Path) -> None:
    import stat

    from bughunt.technology import script_interpreter

    interp = tmp_path / "bin" / "python"
    interp.parent.mkdir(parents=True)
    _ = interp.write_text("")
    interp.chmod(interp.stat().st_mode | stat.S_IXUSR)
    script = tmp_path / "pytest"
    _ = script.write_text(f"#!{interp}\nimport pytest\n")
    assert script_interpreter(str(script)) == str(interp)

    _ = script.write_text("#!/usr/bin/env python3\nimport pytest\n")
    env_interp = script_interpreter(str(script))
    assert (
        env_interp is None or env_interp.endswith("python3") or "python" in env_interp
    )

    _ = script.write_text("not a shebang\n")
    assert script_interpreter(str(script)) is None
    assert script_interpreter(str(tmp_path / "absent")) is None


# trace:v1 id=test.tests-test-build-checks.test-pytest-plugin-gates-use-pytest-interpreter work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_pytest_plugin_gates_use_pytest_interpreter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """pytest plugins must be importable by the pytest that runs them, which is
    not always target_py (no-venv repos resolve pytest from PATH). The gate must
    probe pytest's own interpreter, not target_py, or it passes while the run
    dies with ImportError."""
    import stat

    import bughunt.checks_runtime as cr

    _project(tmp_path, ["memray", "pytest-async-blocking"])
    (tmp_path / "src").mkdir()
    _ = (tmp_path / "src" / "a.py").write_text("x = 1\n")
    (tmp_path / "tests").mkdir()
    # A pytest console script whose shebang points at a distinct interpreter.
    pytest_bin = tmp_path / "pytest"
    other_interp = tmp_path / "other-python"
    _ = other_interp.write_text("")
    other_interp.chmod(other_interp.stat().st_mode | stat.S_IXUSR)
    _ = pytest_bin.write_text(f"#!{other_interp}\nimport pytest\n")
    pytest_bin.chmod(pytest_bin.stat().st_mode | stat.S_IXUSR)

    seen: list[str] = []

    # trace:v1 id=test.tests-test-build-checks-test-pytest-plugin-gates-use-pytest-interpreter.spy-has-module work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    def _spy_has_module(python: str, name: str) -> bool:
        seen.append(f"{python}::{name}")
        return name != "pytest_memray"  # plugin absent from pytest's env

    monkeypatch.setattr(cr, "target_has_module", _spy_has_module)
    import bughunt.technology as tech_mod

    # trace:v1 id=test.tests-test-build-checks-test-pytest-plugin-gates-use-pytest-interpreter.fake-target-executable work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    def _fake_target_executable(root: Path, *names: str) -> str | None:
        return str(pytest_bin)

    # `pytest_python` resolves through `technology`, so the fake pytest must be
    # injected there for both the command and its interpreter to agree.
    monkeypatch.setattr(tech_mod, "target_executable", _fake_target_executable)
    from bughunt.cli import build_checks

    checks, _skipped = build_checks(_cfg(tmp_path), "all", excluded={"mutmut"})
    # memray gate must have probed the shebang interpreter, not target_py.
    assert any(s == f"{other_interp}::pytest_memray" for s in seen), (
        f"plugin gate did not probe pytest's interpreter: {seen}"
    )
    assert not any(c.name == "memray" for c in checks), "memray must skip, not run"


# trace:v1 id=test.tests-test-build-checks.test-pytest-check-skips-empty-suite work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_pytest_check_skips_empty_suite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A suite that collects nothing (pytest exit 5) is a skip, not a failure.

    ADR-002: empty pytest-style exits map to SKIP. The plain `pytest` defense
    ran with only `findings_exit_codes`, so a repository whose test directory
    holds no tests reported an ERROR for a defense that behaved correctly.
    """
    from bughunt.cli import build_checks, run_process
    from bughunt.models import Status
    from bughunt.technology import target_executable

    if target_executable(tmp_path, "pytest") is None:
        pytest.skip("pytest is not resolvable in this environment")

    _project(tmp_path, ["pytest"])
    (tmp_path / "src").mkdir()
    _ = (tmp_path / "src" / "a.py").write_text("x = 1\n")
    (tmp_path / "tests").mkdir()
    # A test module with no tests in it: pytest exits 5 with nothing collected.
    _ = (tmp_path / "tests" / "test_empty.py").write_text("x = 1\n")

    checks, _skipped = build_checks(_cfg(tmp_path), "all", excluded={"mutmut"})
    pytest_check = next(c for c in checks if c.name == "pytest")
    assert asyncio.run(run_process(pytest_check, 4096)).status == Status.SKIPPED
