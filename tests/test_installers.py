"""Installer package-set compatibility (dry-run; executes nothing)."""

from bughunt.installers import install_all


def test_typescript_capped_below_7_with_eslint(tmp_path):
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
def test_typescript_capped_below_7_for_tsc_only(tmp_path, monkeypatch):
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
def test_pysa_provider_present_checks_binary(tmp_path) -> None:
    from bughunt.installers import _pysa_provider_present

    runtime = tmp_path / "pysa-venv"
    assert _pysa_provider_present(runtime) is False
    (runtime / "bin").mkdir(parents=True)
    (runtime / "bin" / "pyre").write_text("#!/bin/sh\n")
    assert _pysa_provider_present(runtime) is False
    (runtime / "bin" / "pyrefly").write_text("#!/bin/sh\n")
    assert _pysa_provider_present(runtime) is True
