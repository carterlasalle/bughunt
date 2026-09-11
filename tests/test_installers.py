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
