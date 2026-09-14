# Copyright (c) 2026 Carter LaSalle
"""End-to-end orchestration on a fixture repo with only stdlib tools."""

from pathlib import Path


def _fixture(tmp_path: Path) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    _ = (src / "a.py").write_text("def add(a: int, b: int) -> int:\n    return a + b\n")
    tests = tmp_path / "tests"
    _ = tests.mkdir()
    _ = (tests / "test_a.py").write_text(
        "from a import add\n\ndef test_add() -> None:\n    assert add(1, 2) == 3\n",
    )
    _ = (tmp_path / "bughunt.toml").write_text(
        '[project]\npython_paths = ["src"]\nsource_paths = ["src"]\n'
        'test_paths = ["tests"]\n[profiles.fast]\ntools = ["compile"]\n',
    )
    return tmp_path


def test_run_fast_profile_end_to_end(tmp_path: Path) -> None:
    from bughunt.cli import main

    root = _fixture(tmp_path)
    assert main(["--root", str(root), "run", "fast", "--no-auto-config"]) == 0
    report = root / ".bughunt" / "reports"
    assert report.exists()


def test_quick_alias_end_to_end(tmp_path: Path) -> None:
    from bughunt.cli import main

    root = _fixture(tmp_path)
    assert main(["--root", str(root), "quick", "--no-auto-config"]) == 0


def test_doctor_reports_fixture_tree(tmp_path: Path) -> None:
    from bughunt.cli import main

    root = _fixture(tmp_path)
    assert main(["--root", str(root), "doctor"]) == 0


def test_run_pr_profile_end_to_end(tmp_path: Path) -> None:
    from bughunt.cli import main

    root = _fixture(tmp_path)
    assert main(["--root", str(root), "run", "pr", "--no-auto-config"]) in (
        0,
        1,
        2,
    )


def test_rules_lists_default_pack(tmp_path: Path) -> None:
    from bughunt.cli import main

    root = _fixture(tmp_path)
    assert main(["--root", str(root), "rules"]) == 0


def test_configure_refreshes_strict_configs(tmp_path: Path) -> None:
    from bughunt.cli import main

    root = _fixture(tmp_path)
    assert main(["--root", str(root), "configure"]) == 0
    assert (root / ".bughunt" / "configs").exists()


def test_install_dry_run_lists_stack(tmp_path: Path) -> None:
    from bughunt.cli import main

    root = _fixture(tmp_path)
    assert main(["--root", str(root), "install", "--dry-run"]) == 0


def test_debt_review_on_fixture(tmp_path: Path) -> None:
    from bughunt.cli import main

    root = _fixture(tmp_path)
    assert main(["--root", str(root), "debt", "review"]) == 0


def test_doctor_on_non_python_tree(tmp_path: Path) -> None:
    from bughunt.cli import main

    _ = (tmp_path / "Dockerfile").write_text("FROM x\n")
    _ = (tmp_path / "bughunt.toml").write_text("[project]\n")
    assert main(["--root", str(tmp_path), "doctor"]) == 0


def test_local_schema_pairs_resolve_and_refuse(tmp_path: Path) -> None:
    from bughunt.cli import local_schema_pairs

    schema = tmp_path / "schema.json"
    _ = schema.write_text("{}")
    doc = tmp_path / "doc.json"
    _ = doc.write_text('{"$schema": "./schema.json"}')
    remote = tmp_path / "r.json"
    _ = remote.write_text('{"$schema": "https://example.com/s.json"}')
    broken = tmp_path / "b.json"
    _ = broken.write_text("{oops")
    assert local_schema_pairs(tmp_path, ["doc.json"]) == [("doc.json", "schema.json")]
    assert local_schema_pairs(tmp_path, ["r.json", "b.json", "missing.json"]) == []


def test_pact_json_files_filter(tmp_path: Path) -> None:
    import json

    from bughunt.cli import pact_json_files

    pact = tmp_path / "p.json"
    _ = pact.write_text(
        json.dumps({"consumer": {}, "provider": {}, "interactions": []}),
    )
    _ = (tmp_path / "plain.json").write_text("{}")
    _ = (tmp_path / "broken.json").write_text("{")
    _ = (tmp_path / "notes.txt").write_text("hi")
    assert pact_json_files(tmp_path, ["p.json"]) == ["p.json"]
    assert pact_json_files(tmp_path, ["plain.json", "broken.json", "notes.txt"]) == ([])


def test_debt_snapshot_guards(tmp_path: Path) -> None:
    from bughunt.cli import debt_snapshot

    assert debt_snapshot(tmp_path, [], "", None) == 2
    assert debt_snapshot(tmp_path, ["s"], "", None) == 2
    assert debt_snapshot(tmp_path, ["s"], "r", None) == 1


def test_debt_snapshot_records_report(tmp_path: Path) -> None:
    import json

    from bughunt.cli import debt_snapshot

    stamp = tmp_path / ".bughunt" / "reports" / "20260101-000000"
    stamp.mkdir(parents=True)
    _ = (stamp / "report.json").write_text(
        json.dumps(
            {
                "results": [
                    {
                        "findings": [
                            {
                                "tool": "ruff",
                                "code": "F401",
                                "message": "unused",
                                "path": "src/a.py",
                                "line": 1,
                                "severity": "warning",
                            },
                        ],
                    },
                ],
            },
        ),
    )
    assert debt_snapshot(tmp_path, ["ruff:F401"], "test debt", None) == 0
    assert (tmp_path / "debt.toml").exists()
    assert debt_snapshot(tmp_path, ["nope:zzz"], "test debt", None) == 1


def test_load_debt_ledger_tolerates_malformed_entries(tmp_path: Path) -> None:
    from bughunt.cli import load_debt_ledger

    _ = (tmp_path / "debt.toml").write_text("debt = 'notalist'\n")
    assert load_debt_ledger(tmp_path) == []
    _ = (tmp_path / "debt.toml").write_text("[[debt]]\ncount = 1\n")
    assert load_debt_ledger(tmp_path) == []
    _ = (tmp_path / "debt.toml").write_text("[[debt]]\nnotasignal = 1\n")
    assert load_debt_ledger(tmp_path) == []


def test_debt_review_without_report_is_error(tmp_path: Path) -> None:
    from bughunt.cli import debt_review

    _ = (tmp_path / "debt.toml").write_text(
        "[[debt]]\nsignal = 'ruff:F401'\npaths = ['src/a.py']\n"
        + "count = 1\nreason = 'test'\n",
    )
    assert debt_review(tmp_path) == 1


def test_tools_all_falls_back_to_profile_union(tmp_path: Path) -> None:
    from bughunt.cli import load_config

    _ = (tmp_path / "bughunt.toml").write_text(
        '[project]\n[profiles.pr]\ntools = ["compile"]\n',
    )
    cfg = load_config(tmp_path, tmp_path / "bughunt.toml")
    assert "compile" in cfg.tools("all")


def test_publishable_package_json_gate(tmp_path: Path) -> None:
    import json

    from bughunt.cli import _publishable_package_json

    assert _publishable_package_json(tmp_path) is None
    _ = (tmp_path / "package.json").write_text(json.dumps({"private": True}))
    assert _publishable_package_json(tmp_path) is None
    _ = (tmp_path / "package.json").write_text("{broken")
    assert _publishable_package_json(tmp_path) is None
    pub = {"name": "x", "version": "0.0.1"}
    _ = (tmp_path / "package.json").write_text(json.dumps(pub))
    assert _publishable_package_json(tmp_path) == tmp_path / "package.json"
