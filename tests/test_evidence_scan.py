# Copyright (c) 2026 Carter LaSalle
"""Evidence-scan behavior: widening, chained casts, accumulator copies."""

from pathlib import Path

import pytest


def _scan_root(tmp_path: Path, name: str, source: str):
    from bughunt.evidence_scan import scan

    src = tmp_path / "src"
    _ = src.mkdir(exist_ok=True)
    _ = (src / name).write_text(source)
    return scan(tmp_path, ["src"])


def test_widen_then_cast_back_is_error(tmp_path: Path) -> None:
    findings = _scan_root(
        tmp_path,
        "w.py",
        "def f(x: int) -> None:\n" + "    y: object = x\n" + "    z = cast(str, y)\n",
    )
    assert [f.code for f in findings] == ["BHEVID001"]
    assert findings[0].severity == "error"


def test_chained_cast_is_warning(tmp_path: Path) -> None:
    findings = _scan_root(
        tmp_path,
        "c.py",
        "def f(x) -> None:\n    z = cast(str, cast(object, x))\n",
    )
    assert [f.code for f in findings] == ["BHEVID002"]


def test_accumulator_copy_is_warning(tmp_path: Path) -> None:
    findings = _scan_root(
        tmp_path,
        "a.py",
        "def f(items) -> None:\n"
        + "    acc = []\n"
        + "    for i in items:\n"
        + "        acc = acc + [i]\n",
    )
    assert [f.code for f in findings] == ["BHEVID003"]


def test_clean_code_has_no_findings(tmp_path: Path) -> None:
    findings = _scan_root(
        tmp_path,
        "ok.py",
        "def f(x: int) -> int:\n    return x + 1\n",
    )
    assert findings == []


def test_main_reports_json_contract(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    import json

    from bughunt.evidence_scan import main

    src = tmp_path / "src"
    _ = src.mkdir(exist_ok=True)
    _ = (src / "ok.py").write_text("def f(x: int) -> int:\n    return x\n")
    assert main([str(tmp_path), "src"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"] == []
    _ = (src / "bad.py").write_text(
        "def f(x: int) -> None:\n" + "    y: object = x\n" + "    z = cast(str, y)\n"
    )
    assert main([str(tmp_path), "src"]) == 1


def test_nested_duplicate_findings_deduped(tmp_path: Path) -> None:
    findings = _scan_root(
        tmp_path,
        "n.py",
        "def f(x: int) -> None:\n"
        + "    y: object = x\n"
        + "    z = cast(str, y)\n"
        + "    def g() -> None:\n"
        + "        a: object = x\n"
        + "        b = cast(str, a)\n",
    )
    assert len({(f.code, f.line) for f in findings}) == len(findings)


def test_inplace_extend_is_not_a_copy(tmp_path: Path) -> None:
    findings = _scan_root(
        tmp_path,
        "u.py",
        "def f(items) -> None:\n"
        + "    acc = []\n"
        + "    for i in items:\n"
        + "        acc += [i]\n",
    )
    assert findings == []


def test_unparseable_file_skipped(tmp_path: Path) -> None:
    from bughunt.evidence_scan import main

    src = tmp_path / "src"
    _ = src.mkdir(exist_ok=True)
    _ = (src / "broken.py").write_text("def f(:\n")
    assert main([str(tmp_path), "src"]) == 0


def test_subscript_annotation_read(tmp_path: Path) -> None:
    findings = _scan_root(
        tmp_path,
        "s.py",
        "def f(x: list[int]) -> None:\n"
        + "    y: object = x\n"
        + "    z = cast(str, y)\n",
    )
    assert [f.code for f in findings] == ["BHEVID001"]


def test_subscript_accumulator_target_is_ignored(tmp_path: Path) -> None:
    findings = _scan_root(
        tmp_path,
        "w.py",
        "def f(items):\n"
        + "    acc = {}\n"
        + "    for i in items:\n"
        + "        acc[i] = acc.get(i, 0) + 1\n"
        + "    return acc\n",
    )
    assert [item.code for item in findings if item.code == "BHEVID003"] == []
