# Copyright (c) 2026 Carter LaSalle
"""Evidence-scan behavior: widening, chained casts, accumulator copies."""

from pathlib import Path


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


def test_scan_reports_clean_then_dirty_tree(tmp_path: Path) -> None:
    from bughunt.evidence_scan import scan

    src = tmp_path / "src"
    _ = src.mkdir(exist_ok=True)
    _ = (src / "ok.py").write_text("def f(x: int) -> int:\n    return x\n")
    assert scan(tmp_path, ["src"]) == []
    _ = (src / "bad.py").write_text(
        "def f(x: int) -> None:\n" + "    y: object = x\n" + "    z = cast(str, y)\n",
    )
    assert [f.code for f in scan(tmp_path, ["src"])] == ["BHEVID001"]


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


# trace:v1 id=test.tests-test-evidence-scan.test-name-and-annotation-shapes work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_name_and_annotation_shapes(tmp_path: Path) -> None:
    import ast

    from bughunt.evidence_scan import _annotation, _name, scan

    value = ast.parse("mod.attr").body[0]
    assert isinstance(value, ast.Expr)
    assert _name(value.value) == "mod.attr"
    sub = ast.parse("box[key]").body[0]
    assert isinstance(sub, ast.Expr)
    assert _name(sub.value) == "box"
    assert _name(None) == ""
    assert _annotation(None) == ""
    assert _annotation(value.value) == "mod.attr"
    src = tmp_path / "src"
    _ = src.mkdir(exist_ok=True)
    assert scan(tmp_path, ["src", "src"]) == []
    _ = (src / "a.py").write_text(
        "from typing import Any\n\n\ndef f(x: int) -> None:\n"
        "    y: Any = make()\n"
        "    return None\n"
    )
    assert scan(tmp_path, ["src", "src"]) == []


# trace:v1 id=test.tests-test-evidence-scan.test-unparse-fallback work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_unparse_fallback(monkeypatch, tmp_path: Path) -> None:
    import ast

    from bughunt import evidence_scan

    # trace:v1 id=test.tests-test-evidence-scan-test-unparse-fallback.boom work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    def _boom(node: ast.AST | None) -> str:
        raise RuntimeError("nope")

    monkeypatch.setattr(ast, "unparse", _boom)
    assert evidence_scan._annotation(ast.parse("x: int").body[0]) == ""
    src = tmp_path / "src"
    _ = src.mkdir(exist_ok=True)
