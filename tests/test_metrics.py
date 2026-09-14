# Copyright (c) 2026 Carter LaSalle
"""Complexity visitors: every construct contributes its metric weight."""

from pathlib import Path

EVERYTHING = """\
async def fetch(items):
    total = 0
    data = [x async for x in agen()] if False else [x * 2 for x in items if x]
    async with scope():
        async for x in agen():
            total += x
    for i in range(3):
        total += i
    with open_ctx():
        while total > 100:
            total -= 1
    try:
        value = items[0] if items else -1
    except (ValueError, KeyError):
        value = -2
    flag = True and False or total > 0
    assert total >= 0, "nonnegative"
    match value:
        case 0:
            total += 1
        case n if n > 1:
            total += n
        case _:
            total += 0
    plain: int = 1
    bumped = plain + 1
    bumped += 2
    if (seen := total) > 0:
        total = seen
    nested = lambda q: q + 1
    run(total, flag)
    def inner():
        return 1
    return total if total else value
"""


def test_every_visitor_counts() -> None:
    import ast

    from bughunt.metrics_scan import _metric_for_function

    node = ast.parse(EVERYTHING).body[0]
    assert isinstance(node, ast.AsyncFunctionDef)
    cyclomatic, assignments, branches, conditions, abc, loc = _metric_for_function(node)
    assert cyclomatic > 10
    assert assignments >= 5
    assert branches >= 1
    assert conditions > 5
    assert abc > 0
    assert loc > 10


def test_severity_boundaries() -> None:
    from bughunt.metrics_scan import _severity

    assert _severity(100, 10, 20) == "error"
    assert _severity(15, 10, 20) == "warning"
    assert _severity(5, 10, 20) is None


def test_scan_skips_unparseable_and_missing(tmp_path: Path) -> None:
    from bughunt.metrics_scan import scan

    src = tmp_path / "src"
    src.mkdir()
    _ = (src / "broken.py").write_text("def f(:\n")
    assert scan(tmp_path, ["src", "no-such-dir"]) == []


def test_malformed_config_falls_back_to_defaults(tmp_path: Path) -> None:
    from bughunt.metrics_scan import _budget

    _ = (tmp_path / "bughunt.toml").write_text("not = [valid")
    assert _budget(tmp_path)["cyclomatic_warn"] > 0
    _ = (tmp_path / "bughunt.toml").write_text("[complexity]\ncyclomatic_warn = 3\n")
    assert _budget(tmp_path)["cyclomatic_warn"] == 3.0


def test_scan_assets_flags_oversize_bundle(tmp_path: Path) -> None:
    from bughunt.metrics_scan import _budget, scan_assets

    static = tmp_path / "static"
    static.mkdir()
    _ = (static / "big.js").write_bytes(b"x" * (600 * 1024))
    _ = (static / "big.js.map").write_bytes(b"x" * 10)
    findings = scan_assets(tmp_path, _budget(tmp_path))
    assert any(item.code == "BHCX005" for item in findings)


def test_main_scans_source_tree(tmp_path: Path) -> None:
    from bughunt.metrics_scan import main

    src = tmp_path / "src"
    src.mkdir()
    _ = (src / "a.py").write_text("def f() -> None:\n    pass\n")
    assert main(["--root", str(tmp_path), "--source", "src"]) == 0


def test_nested_functions_are_not_charged_to_parent() -> None:
    import ast

    from bughunt.metrics_scan import FunctionMetricVisitor

    visitor = FunctionMetricVisitor()
    visitor.visit(ast.parse("async def g():\n    pass\ndef f():\n    pass\n"))
    assert visitor.cyclomatic == 1
    assert visitor.assignments == 0
