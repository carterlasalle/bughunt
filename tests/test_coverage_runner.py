# Copyright (c) 2026 Carter LaSalle
"""Coverage runner: end-to-end on a micro package."""

from pathlib import Path


def test_runner_produces_json_report(tmp_path: Path, capsys) -> None:
    import json

    from bughunt.coverage_runner import main

    pkg = tmp_path / "src" / "pkg"
    pkg.mkdir(parents=True)
    _ = (pkg / "__init__.py").write_text(
        "def add(a: int, b: int) -> int:\n    return a + b\n"
    )
    tests = tmp_path / "tests"
    _ = tests.mkdir()
    _ = (tmp_path / "conftest.py").write_text(
        "import sys\nfrom pathlib import Path\n"
        "sys.path.insert(0, str(Path(__file__).parent / 'src'))\n"
    )
    _ = (tests / "test_add.py").write_text(
        "from pkg import add\n\ndef test_add() -> None:\n    assert add(1, 2) == 3\n"
    )
    _ = (tmp_path / ".bughunt" / "configs").mkdir(parents=True)
    _ = (tmp_path / ".bughunt" / "configs" / "coverage.ini").write_text(
        "[run]\nbranch = true\nsource =\n    src\n"
    )
    assert main([str(tmp_path)]) in (0, 1)
    out = tmp_path / ".bughunt" / "cache" / "coverage.json"
    assert out.exists()
    payload = json.loads(out.read_text())
    assert "files" in payload
