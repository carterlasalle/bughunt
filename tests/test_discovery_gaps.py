# Copyright (c) 2026 Carter LaSalle
"""Discovery helpers: path inference, annotations, strategies, names."""

import ast
from pathlib import Path


def test_infer_source_paths_variants(tmp_path: Path) -> None:
    from bughunt.discovery import infer_source_paths

    assert infer_source_paths(tmp_path) == ["src"]
    src = tmp_path / "src"
    src.mkdir()
    _ = (src / "a.py").write_text("x = 1\n")
    assert infer_source_paths(tmp_path) == ["src"]
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    _ = (pkg / "__init__.py").write_text("")
    assert infer_source_paths(tmp_path) == ["src", "pkg"]


def test_infer_source_paths_flat_file(tmp_path: Path) -> None:
    from bughunt.discovery import infer_source_paths

    _ = (tmp_path / "solo.py").write_text("x = 1\n")
    assert infer_source_paths(tmp_path) == ["."]


def test_infer_test_paths_default(tmp_path: Path) -> None:
    from bughunt.discovery import infer_test_paths

    assert infer_test_paths(tmp_path) == ["tests"]
    _ = (tmp_path / "test").mkdir()
    assert infer_test_paths(tmp_path) == ["test"]


def test_module_name_shapes(tmp_path: Path) -> None:
    from bughunt.discovery import _module_name

    src = tmp_path / "src"
    src.mkdir()
    mod = src / "pkg" / "mod.py"
    mod.parent.mkdir()
    _ = mod.write_text("")
    assert _module_name(tmp_path, mod, ["src"]) == "pkg.mod"
    init = src / "pkg" / "__init__.py"
    _ = init.write_text("")
    assert _module_name(tmp_path, init, ["src"]) == "pkg"
    assert _module_name(tmp_path, tmp_path / "elsewhere.py", ["src"]) is None


def test_annotation_helpers() -> None:
    from bughunt.discovery import _annotation_name, _annotation_text

    assert _annotation_text(None) is None
    node = ast.parse("x: list[int]\n").body[0]
    assert isinstance(node, ast.AnnAssign)
    assert _annotation_name(node.annotation) == "list"
    assert _annotation_text(node.annotation) == "list[int]"
    name = ast.parse("x: Custom\n").body[0]
    assert isinstance(name, ast.AnnAssign)
    assert _annotation_name(name.annotation) == "Custom"


def test_required_positional_counts_methods() -> None:
    from bughunt.discovery import _required_positional_count

    fn = ast.parse("def f(self, a, b=1): ...").body[0]
    assert isinstance(fn, ast.FunctionDef)
    assert _required_positional_count(fn) == 2
    assert _required_positional_count(fn, method=True) == 1


def test_strategy_expressions() -> None:
    from bughunt.discovery import _strategy_expr

    assert _strategy_expr(None) is None
    assert _strategy_expr("int") == "st.integers()"
    assert _strategy_expr("str | None") is not None
    assert _strategy_expr("list[int]") == "st.lists(st.integers(), max_size=32)"
    assert _strategy_expr("dict[str,int]") is not None
    assert _strategy_expr("tuple[int,str]") is not None
    assert _strategy_expr("Custom") is None
    assert _strategy_expr("list[Custom]") is None


def test_name_variant_and_signatures() -> None:
    from bughunt.discovery import (
        _name_variant,
        _safe_campaign_function,
        _same_signature,
        FunctionInfo,
    )

    assert _name_variant("parse_json_strict", {"strict"}) == (
        "parse_json",
        "strict",
    )
    assert _name_variant("parse", {"strict"}) is None
    info = FunctionInfo(
        module="m",
        name="f",
        qualname="f",
        path=Path("m.py"),
        relative_path="m.py",
        line=1,
        params=[("a", "int")],
        return_annotation="int",
        required_count=1,
        is_async=False,
        has_raise=False,
        boundary_calls=[],
    )
    assert _safe_campaign_function(info) is True
    assert _same_signature(info, info) is True


def test_boundary_call_prefixes() -> None:
    from bughunt.discovery import _is_boundary_call

    assert _is_boundary_call("subprocess.run") is True
    assert _is_boundary_call("pure_compute") is False


def test_discovers_reference_optimized_pair(tmp_path: Path) -> None:
    from bughunt.discovery import discover_custom_campaigns

    src = tmp_path / "src"
    src.mkdir()
    _ = (src / "calc.py").write_text(
        "def total_reference(items: list[int]) -> int:\n"
        + "    return sum(items)\n"
        + "\n\ndef total_fast(items: list[int]) -> int:\n"
        + "    total = 0\n"
        + "    for x in items:\n"
        + "        total += x\n"
        + "    return total\n"
    )
    targets = discover_custom_campaigns(tmp_path, ["src"])
    assert len(targets) == 1
    assert targets[0].name == "calc.total:differential"


def test_discovers_factory_built_app(tmp_path: Path) -> None:
    from bughunt.discovery import discover_schemathesis

    src = tmp_path / "src"
    src.mkdir()
    _ = (src / "web.py").write_text(
        "from fastapi import FastAPI\n"
        + "\n\ndef create_app():\n"
        + "    return FastAPI()\n"
        + "\n\napp = create_app()\n"
    )
    targets = discover_schemathesis(tmp_path, ["src"])
    assert len(targets) == 1
    assert targets[0].name == "web.app"


def test_discovers_fuzz_target_with_seeds(tmp_path: Path) -> None:
    from bughunt.discovery import _literal_seeds, discover_atheris

    src = tmp_path / "src"
    src.mkdir()
    _ = (src / "parse.py").write_text("def fuzz_parse(data: bytes):\n" + "    pass\n")
    tests = tmp_path / "tests"
    tests.mkdir()
    _ = (tests / "test_parse.py").write_text(
        "from parse import fuzz_parse\n"
        + "\n\ndef test_seeds() -> None:\n"
        + "    fuzz_parse(b'raw')\n"
        + "    fuzz_parse('text')\n"
    )
    seeds = _literal_seeds(tmp_path, "fuzz_parse")
    assert (b"raw", "bytes") in seeds
    assert ("text".encode("utf-8"), "str") in seeds
    targets = discover_atheris(tmp_path, ["src"])
    assert [target.name for target in targets] == ["parse.fuzz_parse"]
