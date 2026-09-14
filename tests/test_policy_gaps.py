# Copyright (c) 2026 Carter LaSalle
"""Policy helpers: literals, env discovery, secrets, managed keys."""

import ast
from pathlib import Path


def _expr(source: str) -> ast.AST:
    node = ast.parse(source).body[0]
    assert isinstance(node, ast.Expr)
    return node.value


def test_literal_and_numeric_constant() -> None:
    from bughunt.policy_scan import _literal, _numeric_constant

    assert _literal(None) is None
    assert _literal(_expr("f(x)")) is None
    assert _literal(_expr("'x'")) == "x"
    assert _numeric_constant(_expr("True")) is None
    assert _numeric_constant(_expr("3")) == 3
    assert _numeric_constant(_expr("'s'")) is None


def test_assigned_name_shapes() -> None:
    from bughunt.policy_scan import _assigned_name

    tree = ast.parse("PORT = int(os.getenv('PORT', 0))\n")
    assign = tree.body[0]
    assert isinstance(assign, ast.Assign)
    parents: dict[ast.AST, ast.AST] = dict.fromkeys(ast.walk(assign), assign)
    call = assign.value
    assert isinstance(call, ast.Call)
    assert _assigned_name(call, parents) == "PORT"
    tree2 = ast.parse("A = B = f()\n")
    multi = tree2.body[0]
    assert isinstance(multi, ast.Assign)
    parents2: dict[ast.AST, ast.AST] = dict.fromkeys(ast.walk(multi), multi)
    assert _assigned_name(multi.value, parents2) is None


def test_env_discovery_forms(tmp_path: Path) -> None:
    from bughunt.policy_scan import discover_env_uses

    src = tmp_path / "src"
    src.mkdir()
    _ = (src / "cfg.py").write_text(
        "import os\n"
        + "HOST = os.environ['APP_HOST']\n"
        + "PORT = int(os.getenv('APP_PORT', 8080))\n"
        + "FLAG = os.getenv('APP_FLAG')\n"
        + "HOST2 = os.environ['APP_HOST']\n",
    )
    uses = {item.name: item for item in discover_env_uses(tmp_path, ["src"])}
    assert uses["APP_HOST"].required is True
    assert uses["APP_PORT"].required is False
    assert uses["APP_PORT"].inferred_type == "int"
    assert uses["APP_FLAG"].required is True


def test_secret_shapes() -> None:
    from bughunt.policy_scan import _looks_real_secret

    assert _looks_real_secret("TOKEN", "changeme") is False
    assert _looks_real_secret("TOKEN", "${TOKEN}") is False
    assert _looks_real_secret("TOKEN", "<insert>") is False
    assert _looks_real_secret("KEY", "sk-abcdefghijklmnop") is True
    assert _looks_real_secret("API_KEY", "a" * 32) is True
    assert _looks_real_secret("NAME", "short") is False


def test_parse_env_example_variants(tmp_path: Path) -> None:
    from bughunt.policy_scan import _parse_env_example, _parse_managed_keys

    assert _parse_env_example(tmp_path / "missing") == {}
    env = tmp_path / ".env.example"
    _ = env.write_text("# comment\n\nKEY=value\nBAD LINE\n")
    assert _parse_env_example(env) == {"KEY": "value"}
    assert _parse_managed_keys("", "B", "E") == set()
    text = "B\nA=1\n# C=2\nE"
    assert _parse_managed_keys(text, "B", "E") == {"A"}


def test_module_tokens() -> None:
    from bughunt.policy_scan import _module_tokens

    root = Path("/repo")
    assert "persistence" in _module_tokens(root / "src" / "persistence" / "db.py", root)


def test_ensure_env_example_round_trip(tmp_path: Path) -> None:
    from bughunt.policy_scan import ensure_env_example

    src = tmp_path / "src"
    src.mkdir()
    _ = (src / "cfg.py").write_text("import os\nHOST = os.environ['APP_HOST']\n")
    path, uses = ensure_env_example(tmp_path, ["src"])
    assert path is not None
    assert path.exists()
    assert [item.name for item in uses] == ["APP_HOST"]
    path2, _ = ensure_env_example(tmp_path, ["src"])
    assert path2 == path


def test_main_scans_source_and_tests(tmp_path: Path) -> None:
    from bughunt.policy_scan import main

    src = tmp_path / "src"
    src.mkdir()
    _ = (src / "a.py").write_text("X = 1\n")
    tests = tmp_path / "tests"
    _ = tests.mkdir()
    _ = (tests / "test_a.py").write_text("def test_x() -> None:\n    assert True\n")
    assert main(["--root", str(tmp_path)]) == 0


def test_files_skips_missing_and_non_python(tmp_path: Path) -> None:
    from bughunt.policy_scan import _files

    assert list(_files(tmp_path, ["no-such-dir"])) == []
    _ = (tmp_path / "notes.txt").write_text("hi")
    assert list(_files(tmp_path, ["."])) == []


def test_finally_jump_visitor_scopes() -> None:
    import ast

    from bughunt.policy_scan import _finally_jump_nodes

    tree = ast.parse(
        "def f():\n"
        + "    try:\n"
        + "        pass\n"
        + "    finally:\n"
        + "        for _ in range(2):\n"
        + "            break\n"
        + "        while True:\n"
        + "            continue\n"
        + "        def g():\n"
        + "            return 1\n"
        + "        async def h():\n"
        + "            return 2\n"
        + "        cb = lambda: 3\n"
        + "        class C:\n"
        + "            pass\n",
    )
    assert len(_finally_jump_nodes(tree)) == 2


def test_contradictory_string_concat_checks(tmp_path: Path) -> None:
    from bughunt.policy_scan import _scan_check_contradictions

    _ = (tmp_path / "ruff.toml").write_text('[lint]\nselect = ["ISC003"]\n')
    _ = (tmp_path / "basedpyrightconfig.json").write_text(
        '{"reportImplicitStringConcatenation": "error"}'
    )
    findings = _scan_check_contradictions(tmp_path)
    assert [item.code for item in findings] == ["BHPLC001"]


def test_scoped_side_is_quiet(tmp_path: Path) -> None:
    from bughunt.policy_scan import _scan_check_contradictions

    _ = (tmp_path / "ruff.toml").write_text(
        '[lint]\nselect = ["ALL"]\nignore = ["ISC003"]\n'
    )
    _ = (tmp_path / "basedpyrightconfig.json").write_text(
        '{"reportImplicitStringConcatenation": "error"}'
    )
    assert _scan_check_contradictions(tmp_path) == []


def test_booleaness_contradiction(tmp_path: Path) -> None:
    from bughunt.policy_scan import _scan_check_contradictions

    _ = (tmp_path / ".pylintrc").write_text(
        "[MESSAGES CONTROL]\nenable=use-implicit-booleaness-not-comparison-to-zero\n"
    )
    _ = (tmp_path / "pyrefly.toml").write_text("[errors]\nimplicit-bool = true\n")
    findings = _scan_check_contradictions(tmp_path)
    assert [item.code for item in findings] == ["BHPLC001"]


def test_no_configs_is_quiet(tmp_path: Path) -> None:
    from bughunt.policy_scan import _scan_check_contradictions

    assert _scan_check_contradictions(tmp_path) == []
