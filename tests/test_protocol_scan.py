# Copyright (c) 2026 Carter LaSalle
"""Protocol rules: assert misuse, async magic, generator magic, next()."""

from pathlib import Path


def _scan(tmp_path: Path, source: str):
    from bughunt.protocol_scan import scan

    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    _ = (src / "proto.py").write_text(source)
    return scan(tmp_path, ["src"])


def test_assert_exception_is_misuse(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "def check(x):\n"
        + "    assert x > 0, ValueError('bad')\n"
        + "    assert x, 'message is fine'\n",
    )
    assert [item.code for item in findings] == ["BHPRT001"]


def test_async_magic_method(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "class A:\n"
        + "    async def __len__(self):\n"
        + "        return 0\n"
        + "    async def __aenter__(self):\n"
        + "        return self\n",
    )
    assert [item.code for item in findings] == ["BHPRT002"]


def test_yield_in_non_iterator_magic(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "class A:\n"
        + "    def __len__(self):\n"
        + "        yield 1\n"
        + "    def __iter__(self):\n"
        + "        yield 1\n",
    )
    assert [item.code for item in findings] == ["BHPRT003"]


def test_enter_raise_is_not_flagged(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "class A:\n"
        + "    def __enter__(self):\n"
        + "        raise NotImplementedError('subclass me')\n",
    )
    assert findings == []


def test_unguarded_next_in_generator(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "def gen(items):\n"
        + "    it = iter(items)\n"
        + "    while True:\n"
        + "        try:\n"
        + "            yield next(it)\n"
        + "        except StopIteration:\n"
        + "            return\n"
        + "    yield next(iter([1]), None)\n",
    )
    assert findings == []


def test_bare_next_is_flagged(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "def gen(items):\n"
        + "    it = iter(items)\n"
        + "    yield next(it)\n"
        + "    yield 1\n",
    )
    assert [item.code for item in findings] == ["BHPRT004"]


def test_main_gates(monkeypatch, tmp_path: Path, capsys) -> None:
    import json
    import sys

    from bughunt.protocol_scan import main

    monkeypatch.setattr(sys, "argv", ["bughunt-protocol"])
    assert main([]) == 2
    assert "root required" in capsys.readouterr().out
    _ = (tmp_path / "src").mkdir()
    assert main([str(tmp_path), "src"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload == []


# trace:v1 id=test.tests-test-protocol-scan.test-nested-and-attribute-shapes work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_nested_and_attribute_shapes(tmp_path: Path) -> None:
    import ast

    from bughunt.protocol_scan import _exc_name, scan

    src = tmp_path / "src"
    node = ast.parse("mod.Broken('x')").body[0]
    assert isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
    assert _exc_name(node.value) == "Broken"
    func = node.value.func
    assert isinstance(func, ast.Attribute)
    assert _exc_name(func) == "Broken"
    src.mkdir(exist_ok=True)
    _ = (src / "broken.py").write_text("def (:\n")
    _ = (src / "gen.py").write_text(
        "class G:\n"
        "    def __iter__(self):\n"
        "        def inner():\n"
        "            try:\n"
        "                x = next(it)\n"
        "            except StopIteration:\n"
        "                return\n"
        "            yield x\n"
        "        yield from inner()\n"
        "\n\ndef plain():\n"
        "    try:\n"
        "        a = next(it)\n"
        "    except StopIteration:\n"
        "        raise RuntimeError('x')\n"
        "    try:\n"
        "        b = next(it)\n"
        "    except ValueError:\n"
        "        pass\n"
        "    return a, b\n"
    )
    findings = scan(tmp_path, ["src"])
    assert isinstance(findings, list)
