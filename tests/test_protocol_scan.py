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


# trace:v1 id=test.tests-test-protocol-scan.test-use-after-close work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_use_after_close(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "def f(p):\n"
        + "    f = open(p)\n"
        + "    f.close()\n"
        + "    return f.read()\n"
        + "def g(p):\n"
        + "    f = open(p)\n"
        + "    return f.read()\n",
    )
    assert [item.code for item in findings] == ["BHPRT005"]


# trace:v1 id=test.tests-test-protocol-scan.test-open-mode-mismatch work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_open_mode_mismatch(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "def f(p):\n"
        + "    f = open(p, 'r')\n"
        + "    f.write('x')\n"
        + "def g(p):\n"
        + "    with open(p, 'w') as h:\n"
        + "        h.write('x')\n",
    )
    assert [item.code for item in findings] == ["BHPRT006"]


# trace:v1 id=test.tests-test-protocol-scan.test-reflective-raise work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_reflective_raise(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "class A:\n"
        + "    def __eq__(self, other):\n"
        + "        raise NotImplementedError(other)\n"
        + "    def __init__(self):\n"
        + "        raise NotImplementedError\n",
    )
    assert [item.code for item in findings] == ["BHPRT007"]


# trace:v1 id=test.tests-test-protocol-scan.test-overwrite-before-read work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_overwrite_before_read(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "def f(d):\n"
        + "    d['k'] = expensive()\n"
        + "    d['k'] = other()\n"
        + "    return d\n"
        + "def g(d, k):\n"
        + "    d[k] = 1\n"
        + "    d[k] = 2\n"
        + "    return d\n"
        + "def h(d):\n"
        + "    d['k'] = 1\n"
        + "    print(d['k'])\n"
        + "    d['k'] = 2\n"
        + "    return d\n"
        + "def i(d, flag):\n"
        + "    d['k'] = 1\n"
        + "    if flag:\n"
        + "        d['k'] = 2\n"
        + "    return d\n",
    )
    assert [item.code for item in findings] == ["BHPRT008"]


# trace:v1 id=test.tests-test-protocol-scan.test-empty-testcase work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_empty_testcase(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "import unittest\n"
        + "class T(unittest.TestCase):\n"
        + "    def setUp(self):\n"
        + "        pass\n"
        + "class U(unittest.TestCase):\n"
        + "    def test_x(self):\n"
        + "        pass\n",
    )
    assert [item.code for item in findings] == ["BHPRT009"]


# trace:v1 id=test.tests-test-protocol-scan.test-hypot work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_hypot(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "import math\n"
        + "def f(x, y):\n"
        + "    return math.sqrt(x**2 + y**2)\n"
        + "def g(x, y):\n"
        + "    return math.hypot(x, y)\n",
    )
    assert [item.code for item in findings] == ["BHPRT010"]


# trace:v1 id=test.tests-test-protocol-scan.test-json-idiom work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_json_idiom(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "import json\n"
        + "def f(fh):\n"
        + "    return json.loads(fh.read())\n"
        + "def g(fh, x):\n"
        + "    fh.write(json.dumps(x))\n"
        + "def h(fh):\n"
        + "    return json.load(fh)\n",
    )
    assert [item.code for item in findings] == ["BHPRT011", "BHPRT011"]


# trace:v1 id=test.tests-test-protocol-scan.test-sqlalchemy-bool work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_sqlalchemy_bool(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "import sqlalchemy\n"
        + "def f(q, a, b):\n"
        + "    return q.filter(a == 1 and b == 2)\n"
        + "def g(a, b):\n"
        + "    return a and b\n",
    )
    assert [item.code for item in findings] == ["BHPRT012"]


# trace:v1 id=test.tests-test-protocol-scan.test-django-fields work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_django_fields(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "from django.db import models\n"
        + "class M(models.Model):\n"
        + "    tags = models.ManyToManyField('T', null=True)\n"
        + "    code = models.CharField(max_length=8, primary_key=True, unique=True)\n"
        + "    slug = models.SlugField(unique_for_date='pub')\n"
        + "    name = models.CharField(max_length=8)\n",
    )
    assert [item.code for item in findings] == ["BHPRT013", "BHPRT014", "BHPRT015"]


# trace:v1 id=test.tests-test-protocol-scan.test-framework-gating work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_framework_gating(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "def f(q, a, b):\n"
        + "    return q.filter(a == 1 and b == 2)\n"
        + "tags = True\n",
    )
    assert findings == []
