# Copyright (c) 2026 Carter LaSalle
"""Protocol-correctness rules: magic methods, generators, assert misuse.

Concept ports of DeepSource Python Bug Risk semantics (recorded per rule,
implementation is original; no proprietary source copied):

- BHPRT001 (PTC-W0032): `assert cond, ValueError(...)` never raises
  ValueError — assert raises AssertionError with the exception as its
  message. A string message is fine; an exception instance/class is a bug.
- BHPRT002 (PTC-W0045): `async def` on a synchronous-protocol magic method.
  Only __aenter__/__aexit__/__aiter__/__anext__ may be async.
- BHPRT003 (PTC-W0059): `yield` inside a magic method that must not become
  a generator. __iter__ and __await__ are generator-based by design and are
  excluded; __len__/__contains__/__enter__/__bool__ and friends must not yield.
- BHPRT004 (PTC-W0063): bare single-argument `next()` inside a generator
  with no StopIteration guard turns exhaustion into RuntimeError (PEP 479).
"""

from __future__ import annotations

import ast
import json
import sys
from dataclasses import dataclass
from pathlib import Path

ASYNC_DUNDER = {"__aenter__", "__aexit__", "__aiter__", "__anext__"}
GENERATOR_DUNDER = {"__iter__", "__await__"}


# trace:v1 id=impl.src-bughunt-protocol-scan.-finding work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
@dataclass(slots=True)
class ProtocolFinding:
    code: str
    message: str
    path: str
    line: int
    severity: str = "warning"


# trace:v1 id=impl.src-bughunt-protocol-scan.-exc-name work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _exc_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _exc_name(node.func)
    return None


# trace:v1 id=impl.src-bughunt-protocol-scan.-is-magic work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _is_magic(name: str) -> bool:
    return name.startswith("__") and name.endswith("__") and len(name) > 4


# trace:v1 id=impl.src-bughunt-protocol-scan.-assert-misuse work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _assert_misuse(tree: ast.AST, rel: str) -> list[ProtocolFinding]:
    out: list[ProtocolFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assert) or node.msg is None:
            continue
        name = _exc_name(node.msg)
        if name and (name.endswith(("Error", "Exception", "Warning", "BaseException"))):
            out.append(
                ProtocolFinding(
                    "BHPRT001",
                    f"assert carries exception `{name}` as its message; assert "
                    "raises AssertionError, never the carried exception — "
                    + "raise explicitly",
                    rel,
                    node.lineno,
                    "error",
                )
            )
    return out


# trace:v1 id=impl.src-bughunt-protocol-scan.-async-magic work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _async_magic(tree: ast.AST, rel: str) -> list[ProtocolFinding]:
    out: list[ProtocolFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.AsyncFunctionDef):
            continue
        if _is_magic(node.name) and node.name not in ASYNC_DUNDER:
            out.append(
                ProtocolFinding(
                    "BHPRT002",
                    f"magic method `{node.name}` declared async; the "
                    + "synchronous protocol will receive a coroutine, not a value",
                    rel,
                    node.lineno,
                    "error",
                )
            )
    return out


# trace:v1 id=impl.src-bughunt-protocol-scan.-generator-magic work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _generator_magic(tree: ast.AST, rel: str) -> list[ProtocolFinding]:
    out: list[ProtocolFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or not _is_magic(node.name):
            continue
        if node.name in GENERATOR_DUNDER:
            continue
        nested: list[ast.AST] = [
            child
            for child in ast.walk(node)
            if child is not node
            and isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        nested_ids = {id(child) for child in nested}
        for child in ast.walk(node):
            if id(child) in nested_ids:
                continue
            if isinstance(child, (ast.Yield, ast.YieldFrom)):
                out.append(
                    ProtocolFinding(
                        "BHPRT003",
                        f"`yield` inside magic method `{node.name}` turns it "
                        + "into a generator; the protocol receives an iterator, "
                        "not the required value",
                        rel,
                        child.lineno,
                        "error",
                    )
                )
                break
    return out


# trace:v1 id=impl.src-bughunt-protocol-scan.-unguarded-next work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _unguarded_next(tree: ast.AST, rel: str) -> list[ProtocolFinding]:
    out: list[ProtocolFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not any(
            isinstance(child, (ast.Yield, ast.YieldFrom)) for child in ast.walk(node)
        ):
            continue
        guarded: list[ast.Try] = []

        # trace:exempt reason=internal-detail
        def _collect(current: ast.AST) -> None:
            for child in ast.iter_child_nodes(current):
                if isinstance(child, ast.Try):
                    guarded.append(child)
                elif not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    _collect(child)

        _collect(node)
        safe_lines: set[int] = set()
        for attempt in guarded:
            handles_stop = any(
                isinstance(handler.type, ast.Name)
                and handler.type.id
                in {"StopIteration", "RuntimeError", "Exception", "BaseException"}
                or handler.type is None
                for handler in attempt.handlers
            )
            if handles_stop:
                for child in ast.walk(attempt):
                    if isinstance(child, ast.Call):
                        lineno = getattr(child, "lineno", 0)
                        safe_lines.add(lineno)
        for child in ast.walk(node):
            if (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Name)
                and child.func.id == "next"
                and len(child.args) == 1
                and getattr(child, "lineno", 0) not in safe_lines
            ):
                out.append(
                    ProtocolFinding(
                        "BHPRT004",
                        "unguarded single-argument `next()` inside a generator; "
                        + "exhaustion raises StopIteration, which becomes "
                        "RuntimeError (PEP 479) — pass a default or guard it",
                        rel,
                        child.lineno,
                        "error",
                    )
                )
    return out


# trace:v1 id=impl.src-bughunt-protocol-scan.-ordered-stmts work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _ordered_stmts(stmts: list[ast.stmt]) -> list[ast.stmt]:
    out: list[ast.stmt] = []
    for stmt in stmts:
        out.append(stmt)
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for child in ast.iter_child_nodes(stmt):
            if isinstance(child, ast.stmt):
                out.extend(_ordered_stmts([child]))
    return out


# trace:v1 id=impl.src-bughunt-protocol-scan.-own work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _own(node: ast.AST) -> list[ast.AST]:
    """A statement's own effects: skip nested statement subtrees."""
    found: list[ast.AST] = [node]
    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.stmt):
            continue
        found.extend(_own(child))
    return found


# trace:v1 id=impl.src-bughunt-protocol-scan.-open-mode work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _open_mode(call: ast.Call) -> str:
    """Effective open() mode: keyword, method-arg, or builtin-arg position."""
    for keyword in call.keywords:
        if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant):
            return str(keyword.value.value)
    index = 0 if isinstance(call.func, ast.Attribute) else 1
    if len(call.args) > index:
        candidate = call.args[index]
        if isinstance(candidate, ast.Constant):
            return str(candidate.value)
    return "r"


# trace:v1 id=impl.src-bughunt-protocol-scan.-file-state work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _file_state(tree: ast.AST, rel: str) -> list[ProtocolFinding]:
    """BHPRT005/006: use-after-close and open-mode mismatch (PTC-W0021/22)."""
    out: list[ProtocolFinding] = []
    write_only = {"w", "wb", "a", "ab", "x", "xb"}
    read_only = {"r", "rb"}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        closed: set[str] = set()
        modes: dict[str, str] = {}
        for stmt in _ordered_stmts(node.body):
            for child in _own(stmt):
                if isinstance(child, ast.Assign) and len(child.targets) == 1:
                    target = child.targets[0]
                    if isinstance(target, ast.Name) and isinstance(
                        child.value, ast.Call
                    ):
                        func = child.value.func
                        called = (
                            func.attr
                            if isinstance(func, ast.Attribute)
                            else (func.id if isinstance(func, ast.Name) else "")
                        )
                        if called == "open":
                            modes[target.id] = _open_mode(child.value)
                            closed.discard(target.id)
                if isinstance(child, ast.With):
                    for item in child.items:
                        if isinstance(item.optional_vars, ast.Name) and isinstance(
                            item.context_expr, ast.Call
                        ):
                            func = item.context_expr.func
                            called = (
                                func.attr if isinstance(func, ast.Attribute) else ""
                            )
                            if called == "open":
                                modes[item.optional_vars.id] = _open_mode(
                                    item.context_expr
                                )
                if isinstance(child, ast.Call) and isinstance(
                    child.func, ast.Attribute
                ):
                    receiver = child.func.value
                    if isinstance(receiver, ast.Name):
                        if child.func.attr == "close":
                            closed.add(receiver.id)
                        elif receiver.id in closed:
                            out.append(
                                ProtocolFinding(
                                    "BHPRT005",
                                    f"`{receiver.id}.{child.func.attr}()` after "
                                    "`close()`; the stream is shut down",
                                    rel,
                                    child.lineno,
                                    "error",
                                )
                            )
                        else:
                            current = modes.get(receiver.id)
                            if current in write_only and child.func.attr in {
                                "read",
                                "readline",
                                "readlines",
                            }:
                                out.append(
                                    ProtocolFinding(
                                        "BHPRT006",
                                        f"`{receiver.id}` opened with mode "
                                        f"`{current}`; read operations are invalid",
                                        rel,
                                        child.lineno,
                                        "error",
                                    )
                                )
                            elif current in read_only and child.func.attr in {
                                "write",
                                "writelines",
                            }:
                                out.append(
                                    ProtocolFinding(
                                        "BHPRT006",
                                        f"`{receiver.id}` opened with mode "
                                        f"`{current}`; write operations are invalid",
                                        rel,
                                        child.lineno,
                                        "error",
                                    )
                                )
    return out


REFLECTIVE_DUNDER = frozenset(
    {
        "__eq__",
        "__ne__",
        "__lt__",
        "__le__",
        "__gt__",
        "__ge__",
        "__add__",
        "__radd__",
        "__sub__",
        "__mul__",
        "__rmul__",
        "__and__",
        "__rand__",
        "__or__",
        "__ror__",
        "__xor__",
    }
)


# trace:v1 id=impl.src-bughunt-protocol-scan.-notimplemented-error work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _notimplemented_error(tree: ast.AST, rel: str) -> list[ProtocolFinding]:
    """BHPRT007: raise NotImplementedError where NotImplemented is due."""
    out: list[ProtocolFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name not in REFLECTIVE_DUNDER:
            continue
        for child in ast.walk(node):
            if not isinstance(child, ast.Raise) or child.exc is None:
                continue
            name = _exc_name(child.exc)
            if name == "NotImplementedError":
                out.append(
                    ProtocolFinding(
                        "BHPRT007",
                        f"reflective `{node.name}` raises NotImplementedError; "
                        "return NotImplemented for unknown operand types so "
                        "Python can try the reflected operation",
                        rel,
                        child.lineno,
                        "error",
                    )
                )
                break
    return out


# trace:v1 id=impl.src-bughunt-protocol-scan.-overwrite-before-read work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _overwrite_before_read(tree: ast.AST, rel: str) -> list[ProtocolFinding]:
    """BHPRT008: subscript stored twice with no load between (PTC-W0057).

    Conservative by design: only constant slices (``d["k"] = a``) in the
    same statement block. Variable keys need value analysis, and stores
    in exclusive branches (if/else) are not dead — both limitations
    stay silent instead of firing.
    """
    out: list[ProtocolFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for block in _blocks(node.body):
            pending: dict[tuple[str, str], int] = {}
            for stmt in block:
                store_bases = {
                    target.value.id
                    for child in ast.walk(stmt)
                    if isinstance(child, ast.Assign)
                    for target in child.targets
                    if isinstance(target, ast.Subscript)
                    and isinstance(target.value, ast.Name)
                }
                for child in ast.walk(stmt):
                    if child is not stmt and isinstance(child, ast.stmt):
                        continue
                    if (
                        isinstance(child, ast.Subscript)
                        and isinstance(child.ctx, ast.Load)
                        and isinstance(child.value, ast.Name)
                        and isinstance(child.slice, ast.Constant)
                    ):
                        pending.pop((child.value.id, repr(child.slice.value)), None)
                    if (
                        isinstance(child, ast.Name)
                        and isinstance(child.ctx, ast.Load)
                        and child.id not in store_bases
                    ):
                        for key in [k for k in pending if k[0] == child.id]:
                            del pending[key]
                    if isinstance(child, ast.Assign) and len(child.targets) == 1:
                        target = child.targets[0]
                        if (
                            isinstance(target, ast.Subscript)
                            and isinstance(target.value, ast.Name)
                            and isinstance(target.slice, ast.Constant)
                        ):
                            key = (target.value.id, repr(target.slice.value))
                            if key in pending:
                                out.append(
                                    ProtocolFinding(
                                        "BHPRT008",
                                        "subscript value overwritten before the "
                                        "previous value was ever read; the first "
                                        "store is dead",
                                        rel,
                                        pending[key],
                                        "warning",
                                    )
                                )
                            pending[key] = child.lineno
    return out


# trace:v1 id=impl.src-bughunt-protocol-scan.-blocks work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _blocks(stmts: list[ast.stmt]) -> list[list[ast.stmt]]:
    """Statement blocks: each compound body analyzed independently."""
    groups: list[list[ast.stmt]] = [[]]
    for stmt in stmts:
        groups[-1].append(stmt)
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for child in ast.iter_child_nodes(stmt):
            if isinstance(child, ast.stmt):
                groups.extend(_blocks([child]))
    return [group for group in groups if group]


# trace:v1 id=impl.src-bughunt-protocol-scan.-empty-testcase work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _empty_testcase(tree: ast.AST, rel: str) -> list[ProtocolFinding]:
    """BHPRT009: TestCase subclass with no test methods (PTC-W0046)."""
    out: list[ProtocolFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        bases = [
            base.attr if isinstance(base, ast.Attribute) else "" for base in node.bases
        ] + [base.id if isinstance(base, ast.Name) else "" for base in node.bases]
        if "TestCase" not in bases:
            continue
        methods = [
            stmt.name
            for stmt in node.body
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        if methods and not any(name.startswith("test") for name in methods):
            out.append(
                ProtocolFinding(
                    "BHPRT009",
                    f"TestCase `{node.name}` defines methods but no tests; "
                    "the suite silently covers nothing",
                    rel,
                    node.lineno,
                    "warning",
                )
            )
    return out


# trace:v1 id=impl.src-bughunt-protocol-scan.-hypot work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _hypot(tree: ast.AST, rel: str) -> list[ProtocolFinding]:
    """BHPRT010: unstable sqrt(x**2 + y**2); use math.hypot (PTC-W0028)."""
    out: list[ProtocolFinding] = []

    # trace:v1 id=impl.src-bughunt-protocol-scan-hypot.is-square work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    def _is_square(node: ast.AST) -> bool:
        return (
            isinstance(node, ast.BinOp)
            and isinstance(node.op, ast.Pow)
            and isinstance(node.right, ast.Constant)
            and node.right.value in (2, 2.0)
        )

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or len(node.args) != 1:
            continue
        func = node.func
        called = (
            func.attr
            if isinstance(func, ast.Attribute)
            else (func.id if isinstance(func, ast.Name) else "")
        )
        if called != "sqrt":
            continue
        arg = node.args[0]
        if (
            isinstance(arg, ast.BinOp)
            and isinstance(arg.op, ast.Add)
            and _is_square(arg.left)
            and _is_square(arg.right)
        ):
            out.append(
                ProtocolFinding(
                    "BHPRT010",
                    "sqrt(x**2 + y**2) overflows/underflows where "
                    "math.hypot stays stable",
                    rel,
                    node.lineno,
                    "warning",
                )
            )
    return out


# trace:v1 id=impl.src-bughunt-protocol-scan.-json-idiom work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _json_idiom(tree: ast.AST, rel: str) -> list[ProtocolFinding]:
    """BHPRT011: json.loads(f.read()) / f.write(json.dumps(x)) (PY-W0078/79)."""
    out: list[ProtocolFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        called = (
            func.attr
            if isinstance(func, ast.Attribute)
            else (func.id if isinstance(func, ast.Name) else "")
        )
        if called == "loads" and len(node.args) == 1:
            inner = node.args[0]
            if (
                isinstance(inner, ast.Call)
                and isinstance(inner.func, ast.Attribute)
                and inner.func.attr == "read"
            ):
                out.append(
                    ProtocolFinding(
                        "BHPRT011",
                        "json.loads(file.read()) buffers the whole stream; "
                        "json.load(file) streams it",
                        rel,
                        node.lineno,
                        "warning",
                    )
                )
        if called == "write" and len(node.args) == 1:
            inner = node.args[0]
            if (
                isinstance(inner, ast.Call)
                and isinstance(inner.func, ast.Attribute)
                and inner.func.attr == "dumps"
            ):
                out.append(
                    ProtocolFinding(
                        "BHPRT011",
                        "file.write(json.dumps(x)) buffers the whole payload; "
                        "json.dump(x, file) streams it",
                        rel,
                        node.lineno,
                        "warning",
                    )
                )
    return out


# trace:v1 id=impl.src-bughunt-protocol-scan.-imports-module work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _imports_module(tree: ast.AST, prefix: str) -> bool:
    """True when the file imports the framework (gating signal)."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(
                alias.name == prefix or alias.name.startswith(prefix + ".")
                for alias in node.names
            ):
                return True
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.module == prefix or node.module.startswith(prefix + "."):
                return True
    return False


# trace:v1 id=impl.src-bughunt-protocol-scan.-sqlalchemy-bool work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _sqlalchemy_bool(tree: ast.AST, rel: str) -> list[ProtocolFinding]:
    """BHPRT012: Python and/or on SQLAlchemy expressions (PY-W0800)."""
    out: list[ProtocolFinding] = []
    if not _imports_module(tree, "sqlalchemy"):
        return out
    for node in ast.walk(tree):
        if not isinstance(node, ast.BoolOp):
            continue
        if any(isinstance(value, ast.Compare) for value in node.values):
            keyword = "and" if isinstance(node.op, ast.And) else "or"
            out.append(
                ProtocolFinding(
                    "BHPRT012",
                    f"SQLAlchemy expression combined with Python `{keyword}`; "
                    "it evaluates eagerly instead of composing SQL — use "
                    "`&` / `|` (or `and_` / `or_`)",
                    rel,
                    node.lineno,
                    "error",
                )
            )
    return out


# trace:v1 id=impl.src-bughunt-protocol-scan.-django-fields work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _django_fields(tree: ast.AST, rel: str) -> list[ProtocolFinding]:
    """BHPRT013/14/15: Django field-semantics (PTC-W0905/02/08)."""
    out: list[ProtocolFinding] = []
    if not _imports_module(tree, "django"):
        return out
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        called = (
            func.attr
            if isinstance(func, ast.Attribute)
            else (func.id if isinstance(func, ast.Name) else "")
        )
        keywords = {kw.arg: kw.value for kw in node.keywords if kw.arg is not None}

        # trace:v1 id=impl.src-bughunt-protocol-scan-django-fields.is-true work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
        def _is_true(value: ast.AST) -> bool:
            return isinstance(value, ast.Constant) and value.value is True

        if (
            called == "ManyToManyField"
            and "null" in keywords
            and _is_true(keywords["null"])
        ):
            out.append(
                ProtocolFinding(
                    "BHPRT013",
                    "null=True on ManyToManyField has no effect; the "
                    "relation table carries no column to null",
                    rel,
                    node.lineno,
                    "error",
                )
            )
        if (
            "primary_key" in keywords
            and _is_true(keywords["primary_key"])
            and "unique" in keywords
            and _is_true(keywords["unique"])
        ):
            out.append(
                ProtocolFinding(
                    "BHPRT014",
                    "primary_key=True already implies uniqueness; "
                    "unique=True is redundant",
                    rel,
                    node.lineno,
                    "warning",
                )
            )
        for marker in ("unique_for_date", "unique_for_month", "unique_for_year"):
            if marker in keywords:
                out.append(
                    ProtocolFinding(
                        "BHPRT015",
                        f"{marker} is application-level validation, not a "
                        "database uniqueness constraint; concurrent writes "
                        "can violate it",
                        rel,
                        node.lineno,
                        "warning",
                    )
                )
    return out


# trace:v1 id=impl.src-bughunt-protocol-scan.scan work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def scan(root: Path, source_paths: list[str]) -> list[ProtocolFinding]:
    findings: list[ProtocolFinding] = []
    for rel in source_paths:
        base = root / rel
        paths = (
            [base]
            if base.is_file()
            else list(base.rglob("*.py"))
            if base.is_dir()
            else []
        )
        for path in paths:
            try:
                tree = ast.parse(path.read_text(errors="replace"))
            except (OSError, SyntaxError):
                continue
            name = path.relative_to(root).as_posix()
            findings.extend(_assert_misuse(tree, name))
            findings.extend(_async_magic(tree, name))
            findings.extend(_generator_magic(tree, name))
            findings.extend(_unguarded_next(tree, name))
            findings.extend(_file_state(tree, name))
            findings.extend(_notimplemented_error(tree, name))
            findings.extend(_overwrite_before_read(tree, name))
            findings.extend(_empty_testcase(tree, name))
            findings.extend(_hypot(tree, name))
            findings.extend(_json_idiom(tree, name))
            findings.extend(_sqlalchemy_bool(tree, name))
            findings.extend(_django_fields(tree, name))
    return sorted(findings, key=lambda item: (item.path, item.line, item.code))


# trace:v1 id=impl.src-bughunt-protocol-scan.main work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def main(argv: list[str] | None = None) -> int:
    args = list(argv or sys.argv[1:])
    if not args:
        print(json.dumps({"error": "root required"}))
        return 2
    root = Path(args.pop(0)).resolve()
    paths = args or ["src"]
    findings = scan(root, paths)
    print(
        json.dumps(
            [
                {
                    "tool": "protocol",
                    "code": item.code,
                    "path": item.path,
                    "line": item.line,
                    "message": item.message,
                    "severity": item.severity,
                }
                for item in findings
            ]
        )
    )
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
