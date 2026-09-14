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
