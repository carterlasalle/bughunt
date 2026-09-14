# Copyright (c) 2026 Carter LaSalle
"""Direct-verification gaps over the System IR graph (BHVERIFY001/BHIMPL001).

Two cheapest high-signal graph rules, computed from the cached System IR
export (see system_ir_adapter) instead of a second call-graph implementation:

BHVERIFY001 — transitive-only verification: a module-level public function
with no detected direct test whose callees are tested. Coverage here is
transitive: a dependency passing never proves the dependent. The finding
names the tested callees as evidence; "detected" is load-bearing because
SCC test linking is heuristic.

BHIMPL001 — hollow public surface: a module-level public function whose body
is a stub (pass/.../NotImplemented/constant) with no detected direct test.
Protocol/abstract/overload members are excluded: they are contracts, not
missing implementations.
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

STUB_RAISES = {"NotImplementedError"}


# trace:v1 id=impl.src-bughunt-verify-gaps.-load-graph work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _load_graph(root: Path) -> dict[str, object] | None:
    from bughunt.system_ir_adapter import export

    cache, error = export(root)
    if error is not None or cache is None:
        return None
    try:
        payload = json.loads(cache.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    data = payload.get("system_ir")
    return data if isinstance(data, dict) else None


# trace:v1 id=impl.src-bughunt-verify-gaps.-module-level work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _module_level(root: Path, file: str, line: object) -> bool:
    """True when the def opens at column 0 (not nested in another scope)."""
    if not isinstance(line, int):
        return False
    try:
        source = (root / file).read_text(errors="replace").splitlines()
    except OSError:
        return False
    if line < 1 or line > len(source):
        return False
    text = source[line - 1]
    return text.startswith(("def ", "async def "))


# trace:v1 id=impl.src-bughunt-verify-gaps.-stub-body work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _stub_body(root: Path, file: str, start: object, end: object) -> bool:
    """True when the body is pass/.../NotImplemented/constant only."""
    if not isinstance(start, int) or not isinstance(end, int):
        return False
    try:
        source = (root / file).read_text(errors="replace")
    except OSError:
        return False
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.lineno != start:
            continue
        for decorator in node.decorator_list:
            name = ""
            if isinstance(decorator, ast.Name):
                name = decorator.id
            elif isinstance(decorator, ast.Attribute):
                name = decorator.attr
            if name in {"abstractmethod", "overload", "abstractproperty"}:
                return False
        body = [stmt for stmt in node.body if not isinstance(stmt, ast.Expr)]
        if not body:
            doc = node.body and isinstance(node.body[0], ast.Expr)
            return bool(doc)
        if len(body) != 1:
            return False
        only = body[0]
        if isinstance(only, ast.Pass):
            return True
        if isinstance(only, ast.Expr) and isinstance(only.value, ast.Constant):
            return True
        if isinstance(only, ast.Raise):
            exc = only.exc
            if isinstance(exc, ast.Name) and exc.id in STUB_RAISES:
                return True
            if isinstance(exc, ast.Call):
                func = exc.func
                called = ""
                if isinstance(func, ast.Name):
                    called = func.id
                elif isinstance(func, ast.Attribute):
                    called = func.attr
                if called in STUB_RAISES:
                    return True
        if isinstance(only, ast.Return) and isinstance(only.value, ast.Constant):
            return True
        return False
    return False


# trace:v1 id=impl.src-bughunt-verify-gaps.-test-mentions work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _test_mentions(root: Path) -> set[tuple[str, str]]:
    """(module, name) pairs named in tests/ alongside a module import.

    SCC tested_by linking is heuristic and misses direct unit tests that
    import-then-call (the common white-box shape). A test file that imports
    the symbol's module and names the symbol is positive evidence of direct
    verification; only suppressions flow from this, never findings.
    """
    mentioned: set[tuple[str, str]] = set()
    test_dir = root / "tests"
    if not test_dir.is_dir():
        return mentioned
    for path in sorted(test_dir.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(errors="replace"))
        except (OSError, SyntaxError):
            continue
        imported: set[tuple[str, str]] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    imported.add((node.module, alias.asname or alias.name))
        names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        names |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        for module, name in imported:
            if name in names:
                mentioned.add((module, name))
    return mentioned


# trace:v1 id=impl.src-bughunt-verify-gaps.scan work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def scan(root: Path) -> list[dict[str, object]]:
    """Compute verification gaps from the cached System IR."""
    data = _load_graph(root)
    if not data:
        return []
    entities = data.get("entities", [])
    relationships = data.get("relationships", [])
    if not isinstance(entities, list) or not isinstance(relationships, list):
        return []
    tested: set[str] = set()
    calls: dict[str, set[str]] = {}
    for rel in relationships:
        if not isinstance(rel, dict):
            continue
        predicate = rel.get("predicate")
        if predicate == "tested_by" and isinstance(rel.get("subject"), str):
            tested.add(str(rel["subject"]))
        elif predicate == "calls":
            subject, target = rel.get("subject"), rel.get("object")
            if isinstance(subject, str) and isinstance(target, str):
                calls.setdefault(subject, set()).add(target)

    # trace:exempt reason=internal-detail
    def short_name(symbol_id: str) -> str:
        return symbol_id.rsplit("/", 1)[-1]

    # trace:exempt reason=internal-detail
    def module_of(file: str) -> str:
        stem = file[4:] if file.startswith("src/") else file
        return stem.removesuffix(".py").replace("/", ".")

    mentioned = _test_mentions(root)

    out: list[dict[str, object]] = []
    for entity in entities:
        if not isinstance(entity, dict) or entity.get("kind") != "symbol":
            continue
        symbol_id = entity.get("id")
        if not isinstance(symbol_id, str):
            continue
        attributes = entity.get("attributes", {})
        if not isinstance(attributes, dict):
            continue
        file = attributes.get("file")
        if not isinstance(file, str) or not file.startswith("src/"):
            continue
        name = short_name(symbol_id)
        if name.startswith(("_", "test")):
            continue
        if attributes.get("kind") not in ("function", "method"):
            continue
        if symbol_id in tested or (module_of(file), name) in mentioned:
            continue
        start = attributes.get("start_line")
        if not _module_level(root, file, start):
            continue
        line = start if isinstance(start, int) else 1
        tested_callees = sorted(
            short_name(target)
            for target in calls.get(symbol_id, set())
            if target in tested
        )
        if tested_callees:
            out.append(
                {
                    "tool": "verify-gaps",
                    "code": "BHVERIFY001",
                    "path": file,
                    "line": line,
                    "severity": "warning",
                    "message": (
                        f"`{name}` has no detected direct test; its verification "
                        f"is transitive through tested callees "
                        f"({', '.join(tested_callees[:5])})"
                    ),
                }
            )
            continue
        end = attributes.get("end_line")
        if _stub_body(root, file, start, end):
            out.append(
                {
                    "tool": "verify-gaps",
                    "code": "BHIMPL001",
                    "path": file,
                    "line": line,
                    "severity": "warning",
                    "message": (
                        f"`{name}` is a public stub with no detected direct "
                        "test; interface without verified implementation"
                    ),
                }
            )

    # trace:exempt reason=internal-detail
    def _sort_key(item: dict[str, object]) -> tuple[str, int]:
        line = item.get("line", 0)
        return (str(item["path"]), line if isinstance(line, int) else 0)

    return sorted(out, key=_sort_key)


# trace:v1 id=impl.src-bughunt-verify-gaps.main work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def main(argv: list[str] | None = None) -> int:
    args = list(argv or sys.argv[1:])
    if not args:
        print(json.dumps({"error": "root required"}))
        return 2
    root = Path(args.pop(0)).resolve()
    if not (root / ".scc").is_dir():
        print(json.dumps({"findings": [], "not_applicable": True}))
        return 0
    findings = scan(root)
    print(json.dumps({"findings": findings}))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
