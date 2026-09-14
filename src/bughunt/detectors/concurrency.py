# Copyright (c) 2026 Carter LaSalle
"""BHCONC001: shared-state multi-writer without synchronization.

Writers are file opens in write/append mode against literal paths and
stores to `global`-declared names. Entry points are thread/async task
spawns; reachability rides SCC call edges (depth-capped BFS). A writer
counts as synchronized when its body uses a lock context, acquire /
release calls, or a queues / executor submission boundary. Two
unsynchronized writers to one target from concurrent entries is the
finding — one writer, or synchronized writers, stay silent.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from ..graph.facts import GraphFacts


# trace:v1 id=impl.src-bughunt-detectors-concurrency.writer work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
@dataclass(slots=True)
class Writer:
    function: str
    file: str
    target: str
    lineno: int
    synchronized: bool = False


# trace:v1 id=impl.src-bughunt-detectors-concurrency.finding work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
@dataclass(slots=True)
class ConcurrencyFinding:
    code: str
    message: str
    file: str
    lineno: int
    confidence: float


_ENTRY_SHORTS = {"Thread", "create_task", "submit", "gather"}


# trace:v1 id=impl.src-bughunt-detectors-concurrency.-entry-targets work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _entry_targets(tree: ast.AST) -> set[str]:
    """Function names handed to thread/task spawns."""
    targets: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        short = (
            func.attr
            if isinstance(func, ast.Attribute)
            else (func.id if isinstance(func, ast.Name) else "")
        )
        if short not in _ENTRY_SHORTS:
            continue
        candidates: list[ast.expr] = list(node.args[:1])
        candidates.extend(
            keyword.value
            for keyword in node.keywords
            if keyword.arg in {"target", "fn", "func", "coro"}
        )
        for candidate in candidates:
            if isinstance(candidate, ast.Name):
                targets.add(candidate.id)
    return targets


# trace:v1 id=impl.src-bughunt-detectors-concurrency.-writers-in work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _writers_in(tree: ast.AST, rel: str) -> tuple[list[Writer], set[str]]:
    """Writers per function plus the file's entry targets."""
    writers: list[Writer] = []
    entries = _entry_targets(tree)
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        synchronized = _is_synchronized(node)
        globals_declared = {
            name
            for child in ast.walk(node)
            if isinstance(child, ast.Global)
            for name in child.names
        }
        for child in ast.walk(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
                child is not node
            ):
                continue
            if not isinstance(child, ast.Assign) or len(child.targets) != 1:
                continue
            target = child.targets[0]
            if isinstance(target, ast.Name) and target.id in globals_declared:
                writers.append(
                    Writer(
                        node.name,
                        rel,
                        f"global:{target.id}",
                        child.lineno,
                        synchronized,
                    )
                )
            if isinstance(child.value, ast.Call):
                path = _write_path(child.value)
                if path is not None and isinstance(target, ast.Name):
                    writers.append(
                        Writer(
                            node.name,
                            rel,
                            f"file:{path}",
                            child.lineno,
                            synchronized,
                        )
                    )
    return writers, entries


# trace:v1 id=impl.src-bughunt-detectors-concurrency.-is-synchronized work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _is_synchronized(node: ast.AST) -> bool:
    """Lock context, acquire/release, or queue boundary in scope."""
    for child in ast.walk(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
            child is not node
        ):
            continue
        if isinstance(child, ast.With):
            for item in child.items:
                text = ast.unparse(item.context_expr)
                if "lock" in text.lower() or "mutex" in text.lower():
                    return True
        if (
            isinstance(child, ast.Call)
            and isinstance(child.func, ast.Attribute)
            and child.func.attr in {"acquire", "release"}
        ):
            return True
    return False


# trace:v1 id=impl.src-bughunt-detectors-concurrency.-write-path work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _write_path(call: ast.Call) -> str | None:
    """Literal path opened for writing, else None (unresolvable stays silent)."""
    func = call.func
    if isinstance(func, ast.Name) and func.id == "open" and len(call.args) >= 2:
        path, mode = call.args[0], call.args[1]
    elif isinstance(func, ast.Attribute) and func.attr == "open" and call.args:
        path, mode = None, call.args[0]
    else:
        return None
    if not isinstance(mode, ast.Constant):
        return None
    if not str(mode.value).startswith(("w", "a", "x")):
        return None
    if path is None:
        return f"method:{ast.unparse(call.func)}"
    if not isinstance(path, ast.Constant) or not isinstance(path.value, str):
        return None
    return path.value


# trace:v1 id=impl.src-bughunt-detectors-concurrency.-reachable work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _reachable(facts: GraphFacts, entries: set[str], name: str) -> bool:
    """BFS from entry targets over SCC edges (depth ≤ 3)."""
    if name in entries:
        return True
    frontier = set(entries)
    seen = set(frontier)
    for _ in range(3):
        nxt: set[str] = set()
        for edge in facts.calls:
            if edge.caller.name.split(".")[-1] in frontier:
                short = edge.callee.name.split(".")[-1]
                if short == name:
                    return True
                if short not in seen:
                    seen.add(short)
                    nxt.add(short)
        frontier = nxt
    return False


# trace:v1 id=impl.src-bughunt-detectors-concurrency.scan work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def scan(
    root: Path, source_paths: list[str], facts: GraphFacts
) -> list[ConcurrencyFinding]:
    """Two unsynchronized concurrent writers to one target."""
    out: list[ConcurrencyFinding] = []
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
            writers, entries = _writers_in(tree, name)
            if not entries:
                continue
            by_target: dict[str, list[Writer]] = {}
            for writer in writers:
                if _reachable(facts, entries, writer.function):
                    by_target.setdefault(writer.target, []).append(writer)
            for target, group in by_target.items():
                live = [w for w in group if not w.synchronized]
                if len({w.function for w in live}) >= 2:
                    first = min(live, key=lambda w: w.lineno)
                    out.append(
                        ConcurrencyFinding(
                            code="BHCONC001",
                            message=(
                                f"shared-state multi-writer: {target} written "
                                f"by {sorted({w.function for w in live})} "
                                "reachable from thread/task entries with no "
                                "lock, transaction, or queue serialization"
                            ),
                            file=name,
                            lineno=first.lineno,
                            confidence=0.70,
                        )
                    )
    return out
