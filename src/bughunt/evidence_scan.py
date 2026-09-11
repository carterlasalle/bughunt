from __future__ import annotations

import ast
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

IGNORED = {".git", ".venv", "venv", ".bughunt", "node_modules", "build", "dist", "__pycache__", "site-packages", "mutants"}


@dataclass(frozen=True, slots=True)
class EvidenceFinding:
    code: str
    message: str
    path: str
    line: int
    severity: str = "warning"


def _files(root: Path, paths: Iterable[str]) -> Iterable[Path]:
    seen: set[Path] = set()
    for rel in paths:
        base = root / rel
        candidates = [base] if base.is_file() and base.suffix == ".py" else base.rglob("*.py") if base.is_dir() else []
        for path in candidates:
            if path in seen or any(part in IGNORED for part in path.parts):
                continue
            seen.add(path)
            yield path


def _name(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Subscript):
        return _name(node.value)
    return ""


def _annotation(node: ast.AST | None) -> str:
    try:
        return ast.unparse(node) if node is not None else ""
    except Exception:
        return ""


def _is_broad(annotation: str) -> bool:
    compact = annotation.replace(" ", "")
    return compact in {"Any", "typing.Any", "object", "builtins.object"} or "Any" in compact and compact.startswith(("dict[", "Mapping[", "MutableMapping["))


def _function_findings(node: ast.FunctionDef | ast.AsyncFunctionDef, rel: str) -> list[EvidenceFinding]:
    out: list[EvidenceFinding] = []
    known: dict[str, str] = {}
    widened_from: dict[str, tuple[str, str, int]] = {}
    for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]:
        ann = _annotation(arg.annotation)
        if ann:
            known[arg.arg] = ann

    for child in ast.walk(node):
        if isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name):
            ann = _annotation(child.annotation)
            if isinstance(child.value, ast.Name) and _is_broad(ann):
                source_ann = known.get(child.value.id)
                if source_ann and not _is_broad(source_ann):
                    widened_from[child.target.id] = (child.value.id, source_ann, child.lineno)
            if ann:
                known[child.target.id] = ann
        if isinstance(child, ast.Call) and _name(child.func).rsplit(".", 1)[-1] == "cast" and len(child.args) >= 2:
            target_ann = _annotation(child.args[0])
            value = child.args[1]
            if isinstance(value, ast.Call) and _name(value.func).rsplit(".", 1)[-1] == "cast":
                out.append(EvidenceFinding(
                    "BHEVID002",
                    f"chained cast reconstructs type evidence through multiple assertions (`{target_ann}` outside another cast); preserve/narrow the original contract instead",
                    rel, child.lineno, "warning",
                ))
            if isinstance(value, ast.Name) and value.id in widened_from:
                src, src_ann, line = widened_from[value.id]
                out.append(EvidenceFinding(
                    "BHEVID001",
                    f"`{src}` had known type `{src_ann}`, was widened into `{value.id}`, then cast back to `{target_ann}`; this erases static evidence at the seam",
                    rel, child.lineno, "error",
                ))

    # Growing accumulator copies are often accidental quadratic work. Require a
    # loop and self-reference so ordinary immutable-expression code is ignored.
    for loop in ast.walk(node):
        if not isinstance(loop, (ast.For, ast.AsyncFor, ast.While)):
            continue
        for child in ast.walk(loop):
            if not isinstance(child, (ast.Assign, ast.AugAssign)):
                continue
            target: ast.AST | None = child.target if isinstance(child, ast.AugAssign) else child.targets[0] if len(child.targets) == 1 else None
            value = child.value
            if not isinstance(target, ast.Name):
                continue
            acc = target.id
            copies = False
            if isinstance(value, ast.BinOp) and isinstance(value.op, (ast.Add, ast.BitOr)) and (
                isinstance(value.left, ast.Name) and value.left.id == acc or isinstance(value.right, ast.Name) and value.right.id == acc
            ):
                copies = True
            elif isinstance(value, ast.Dict) and any(isinstance(v, ast.Name) and v.id == acc for v in value.values):
                copies = True
            elif isinstance(value, ast.Call) and _name(value.func) in {"list", "dict", "set", "tuple"} and value.args and isinstance(value.args[0], ast.Name) and value.args[0].id == acc:
                copies = True
            if copies:
                out.append(EvidenceFinding(
                    "BHEVID003",
                    f"loop repeatedly copies growing accumulator `{acc}`; this can turn linear work quadratic and hide a performance bug",
                    rel, child.lineno, "warning",
                ))
    return out


def scan(root: Path, paths: Iterable[str]) -> list[EvidenceFinding]:
    findings: list[EvidenceFinding] = []
    for path in _files(root, paths):
        try:
            tree = ast.parse(path.read_text(errors="replace"), filename=str(path))
        except (OSError, SyntaxError):
            continue
        rel = path.resolve(strict=False).relative_to(root.resolve(strict=False)).as_posix()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(_function_findings(node, rel))
    # AST walking nested functions can duplicate findings; stable semantic dedup.
    dedup = {(f.code, f.path, f.line, f.message): f for f in findings}
    return sorted(dedup.values(), key=lambda f: (f.path, f.line, f.code))


def main(argv: list[str] | None = None) -> int:
    args = list(argv or sys.argv[1:])
    root = Path(args.pop(0) if args else ".").resolve()
    paths = args or ["src"]
    findings = scan(root, paths)
    print(json.dumps({"findings": [{"tool": "evidence", "code": f.code, "message": f.message, "path": f.path, "line": f.line, "severity": f.severity} for f in findings]}))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
