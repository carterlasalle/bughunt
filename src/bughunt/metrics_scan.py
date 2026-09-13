# Copyright (c) 2026 Carter LaSalle
from __future__ import annotations

import argparse
import ast
import json
import math
import tomllib
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path

EXCLUDED = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    ".tox",
    ".nox",
    ".bughunt",
    "__pycache__",
    "mutants",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
}

DEFAULTS = {
    "cyclomatic_warn": 10,
    "cyclomatic_error": 20,
    "cognitive_max": 10,
    "function_loc_warn": 80,
    "function_loc_error": 150,
    "file_loc_warn": 500,
    "file_loc_error": 1200,
    "abc_warn": 30.0,
    "abc_error": 45.0,
    "js_file_kb_warn": 500,
    "css_file_kb_warn": 250,
    "wasm_file_kb_warn": 2000,
    "bundle_kb_warn": 1500,
}


@dataclass(slots=True)
class MetricFinding:
    path: str
    line: int
    column: int
    code: str
    message: str
    severity: str = "warning"


# trace:v1 id=impl.src-bughunt-metrics_scan.functionmetricvisitor work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
class FunctionMetricVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.cyclomatic = 1
        self.assignments = 0
        self.branches = 0
        self.conditions = 0

    def visit_If(self, node: ast.If) -> None:
        self.cyclomatic += 1
        self.conditions += 1
        self.generic_visit(node)

    def visit_IfExp(self, node: ast.IfExp) -> None:
        self.cyclomatic += 1
        self.conditions += 1
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self.cyclomatic += 1
        self.conditions += 1
        self.generic_visit(node)

    # trace:exempt reason=internal-detail
    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.cyclomatic += 1
        self.conditions += 1
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        self.cyclomatic += 1
        self.conditions += 1
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        self.cyclomatic += 1
        self.conditions += 1
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        self.cyclomatic += 1
        self.generic_visit(node)

    # trace:exempt reason=internal-detail
    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self.cyclomatic += 1
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        self.cyclomatic += 1
        self.conditions += 1
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        increment = max(0, len(node.values) - 1)
        self.cyclomatic += increment
        self.conditions += increment
        self.generic_visit(node)

    def visit_comprehension(self, node: ast.comprehension) -> None:
        self.cyclomatic += 1 + len(node.ifs)
        self.conditions += 1 + len(node.ifs)
        self.generic_visit(node)

    # trace:v1 id=impl.src-bughunt-metrics_scan-functionmetricvisitor.visit-match work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
    def visit_Match(self, node: ast.Match) -> None:
        for case in node.cases:
            if not (
                isinstance(case.pattern, ast.MatchAs)
                and case.pattern.name is None
                and case.pattern.pattern is None
            ):
                self.cyclomatic += 1
                self.conditions += 1
            if case.guard is not None:
                self.cyclomatic += 1
                self.conditions += 1
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.assignments += 1
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.assignments += 1
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.assignments += 1
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.assignments += 1
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        self.branches += 1
        self.generic_visit(node)

    # Nested functions are measured separately, not charged to the parent.
    # trace:v1 id=impl.src-bughunt-metrics-scan.visit-functiondef work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    def visit_FunctionDef(self, _node: ast.FunctionDef) -> None:
        return

    # trace:v1 id=impl.src-bughunt-metrics-scan.visit-asyncfunctiondef work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    def visit_AsyncFunctionDef(self, _node: ast.AsyncFunctionDef) -> None:
        return

    # trace:v1 id=impl.src-bughunt-metrics-scan.visit-lambda work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    def visit_Lambda(self, _node: ast.Lambda) -> None:
        return


def _budget(root: Path) -> dict[str, float]:
    values: dict[str, float] = {k: float(v) for k, v in DEFAULTS.items()}
    path = root / "bughunt.toml"
    if path.exists():
        try:
            raw = tomllib.loads(path.read_text()).get("complexity", {})
            for key in DEFAULTS:
                if key in raw:
                    values[key] = float(raw[key])
        except (OSError, tomllib.TOMLDecodeError, TypeError, ValueError):
            pass
    return values


# trace:v1 id=impl.src-bughunt-metrics_scan.-files work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _files(root: Path, source_paths: Iterable[str]) -> Iterable[Path]:
    seen: set[Path] = set()
    for rel in source_paths:
        base = root / rel
        if not base.exists():
            continue
        candidates = [base] if base.is_file() else base.rglob("*.py")
        for path in candidates:
            if path.suffix == ".py" and not any(
                part in EXCLUDED for part in path.parts
            ):
                rp = path.resolve()
                if rp not in seen:
                    seen.add(rp)
                    yield path


def _iter_functions(tree: ast.AST) -> Iterable[ast.FunctionDef | ast.AsyncFunctionDef]:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


# trace:v1 id=impl.src-bughunt-metrics_scan.-metric-for-function work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _metric_for_function(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[int, int, int, int, float, int]:
    visitor = FunctionMetricVisitor()
    for stmt in node.body:
        visitor.visit(stmt)
    abc = math.sqrt(
        visitor.assignments**2 + visitor.branches**2 + visitor.conditions**2,
    )
    loc = max(
        1,
        (getattr(node, "end_lineno", node.lineno) or node.lineno) - node.lineno + 1,
    )
    return (
        visitor.cyclomatic,
        visitor.assignments,
        visitor.branches,
        visitor.conditions,
        abc,
        loc,
    )


def _severity(value: float, warn: float, error: float) -> str | None:
    if value > error:
        return "error"
    if value > warn:
        return "warning"
    return None


# trace:v1 id=impl.src-bughunt-metrics_scan.scan-python work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def scan_python(
    root: Path,
    source_paths: Iterable[str],
    budget: dict[str, float],
) -> list[MetricFinding]:
    out: list[MetricFinding] = []
    for path in _files(root, source_paths):
        rel = path.relative_to(root).as_posix()
        try:
            source = path.read_text(errors="replace")
            tree = ast.parse(source)
        except (OSError, SyntaxError):
            continue
        physical_loc = len(source.splitlines())
        sev = _severity(physical_loc, budget["file_loc_warn"], budget["file_loc_error"])
        if sev:
            out.append(
                MetricFinding(
                    rel,
                    1,
                    1,
                    "BHCX003",
                    (
                        f"file has {physical_loc} LOC; budget is "
                        f"{int(budget['file_loc_warn'])} warning / "
                        f"{int(budget['file_loc_error'])} error. Split only at real "
                        "subsystem/cohesion boundaries, never into nonsense fragments "
                        "just to satisfy LOC."
                    ),
                    sev,
                ),
            )
        for fn in _iter_functions(tree):
            cc, a, b, c, abc, loc = _metric_for_function(fn)
            sev = _severity(cc, budget["cyclomatic_warn"], budget["cyclomatic_error"])
            if sev:
                out.append(
                    MetricFinding(
                        rel,
                        fn.lineno,
                        1,
                        "BHCX001",
                        (
                            f"`{fn.name}` cyclomatic complexity is {cc}; budget is "
                            f"{int(budget['cyclomatic_warn'])} warning / "
                            f"{int(budget['cyclomatic_error'])} error"
                        ),
                        sev,
                    ),
                )
            sev = _severity(
                loc,
                budget["function_loc_warn"],
                budget["function_loc_error"],
            )
            if sev:
                out.append(
                    MetricFinding(
                        rel,
                        fn.lineno,
                        1,
                        "BHCX002",
                        (
                            f"`{fn.name}` spans {loc} lines; budget is "
                            f"{int(budget['function_loc_warn'])} warning / "
                            f"{int(budget['function_loc_error'])} error"
                        ),
                        sev,
                    ),
                )
            sev = _severity(abc, budget["abc_warn"], budget["abc_error"])
            if sev:
                out.append(
                    MetricFinding(
                        rel,
                        fn.lineno,
                        1,
                        "BHCX004",
                        (
                            f"`{fn.name}` ABC magnitude is {abc:.1f} (A={a}, B={b}, "
                            f"C={c}); budget is {budget['abc_warn']:.0f} warning / "
                            f"{budget['abc_error']:.0f} error"
                        ),
                        sev,
                    ),
                )
    return out


# trace:v1 id=impl.src-bughunt-metrics_scan.scan-assets work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def scan_assets(root: Path, budget: dict[str, float]) -> list[MetricFinding]:
    out: list[MetricFinding] = []
    roots = [
        p
        for p in (
            root / "dist",
            root / "build",
            root / ".next" / "static",
            root / "public" / "assets",
            root / "static",
        )
        if p.exists()
    ]
    thresholds = {
        ".js": budget["js_file_kb_warn"],
        ".mjs": budget["js_file_kb_warn"],
        ".cjs": budget["js_file_kb_warn"],
        ".css": budget["css_file_kb_warn"],
        ".wasm": budget["wasm_file_kb_warn"],
    }
    for base in roots:
        total = 0
        for path in base.rglob("*"):
            if (
                not path.is_file()
                or path.suffix.lower() not in thresholds
                or path.name.endswith(".map")
            ):
                continue
            kb = path.stat().st_size / 1024.0
            total += path.stat().st_size
            limit = thresholds[path.suffix.lower()]
            if kb > limit:
                out.append(
                    MetricFinding(
                        path.relative_to(root).as_posix(),
                        1,
                        1,
                        "BHCX005",
                        (
                            f"built asset is {kb:.1f} KiB; default "
                            f"{path.suffix.lower()} per-file budget is {limit:.0f} "
                            "KiB"
                        ),
                        "warning",
                    ),
                )
        total_kb = total / 1024.0
        if total_kb > budget["bundle_kb_warn"]:
            out.append(
                MetricFinding(
                    base.relative_to(root).as_posix(),
                    1,
                    1,
                    "BHCX006",
                    (
                        f"built JS/CSS/WASM asset set totals {total_kb:.1f} KiB; "
                        f"default bundle budget is {budget['bundle_kb_warn']:.0f} "
                        "KiB"
                    ),
                    "warning",
                ),
            )
    return out


def scan(root: Path, source_paths: Iterable[str]) -> list[MetricFinding]:
    budget = _budget(root)
    return [*scan_python(root, source_paths, budget), *scan_assets(root, budget)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    _ = parser.add_argument("--root", type=Path, default=Path.cwd())
    _ = parser.add_argument("--source", action="append", default=[])
    args = parser.parse_args(argv)
    root = args.root.resolve()
    findings = scan(root, args.source or ["src"])
    print(json.dumps([asdict(x) for x in findings]))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
