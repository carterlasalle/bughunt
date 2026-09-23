# Copyright (c) 2026 Carter LaSalle
"""Data-invariant scan: missingness, derived columns, intervals, artifacts.

Pure-AST native defense (SPEC-BUG-DATA01, ADR-009). Covers the bug
families ordinary linters never catch: fabricated zeros flowing into
quantitative sinks (BHMISS001), stale derived DataFrame columns
(BHDF001), half-open selection into adjacent-sample integrators
(BHINT001), trailing values used as forward intervals (BHINT002),
use-before-artifact-validation (BHART001), incomplete freshness
fingerprints (BHART002), contradictory availability metadata
(BHMETA001), local-wall-as-UTC (BHTIME002), and duplicated policy
predicates (BHINV001).

Semgrep/ast-grep are the wrong engine for the cross-statement
relationships here (OSS taint is intraprocedural); this module keeps
tiny per-function SSA instead.
"""

from __future__ import annotations

import ast
import json
import sys
from dataclasses import dataclass
from pathlib import Path

IGNORED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "vendor",
    "build",
    "dist",
    ".bughunt",
    ".tox",
    ".nox",
    "__pycache__",
    "site-packages",
    "mutants",
}

_QUANTITY_HINTS = (
    "irradiance",
    "radiation",
    "dose",
    "uv_index",
    "uvi",
    "_wm2",
    "_j_m2",
    "sed_",
    "score",
    "pigment",
    "uva",
    "uvb",
    "vitamin",
    "erythemal",
)
_INTEGRATOR_HINTS = ("integrate", "trapz", "cumtrapz", "window_", "_dose")
_LOCAL_WALL_HINTS = (
    "local",
    "wall",
    "dt_local",
    "local_time",
    "wall_time",
    "site_time",
)
_TRAILING_HINTS = ("trailing", "tan_dose_30m")
_FORWARD_START_HINTS = ("best_", "window_start")
_ARTIFACT_SUFFIXES = (".parquet", ".pkl", ".pickle", ".npz", ".npy", ".joblib", ".onnx")
_FRESHNESS_HINTS = (
    "exists",
    "stat",
    "mtime",
    "fresh",
    "stale",
    "manifest",
    "_version",
    "version",
    "valid",
)
_QUALITY_SUFFIXES = (
    "_complete",
    "_coverage",
    "_coverage_fraction",
    "_valid",
    "_stale",
    "_version",
    "_confidence",
    "_source",
)


# trace:v1 id=impl.src-bughunt-data-scan.data-finding work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
@dataclass(slots=True)
class DataFinding:
    code: str
    message: str
    path: str
    line: int
    severity: str = "warning"


# trace:v1 id=impl.src-bughunt-data-scan.-iter-python work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _iter_python(root: Path, paths: list[str]) -> list[Path]:
    out: list[Path] = []
    seen: set[Path] = set()
    for rel in paths:
        base = root / rel
        candidates = (
            [base]
            if base.is_file() and base.suffix == ".py"
            else list(base.rglob("*.py"))
            if base.is_dir()
            else []
        )
        for path in candidates:
            if path in seen or any(part in IGNORED_DIRS for part in path.parts):
                continue
            seen.add(path)
            out.append(path)
    return out


# trace:v1 id=impl.src-bughunt-data-scan.-rel work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _rel(root: Path, path: Path) -> str:
    try:
        return (
            path.resolve(strict=False)
            .relative_to(root.resolve(strict=False))
            .as_posix()
        )
    except ValueError:
        return path.as_posix()


# trace:v1 id=impl.src-bughunt-data-scan.-lower work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _lower(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id.lower()
    if isinstance(node, ast.Attribute):
        return node.attr.lower()
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.lower()
    return ""


# trace:v1 id=impl.src-bughunt-data-scan.-call-name work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _call_name(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


# trace:v1 id=impl.src-bughunt-data-scan.-is-quantity work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _is_quantity(text: str) -> bool:
    lowered = text.lower()
    return any(hint in lowered for hint in _QUANTITY_HINTS)


# trace:v1 id=impl.src-bughunt-data-scan.-is-integrator work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _is_integrator(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in _INTEGRATOR_HINTS)


# trace:v1 id=impl.src-bughunt-data-scan.-is-local-wall work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _is_local_wall(text: str) -> bool:
    lowered = text.lower()
    return any(hint in lowered for hint in _LOCAL_WALL_HINTS)


# trace:v1 id=impl.src-bughunt-data-scan.-is-trailing work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _is_trailing(text: str) -> bool:
    lowered = text.lower()
    return any(hint in lowered for hint in _TRAILING_HINTS)


# trace:v1 id=impl.src-bughunt-data-scan.-is-forward-start work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _is_forward_start(text: str) -> bool:
    lowered = text.lower()
    return any(lowered.startswith(hint) for hint in _FORWARD_START_HINTS)


# trace:v1 id=impl.src-bughunt-data-scan.-fillna-zero work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _fillna_zero(node: ast.AST) -> bool:
    """True for `.fillna(0)` / `.fillna(0.0)` call nodes."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "fillna"
        and len(node.args) == 1
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value in (0, 0.0)
        and not isinstance(node.args[0].value, bool)
    )


# trace:v1 id=impl.src-bughunt-data-scan.-miss work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _miss(tree: ast.AST, rel: str) -> list[DataFinding]:
    """BHMISS001: fillna(0)-imputed value into a quantitative sink."""
    out: list[DataFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        imputed: set[str] = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Call) and _fillna_zero(child):
                func = child.func
                recv: ast.AST = func.value if isinstance(func, ast.Attribute) else func
                name = _lower(recv)
                if isinstance(recv, ast.Name):
                    imputed.add(recv.id)
                elif name:
                    imputed.add(name)
            if isinstance(child, ast.Assign) and any(
                _fillna_zero(n) for n in ast.walk(child.value)
            ):
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        imputed.add(target.id)
        if not imputed:
            continue
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            callee = _call_name(child.func)
            if not (_is_integrator(callee) or _is_quantity(callee)):
                continue
            hit = False
            for arg in (*child.args, *(kw.value for kw in child.keywords)):
                for sub in ast.walk(arg):
                    if isinstance(sub, ast.Name) and sub.id in imputed:
                        hit = True
                    elif _fillna_zero(sub):
                        hit = True
            if hit:
                out.append(
                    DataFinding(
                        "BHMISS001",
                        "imputed zero (fillna(0)) flows into quantitative "
                        f"sink `{callee}`; unknown measurement becomes a "
                        "fabricated physical zero",
                        rel,
                        child.lineno,
                        "error",
                    )
                )
                break
    return out


# trace:v1 id=impl.src-bughunt-data-scan.-subscript-key work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _subscript_key(node: ast.AST) -> tuple[str, str] | None:
    """(base name, constant key) for `base["key"]`, else None."""
    if (
        isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Name)
        and isinstance(node.slice, ast.Constant)
        and isinstance(node.slice.value, str)
    ):
        return (node.value.id, node.slice.value)
    return None


# trace:v1 id=impl.src-bughunt-data-scan.-read-columns work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _read_columns(base: str, node: ast.AST) -> set[str]:
    """Constant column keys of `base[...]` loaded under `node`."""
    out: set[str] = set()
    for child in ast.walk(node):
        if (
            isinstance(child, ast.Subscript)
            and isinstance(child.ctx, ast.Load)
            and isinstance(child.value, ast.Name)
            and child.value.id == base
            and isinstance(child.slice, ast.Constant)
            and isinstance(child.slice.value, str)
        ):
            out.add(child.slice.value)
    return out


# trace:v1 id=impl.src-bughunt-data-scan.-call-exports work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _call_exports(node: ast.Call, base: str, column: str) -> bool:
    """True when call `node` carries `base["column"]` out of the frame."""
    callee = _call_name(node.func)
    if callee.split(".")[-1] in {"to_dict", "to_csv", "to_parquet", "to_json"}:
        return True
    if isinstance(node.func, ast.Name):
        return True
    return any(
        _subscript_key(arg) == (base, column)
        for arg in (*node.args, *(kw.value for kw in node.keywords))
    )


# trace:v1 id=impl.src-bughunt-data-scan.-is-export work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _is_export(
    node: ast.stmt, base: str, column: str, known: set[str] | None = None
) -> bool:
    """True when statement `node` reads `base["column"]` out of the frame."""
    if isinstance(node, ast.Return):
        values = node.value
        if values is None:
            return False
        if isinstance(values, ast.Name):
            return True
        if _read_columns(base, values):
            return True
        return known is not None and column in known
    if isinstance(node, ast.Expr):
        value = node.value
        if isinstance(value, ast.Subscript):
            return _subscript_key(value) == (base, column)
        return isinstance(value, ast.Call) and _call_exports(value, base, column)
    if isinstance(node, ast.Assign):
        return any(
            isinstance(v, ast.Call) and _call_exports(v, base, column)
            for v in ast.walk(node.value)
        )
    return False


# trace:v1 id=impl.src-bughunt-data-scan.-derived work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _derived(tree: ast.AST, rel: str) -> list[DataFinding]:
    out: list[DataFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        deps: dict[tuple[str, str], set[str]] = {}
        stale: set[tuple[str, str]] = set()
        ordered: list[ast.stmt] = [
            sub
            for sub in ast.walk(node)
            if isinstance(sub, ast.stmt)
            and not isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        ordered.sort(key=lambda sub: (sub.lineno, sub.col_offset))
        for probe in ordered:
            if isinstance(probe, ast.Assign) and len(probe.targets) == 1:
                key = _subscript_key(probe.targets[0])
                if key is None:
                    continue
                base, column = key
                reads = _read_columns(base, probe.value) - {column}
                if reads and reads != {column}:
                    deps[key] = reads
                    if key in stale:
                        stale.remove(key)
                    continue
                for derived_key, dep_needs in deps.items():
                    if column in dep_needs:
                        stale.add(derived_key)
                if key in stale:
                    stale.remove(key)
                if key in deps:
                    del deps[key]
            for stale_key in sorted(stale):
                stale_base, stale_column = stale_key
                known = {col for (base, col) in deps if base == stale_base}
                if _is_export(probe, stale_base, stale_column, known):
                    required = sorted(deps.get(stale_key, set()))
                    out.append(
                        DataFinding(
                            "BHDF001",
                            f"stale derived column `{stale_column}` depends on "
                            f"{{{', '.join(required)}}}; dependency mutated "
                            "after last computation",
                            rel,
                            probe.lineno,
                            "error",
                        )
                    )
                    stale.discard(stale_key)
                    break
    return out


# trace:v1 id=impl.src-bughunt-data-scan.-half-open-mask work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _half_open_mask(node: ast.BoolOp | ast.BinOp) -> bool:
    """True for `(t >= start) & (t < end)`-shaped half-open selections."""
    if not isinstance(node.op, (ast.BitAnd, ast.And)):
        return False
    lowers = False
    upper_open = False
    for child in ast.walk(node):
        if not isinstance(child, ast.Compare) or len(child.ops) != 1:
            continue
        op = child.ops[0]
        if isinstance(op, (ast.GtE, ast.Gt)):
            lowers = True
        if isinstance(op, ast.Lt):
            upper_open = True
    return lowers and upper_open


# trace:v1 id=impl.src-bughunt-data-scan.-interval-endpoint work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _interval_endpoint(tree: ast.AST, rel: str) -> list[DataFinding]:
    out: list[DataFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        masked: set[str] = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name) and isinstance(
                        child.value, (ast.BoolOp, ast.BinOp)
                    ):
                        if _half_open_mask(child.value):
                            masked.add(target.id)
            if isinstance(child, ast.NamedExpr) and isinstance(
                child.value, (ast.BoolOp, ast.BinOp)
            ):
                if _half_open_mask(child.value) and isinstance(child.target, ast.Name):
                    masked.add(child.target.id)
        if not masked:
            continue
        for child in ast.walk(node):
            if not isinstance(child, ast.Call) or not _is_integrator(
                _call_name(child.func)
            ):
                continue
            hit = any(
                (
                    isinstance(sub, ast.Name)
                    and sub.id in masked
                    or isinstance(sub, ast.Subscript)
                    and isinstance(sub.value, ast.Name)
                    and sub.value.id in masked
                )
                for arg in (*child.args, *(kw.value for kw in child.keywords))
                for sub in ast.walk(arg)
            )
            if hit:
                out.append(
                    DataFinding(
                        "BHINT001",
                        "half-open point selection feeds an adjacent-sample "
                        "integrator; the sample at `end` is excluded so the "
                        "final interval cannot be integrated",
                        rel,
                        child.lineno,
                        "error",
                    )
                )
                break
    return out


# trace:v1 id=impl.src-bughunt-data-scan.-interval-alignment work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _interval_alignment(tree: ast.AST, rel: str) -> list[DataFinding]:
    """BHINT002: trailing-interval value used as a forward interval start."""
    out: list[DataFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        trailing_vars: dict[str, int] = {}
        for arg in (*node.args.args, *node.args.kwonlyargs):
            if _is_trailing(arg.arg):
                trailing_vars[arg.arg] = node.lineno
        for child in ast.walk(node):
            if isinstance(child, ast.Assign) and len(child.targets) == 1:
                target = child.targets[0]
                if isinstance(target, ast.Name) and _is_trailing(target.id):
                    trailing_vars[target.id] = child.lineno
                if (
                    isinstance(target, ast.Name)
                    and _is_forward_start(target.id)
                    and target.id not in trailing_vars
                    and isinstance(child.value, ast.Name)
                    and child.value.id in trailing_vars
                ):
                    out.append(
                        DataFinding(
                            "BHINT002",
                            f"trailing interval value `{child.value.id}` used "
                            f"as forward interval `{target.id}` starting at "
                            "the current timestamp",
                            rel,
                            child.lineno,
                            "error",
                        )
                    )
            if isinstance(child, ast.Call):
                for kw in child.keywords:
                    if (
                        kw.arg in {"start", "begin", "start_ts"}
                        and isinstance(kw.value, ast.Name)
                        and kw.value.id in trailing_vars
                    ):
                        out.append(
                            DataFinding(
                                "BHINT002",
                                f"trailing interval value `{kw.value.id}` "
                                f"passed as `{kw.arg}=` of "
                                f"`{_call_name(child.func)}`",
                                rel,
                                child.lineno,
                                "error",
                            )
                        )
    return out


# trace:v1 id=impl.src-bughunt-data-scan.-artifact-reads work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _artifact_reads(node: ast.Call) -> str | None:
    """Artifact path string when the call reads a cached artifact file."""
    for arg in (*node.args, *(kw.value for kw in node.keywords)):
        for sub in ast.walk(arg):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                if any(sub.value.endswith(suffix) for suffix in _ARTIFACT_SUFFIXES):
                    return sub.value
    return None


# trace:v1 id=impl.src-bughunt-data-scan.-has-freshness work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _has_freshness(node: ast.AST) -> bool:
    """True when the subtree mentions a freshness/validation check."""
    for child in ast.walk(node):
        if isinstance(child, ast.Call) and any(
            hint in _call_name(child.func).lower() for hint in _FRESHNESS_HINTS
        ):
            return True
        if isinstance(child, ast.Compare):
            for comparator in (*[child.left], *child.comparators):
                if isinstance(comparator, ast.Constant) and isinstance(
                    comparator.value, str
                ):
                    if any(
                        hint in comparator.value.lower() for hint in _FRESHNESS_HINTS
                    ):
                        return True
    return False


# trace:v1 id=impl.src-bughunt-data-scan.-artifact-order work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _artifact_order(tree: ast.AST, rel: str) -> list[DataFinding]:
    """BHART001: cached artifact consumed before freshness is validated."""
    out: list[DataFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        ordered: list[ast.stmt] = []
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.stmt) and not isinstance(
                stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                ordered.append(stmt)
        validated = False
        for stmt in ordered:
            if _has_freshness(stmt):
                validated = True
            for child in ast.walk(stmt):
                if isinstance(child, ast.Call) and _artifact_reads(child):
                    if not validated:
                        out.append(
                            DataFinding(
                                "BHART001",
                                "cached artifact consumed before freshness "
                                "is validated; a stale local reference is "
                                "used as if current",
                                rel,
                                child.lineno,
                                "warning",
                            )
                        )
                        validated = True
                    break
    return out


# trace:v1 id=impl.src-bughunt-data-scan.-config-keys work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _config_keys(node: ast.AST) -> set[str]:
    """UPPER_SNAKE config keys referenced under `node`."""
    out: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id.isupper() and "_" in child.id:
            out.add(child.id)
        if (
            isinstance(child, ast.Constant)
            and isinstance(child.value, str)
            and child.value.isupper()
            and "_" in child.value
        ):
            out.add(child.value)
    return out


# trace:v1 id=impl.src-bughunt-data-scan.-artifact-fingerprint work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _artifact_fingerprint(tree: ast.AST, rel: str) -> list[DataFinding]:
    """BHART002: freshness contract omits build-time config dependencies."""
    out: list[DataFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        lowered = node.name.lower()
        if not any(
            hint in lowered
            for hint in ("build", "compute", "refresh", "update", "make")
        ):
            continue
        built = _config_keys(node)
        if len(built) < 2:
            continue
        for child in ast.walk(tree):
            if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if child is node:
                continue
            if not any(
                hint in child.name.lower()
                for hint in ("fresh", "valid", "stale", "manifest", "version", "check")
            ):
                continue
            checked = _config_keys(child)
            omitted = sorted(built - checked)
            if omitted and checked:
                out.append(
                    DataFinding(
                        "BHART002",
                        "artifact freshness contract omits configuration "
                        f"dependencies: {', '.join(omitted)}",
                        rel,
                        child.lineno,
                        "error",
                    )
                )
    return out


# trace:v1 id=impl.src-bughunt-data-scan.-contradictory-meta work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _contradictory_meta(tree: ast.AST, rel: str) -> list[DataFinding]:
    """BHMETA001: NaN quantity defaults beside complete=True / coverage=1.0."""
    out: list[DataFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        keys = {
            k.value.lower()
            for k in node.keys
            if isinstance(k, ast.Constant) and isinstance(k.value, str)
        }
        has_complete = "complete" in keys and any(
            isinstance(v, ast.Constant) and v.value is True
            for k, v in zip(node.keys, node.values)
            if isinstance(k, ast.Constant) and k.value == "complete"
        )
        has_coverage = "coverage" in keys and any(
            isinstance(v, ast.Constant) and v.value in (1, 1.0)
            for k, v in zip(node.keys, node.values)
            if isinstance(k, ast.Constant) and k.value == "coverage"
        )
        if not (has_complete or has_coverage):
            continue
        has_quantity = any(_is_quantity(k) for k in keys)
        if not has_quantity:
            continue
        out.append(
            DataFinding(
                "BHMETA001",
                "quantity result defaults beside "
                + ("complete=True" if has_complete else "coverage=1.0")
                + "; missing data is labeled fully available",
                rel,
                node.lineno,
                "error",
            )
        )
    return out


# trace:v1 id=impl.src-bughunt-data-scan.-local-as-utc work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _local_as_utc(tree: ast.AST, rel: str) -> list[DataFinding]:
    """BHTIME002: naive local wall clock labeled as UTC via utc=True."""
    out: list[DataFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        localized: set[str] = set()
        for child in ast.walk(node):
            if (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Attribute)
                and child.func.attr == "tz_localize"
            ):
                recv = child.func.value
                if isinstance(recv, ast.Name):
                    localized.add(recv.id)
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            if _call_name(child.func) not in {
                "pd.to_datetime",
                "pandas.to_datetime",
                "to_datetime",
            }:
                continue
            utc_true = any(
                kw.arg == "utc"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is True
                for kw in child.keywords
            )
            if not utc_true or not child.args:
                continue
            first = child.args[0]
            name = _lower(first)
            if isinstance(first, ast.Name) and first.id in localized:
                continue
            if _is_local_wall(name) or _is_local_wall(ast.unparse(first)):
                out.append(
                    DataFinding(
                        "BHTIME002",
                        "naive local wall clock passed to "
                        "pd.to_datetime(..., utc=True); utc=True labels "
                        "the clock as UTC instead of converting it",
                        rel,
                        child.lineno,
                        "error",
                    )
                )
    return out


# trace:v1 id=impl.src-bughunt-data-scan.-predicates work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _predicates(tree: ast.AST, rel: str) -> list[DataFinding]:
    """BHINV001: two reject-predicates over one variable accept different sets."""
    out: list[DataFinding] = []
    accept: dict[str, list[tuple[set[str], int]]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.col_offset != 0:
            continue
        for child in node.body:
            for sub in ast.walk(child):
                if not isinstance(sub, ast.If):
                    continue
                test = sub.test
                var: str | None = None
                excluded: str | None = None
                included: set[str] | None = None
                if (
                    isinstance(test, ast.Compare)
                    and len(test.ops) == 1
                    and isinstance(test.left, ast.Name)
                    and len(test.comparators) == 1
                    and isinstance(test.comparators[0], ast.Constant)
                    and isinstance(test.comparators[0].value, str)
                ):
                    var = test.left.id
                    lit = test.comparators[0].value
                    if isinstance(test.ops[0], ast.Eq):
                        included = {lit}
                    elif isinstance(test.ops[0], ast.NotEq):
                        excluded = lit
                if var is None:
                    continue
                body_rejects = any(
                    isinstance(stmt, ast.Raise)
                    or (
                        isinstance(stmt, ast.Return)
                        and stmt.value is not None
                        and not (
                            isinstance(stmt.value, ast.Constant)
                            and stmt.value.value is True
                        )
                    )
                    for stmt in sub.body
                ) or (
                    len(sub.body) == 1
                    and isinstance(sub.body[0], ast.Expr)
                    and isinstance(sub.body[0].value, ast.Call)
                    and "reject" in _call_name(sub.body[0].value.func).lower()
                )
                if not body_rejects:
                    continue
                key = var
                if included is not None:
                    accept.setdefault(key, []).append((included, sub.lineno))
                elif excluded is not None:
                    accept.setdefault(key, []).append(
                        ({"__neq__:" + excluded}, sub.lineno)
                    )
    for var, groups in accept.items():
        if len(groups) < 2:
            continue
        if all(group == groups[0][0] for group, _ in groups):
            continue
        # `!=lit: raise` rejects everything except lit (strictly larger
        # unless the domain is a singleton). A bare-literal Eq reject
        # beside a NotEq reject over the same variable is therefore an
        # inconsistent policy predicate pair by construction.
        kinds = {
            ("eq" if any(not lit.startswith("__neq__:") for lit in group) else "neq")
            for group, _ in groups
        }
        if kinds == {"eq", "neq"}:
            _, first_line = groups[0]
            _, other_line = groups[1]
            out.append(
                DataFinding(
                    "BHINV001",
                    f"inconsistent policy predicates over `{var}`: "
                    f"line {first_line} rejects one literal but line "
                    f"{other_line} rejects the complement; the accepted "
                    "sets differ",
                    rel,
                    other_line,
                    "error",
                )
            )
            continue
        # Resolve __neq__ markers against the inferred literal domain.
        domain = {
            lit
            for group, _ in groups
            for lit in group
            if not lit.startswith("__neq__:")
        }
        for group, _ in groups:
            for lit in list(group):
                if lit.startswith("__neq__:"):
                    domain.add(lit[len("__neq__:") :])
        resolved: list[tuple[set[str], int]] = []
        for group, lineno in groups:
            neq = {
                lit[len("__neq__:") :] for lit in group if lit.startswith("__neq__:")
            }
            eq = {lit for lit in group if not lit.startswith("__neq__:")}
            resolved.append((eq or (domain - neq), lineno))
        first, first_line = resolved[0]
        for other, other_line in resolved[1:]:
            out.append(
                DataFinding(
                    "BHINV001",
                    f"inconsistent policy predicates over `{var}`: "
                    f"line {first_line} accepts "
                    f"{{{', '.join(sorted(first))}}} but line "
                    f"{other_line} accepts "
                    f"{{{', '.join(sorted(other))}}}",
                    rel,
                    other_line,
                    "error",
                )
            )
            break
    return out


QUALITY_SUFFIXES = (
    "_complete",
    "_coverage",
    "_coverage_fraction",
    "_valid",
    "_stale",
    "_version",
    "_confidence",
    "_source",
)


# trace:v1 id=impl.src-bughunt-data-scan.quality-base work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _quality_base(name: str) -> str | None:
    """Base quantity when `name` is attached quality metadata, else None."""
    lowered = name.lower()
    for suffix in QUALITY_SUFFIXES:
        if lowered.endswith(suffix) and len(lowered) > len(suffix):
            return name[: -len(suffix)]
    return None


# trace:v1 id=impl.src-bughunt-data-scan.quality-metadata-gap work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _quality_metadata_gap(tree: ast.AST, rel: str) -> list[DataFinding]:
    """BHMETA002: quantity crosses a boundary without its quality metadata."""
    out: list[DataFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        defined: set[str] = set()
        for arg in (*node.args.args, *node.args.kwonlyargs):
            defined.add(arg.arg)
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        defined.add(target.id)
                    if (
                        isinstance(target, ast.Subscript)
                        and isinstance(target.value, ast.Name)
                        and isinstance(target.slice, ast.Constant)
                        and isinstance(target.slice.value, str)
                    ):
                        defined.add(target.slice.value)
            if isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name):
                defined.add(child.target.id)
        for child in ast.walk(node):
            if not isinstance(child, ast.Return) or not isinstance(
                child.value, ast.Dict
            ):
                continue
            keys = _dict_keys(child.value)
            for key in sorted(keys):
                if _quality_base(key) is not None:
                    continue
                base = key.rsplit("_", 2)[0] if key.count("_") >= 2 else key
                missing = sorted(
                    candidate
                    for suffix in QUALITY_SUFFIXES
                    for candidate in (base + suffix,)
                    if candidate in defined and candidate not in keys
                )
                if missing:
                    out.append(
                        DataFinding(
                            "BHMETA002",
                            f"`{key}` propagated without available quality "
                            f"metadata: {', '.join(missing)}",
                            rel,
                            child.lineno,
                            "warning",
                        ),
                    )
    return out


# trace:v1 id=impl.src-bughunt-data-scan.-dict-keys work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _dict_keys(node: ast.Dict) -> set[str]:
    """String keys of a dict literal."""
    return {
        key.value
        for key in node.keys
        if isinstance(key, ast.Constant) and isinstance(key.value, str)
    }


# trace:v1 id=impl.src-bughunt-data-scan.scan work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def scan(root: Path, source_paths: list[str]) -> list[DataFinding]:
    findings: list[DataFinding] = []
    for path in _iter_python(root, source_paths):
        try:
            tree = ast.parse(path.read_text(errors="replace"))
        except (OSError, SyntaxError):
            continue
        rel = _rel(root, path)
        findings.extend(_miss(tree, rel))
        findings.extend(_derived(tree, rel))
        findings.extend(_interval_endpoint(tree, rel))
        findings.extend(_interval_alignment(tree, rel))
        findings.extend(_artifact_order(tree, rel))
        findings.extend(_artifact_fingerprint(tree, rel))
        findings.extend(_contradictory_meta(tree, rel))
        findings.extend(_local_as_utc(tree, rel))
        findings.extend(_predicates(tree, rel))
        findings.extend(_quality_metadata_gap(tree, rel))
    return sorted(findings, key=lambda item: (item.path, item.line, item.code))


# trace:v1 id=impl.src-bughunt-data-scan.main work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
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
            {
                "findings": [
                    {
                        "tool": "data",
                        "code": item.code,
                        "path": item.path,
                        "line": item.line,
                        "message": item.message,
                        "severity": item.severity,
                    }
                    for item in findings
                ]
            }
        )
    )
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
