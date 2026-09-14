# Copyright (c) 2026 Carter LaSalle
from __future__ import annotations

import argparse
import ast
import json
import re
from collections.abc import Iterable
from contextlib import suppress
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import cast

from typing_extensions import override

EXCLUDED = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    ".tox",
    ".nox",
    "build",
    "dist",
    ".bughunt",
    "mutants",
    "__pycache__",
}

SECRET_NAME = re.compile(
    r"(?:secret|token|password|passwd|api[_-]?key|private[_-]?key|access[_-]?key|"
    + r"client[_-]?secret)",
    re.IGNORECASE,
)
CONFIG_NAME = re.compile(
    r"(?:^|_)(timeout|retries|retry|host|port|url|endpoint|threshold|limit|max|min|"
    + r"interval|ttl|workers|batch(?:_size)?|concurrency|rate|delay|buffer|cache)(?:_|$)",
    re.IGNORECASE,
)
CONFIG_MODULE = re.compile(
    r"(?:^|[._/])(config|settings|constants|defaults|cli|options)(?:[._/]|$)",
    re.IGNORECASE,
)
UPPER_LAYER = {
    "api",
    "apis",
    "route",
    "routes",
    "web",
    "ui",
    "service",
    "services",
    "domain",
    "core",
    "application",
    "usecase",
    "usecases",
    "handler",
    "handlers",
    "controller",
    "controllers",
}
PERSIST_IMPL = {
    "sqlite",
    "postgres",
    "postgresql",
    "mysql",
    "sqlalchemy",
    "peewee",
    "orm",
    "mongo",
    "mongodb",
    "redis",
}
ROUNDTRIP_PAIRS = (("export", "import"), ("backup", "restore"))
PLACEHOLDER_VALUES = {
    "",
    "changeme",
    "change-me",
    "example",
    "example-value",
    "placeholder",
    "your-value-here",
    "your_value_here",
    "todo",
    "unset",
    "none",
    "null",
    "<required>",
    "required",
    "replace-me",
    "replace_me",
}


@dataclass(slots=True)
class EnvUse:
    name: str
    path: str
    line: int
    required: bool
    default: object | None
    inferred_type: str
    unit: str | None
    accepted_range: str | None
    secret_like: bool


@dataclass(slots=True)
class PolicyFinding:
    path: str
    line: int
    column: int
    code: str
    message: str
    severity: str = "warning"


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = _call_name(node.value)
        return f"{left}.{node.attr}" if left else node.attr
    return ""


def _files(root: Path, paths: Iterable[str]) -> Iterable[Path]:
    seen: set[Path] = set()
    for rel in paths:
        base = root / rel
        if not base.exists():
            continue
        candidates = [base] if base.is_file() else base.rglob("*.py")
        for path in candidates:
            if path.suffix != ".py" or any(part in EXCLUDED for part in path.parts):
                continue
            resolved = path.resolve()
            if resolved not in seen:
                seen.add(resolved)
                yield path


# trace:v1 id=impl.src-bughunt-policy-scan.-literal work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _literal(node: ast.AST | None) -> object | None:
    if node is None:
        return None
    try:
        return cast("object | None", ast.literal_eval(node))
    except (ValueError, TypeError):
        return None


# trace:v1 id=impl.src-bughunt-policy_scan.-unit-for work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _unit_for(name: str) -> str | None:
    n = name.lower()
    suffixes = {
        "_ms": "milliseconds",
        "_millis": "milliseconds",
        "_milliseconds": "milliseconds",
        "_us": "microseconds",
        "_ns": "nanoseconds",
        "_s": "seconds",
        "_sec": "seconds",
        "_secs": "seconds",
        "_seconds": "seconds",
        "_min": "minutes",
        "_mins": "minutes",
        "_minutes": "minutes",
        "_hours": "hours",
        "_b": "bytes",
        "_bytes": "bytes",
        "_kb": "kilobytes",
        "_mb": "megabytes",
        "_gb": "gigabytes",
        "_tb": "terabytes",
        "_percent": "percent",
        "_percentage": "percent",
        "_port": "TCP/UDP port",
    }
    return next((unit for suffix, unit in suffixes.items() if n.endswith(suffix)), None)


# trace:v1 id=impl.src-bughunt-policy_scan.-assigned-name work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _assigned_name(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> str | None:
    current: ast.AST | None = node
    for _ in range(5):
        if current is None:
            return None
        parent = parents.get(current)
        if isinstance(parent, ast.Assign):
            names = [
                target.id for target in parent.targets if isinstance(target, ast.Name)
            ]
            return names[0] if len(names) == 1 else None
        if isinstance(parent, ast.AnnAssign) and isinstance(parent.target, ast.Name):
            return parent.target.id
        current = parent
    return None


def _numeric_constant(node: ast.AST) -> int | float | None:
    value = _literal(node)
    if isinstance(value, bool):
        return None
    return value if isinstance(value, (int, float)) else None


_COMPARE_SYMBOLS: dict[type[ast.cmpop], str] = {
    ast.Gt: ">",
    ast.GtE: ">=",
    ast.Lt: "<",
    ast.LtE: "<=",
    ast.Eq: "==",
}
_FLIPPED_COMPARE_SYMBOLS: dict[type[ast.cmpop], str] = {
    ast.Lt: ">",
    ast.LtE: ">=",
    ast.Gt: "<",
    ast.GtE: "<=",
}


# trace:v1 id=impl.src-bughunt-policy-scan.-range-for-variable work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _range_for_variable(tree: ast.AST, variable: str) -> str | None:
    constraints: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        operands = [node.left, *node.comparators]
        for left, op, right in zip(operands, node.ops, operands[1:]):
            left_num = _numeric_constant(left)
            right_num = _numeric_constant(right)
            if (
                isinstance(left, ast.Name)
                and left.id == variable
                and right_num is not None
            ):
                symbol = _COMPARE_SYMBOLS.get(type(op))
                if symbol:
                    constraints.append(f"{symbol}{right_num}")
            elif (
                left_num is not None
                and isinstance(right, ast.Name)
                and right.id == variable
            ):
                symbol = _FLIPPED_COMPARE_SYMBOLS.get(type(op))
                if symbol:
                    constraints.append(f"{symbol}{left_num}")
    unique = list(dict.fromkeys(constraints))
    return " and ".join(unique[:4]) if unique else None


_UNIT_STEMS = frozenset(
    {
        "timeout",
        "interval",
        "delay",
        "ttl",
        "duration",
        "latency",
        "deadline",
        "backoff",
        "heartbeat",
        "period",
        "expiry",
        "lifetime",
        "size",
        "length",
        "width",
        "height",
        "memory",
        "capacity",
    }
)
_BARE_UNIT_NAMES = frozenset(
    {
        "ms",
        "s",
        "sec",
        "secs",
        "seconds",
        "min",
        "mins",
        "minutes",
        "h",
        "hours",
        "us",
        "ns",
        "b",
        "bytes",
        "kb",
        "mb",
        "gb",
        "tb",
    }
)
_UNIT_DIMENSIONS = {
    "milliseconds": "time",
    "microseconds": "time",
    "nanoseconds": "time",
    "seconds": "time",
    "minutes": "time",
    "hours": "time",
    "bytes": "size",
    "kilobytes": "size",
    "megabytes": "size",
    "gigabytes": "size",
    "terabytes": "size",
}
_CONVERSION_FACTORS = frozenset({1000, 1000.0, 1024, 1024.0})


# trace:v1 id=impl.src-bughunt-policy-scan.-scan-unit-policies work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _scan_unit_policies(tree: ast.AST, rel: str) -> list[PolicyFinding]:
    """Flag unit-bearing names without units and mixed-unit expressions.

    BHUNIT001 (warning): a unit-bearing stem bound to a bare number
    (`timeout = 10`) carries no unit; suffix it (`timeout_s`).
    BHUNIT002 (error): one expression mixes units of one dimension
    (`deadline_ms + grace_s`) or adds a bare number to a unit
    (`elapsed_ms + 500`); an explicit x1000/x1024 factor reads as a
    deliberate conversion and is exempt, as is comparison against 0.
    BHUNIT003 (warning): one stem bound in two units in one file
    (`timeout_ms` and `timeout_s`) is an ambiguous contract.
    Call keyword arguments are the callee's contract and are never flagged.
    """
    findings: list[PolicyFinding] = []

    # trace:v1 id=impl.src-bughunt-policy-scan-scan-unit-policies.stem-of work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    def stem_of(name: str) -> str:
        return name.lower().split("_")[-1]

    # trace:v1 id=impl.src-bughunt-policy-scan-scan-unit-policies.needs-unit work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    def needs_unit(name: str) -> bool:
        n = name.lower()
        if _unit_for(name) is not None or n in _BARE_UNIT_NAMES:
            return False
        return n in _UNIT_STEMS or stem_of(name) in _UNIT_STEMS

    # trace:v1 id=impl.src-bughunt-policy-scan-scan-unit-policies.bound-names work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    def bound_names(node: ast.AST) -> list[tuple[str, int]]:
        """(name, lineno) pairs this node binds to a numeric literal."""
        out: list[tuple[str, int]] = []
        if isinstance(node, ast.Assign) and _numeric_constant(node.value) is not None:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    out.append((target.id, target.lineno))
                elif isinstance(target, ast.Attribute):
                    out.append((target.attr, target.lineno))
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.value is not None
            and _numeric_constant(node.value) is not None
        ):
            out.append((node.target.id, node.target.lineno))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = node.args
            positional = [*args.posonlyargs, *args.args]
            for arg, default in zip(
                positional[len(positional) - len(args.defaults) :] or [],
                args.defaults,
            ):
                if _numeric_constant(default) is not None:
                    out.append((arg.arg, arg.lineno))
            for kw_arg, kw_default in zip(args.kwonlyargs, args.kw_defaults):
                if kw_default is not None and _numeric_constant(kw_default) is not None:
                    out.append((kw_arg.arg, kw_arg.lineno))
        return out

    # trace:v1 id=impl.src-bughunt-policy-scan-scan-unit-policies.expr-units work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    def expr_units(node: ast.AST) -> set[str]:
        units: set[str] = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                unit = _unit_for(child.id)
                if unit is not None:
                    units.add(unit)
            elif isinstance(child, ast.Attribute):
                unit = _unit_for(child.attr)
                if unit is not None:
                    units.add(unit)
        return units

    # trace:v1 id=impl.src-bughunt-policy-scan-scan-unit-policies.expr-numbers work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    def expr_numbers(node: ast.AST) -> set[int | float]:
        return {
            value
            for child in ast.walk(node)
            if isinstance(child, ast.Constant)
            and (value := _numeric_constant(child)) is not None
        }

    stem_units: dict[str, set[str]] = {}
    stem_lines: dict[str, int] = {}
    for node in ast.walk(tree):
        for name, lineno in bound_names(node):
            unit = _unit_for(name)
            if unit is not None:
                stem = name.lower()
                for suffix in (
                    "_milliseconds",
                    "_seconds",
                    "_minutes",
                    "_hours",
                    "_percent",
                    "_bytes",
                    "_millis",
                    "_micros",
                ):
                    if stem.endswith(suffix):
                        stem = stem[: -len(suffix)]
                        break
                else:
                    for suffix in ("_ms", "_us", "_ns", "_kb", "_mb", "_gb", "_tb"):
                        if stem.endswith(suffix):
                            stem = stem[: -len(suffix)]
                            break
                if stem.endswith(("_sec", "_secs", "_min", "_mins", "_s", "_b")):
                    stem = stem.rsplit("_", 1)[0]
                if stem in stem_units and unit not in stem_units[stem]:
                    findings.append(
                        PolicyFinding(
                            rel,
                            lineno,
                            1,
                            "BHUNIT003",
                            (
                                f"stem `{stem}` is bound as both "
                                f"{sorted(stem_units[stem])[0]} and {unit}; "
                                "one contract per stem"
                            ),
                            "warning",
                        ),
                    )
                stem_units.setdefault(stem, set()).add(unit)
                stem_lines.setdefault(stem, lineno)
            elif needs_unit(name):
                findings.append(
                    PolicyFinding(
                        rel,
                        lineno,
                        1,
                        "BHUNIT001",
                        (
                            f"unit-bearing name `{name}` is bound to a bare "
                            "number with no unit suffix; suffix the unit "
                            f"(`{name}_ms`, `{name}_s`, …)"
                        ),
                        "warning",
                    ),
                )
        if isinstance(node, (ast.BinOp, ast.Compare)):
            numbers = expr_numbers(node)
            if numbers & _CONVERSION_FACTORS:
                continue
            units = expr_units(node)
            dims: dict[str, set[str]] = {}
            for unit in units:
                dims.setdefault(_UNIT_DIMENSIONS.get(unit, unit), set()).add(unit)
            multi = sorted({u for ds in dims.values() if len(ds) > 1 for u in ds})
            if multi:
                findings.append(
                    PolicyFinding(
                        rel,
                        node.lineno,
                        node.col_offset + 1,
                        "BHUNIT002",
                        (
                            f"mixing {multi[0]} with {multi[1]} in one "
                            "expression; convert explicitly (×/÷1000)"
                        ),
                        "error",
                    ),
                )
                continue
            bare = {n for n in numbers if n != 0 and n != 0.0}
            scales = isinstance(node, ast.BinOp) and not isinstance(
                node.op, (ast.Add, ast.Sub)
            )
            if units and bare and not scales:
                findings.append(
                    PolicyFinding(
                        rel,
                        node.lineno,
                        node.col_offset + 1,
                        "BHUNIT002",
                        (
                            f"bare number in {sorted(units)[0]} arithmetic; "
                            "suffix the unit or convert explicitly"
                        ),
                        "error",
                    ),
                )
    return findings


# trace:v1 id=impl.src-bughunt-policy_scan.discover-env-uses work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def discover_env_uses(root: Path, source_paths: Iterable[str]) -> list[EnvUse]:
    out: list[EnvUse] = []
    for path in _files(root, source_paths):
        try:
            tree = ast.parse(path.read_text(errors="replace"))
        except (OSError, SyntaxError):
            continue
        rel = path.relative_to(root).as_posix()
        parents: dict[ast.AST, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[child] = parent
        for node in ast.walk(tree):
            key: str | None = None
            required = True
            default: object | None = None
            inferred = "str"
            if isinstance(node, ast.Subscript) and _call_name(node.value) in {
                "os.environ",
                "environ",
            }:
                value = _literal(node.slice)
                if isinstance(value, str):
                    key = value
            elif isinstance(node, ast.Call):
                name = _call_name(node.func)
                if (
                    name in {"os.getenv", "getenv", "os.environ.get", "environ.get"}
                    and node.args
                ):
                    value = _literal(node.args[0])
                    if isinstance(value, str):
                        key = value
                        required = False
                        default = _literal(node.args[1]) if len(node.args) > 1 else None
                        if len(node.args) < 2 or default is None:
                            required = True
            if key is None:
                continue
            enclosing = parents.get(node)
            if isinstance(enclosing, ast.Call):
                wrapper = _call_name(enclosing.func).split(".")[-1]
                if wrapper in {"int", "float", "bool", "str"}:
                    inferred = wrapper
            out.append(
                EnvUse(
                    name=key,
                    path=rel,
                    line=getattr(node, "lineno", 1),
                    required=required,
                    default=default,
                    inferred_type=inferred,
                    unit=_unit_for(key),
                    accepted_range=_range_for_variable(
                        tree,
                        _assigned_name(node, parents) or "",
                    ),
                    secret_like=bool(SECRET_NAME.search(key)),
                ),
            )
    # Keep the strongest requirement and first evidence for each key.
    merged: dict[str, EnvUse] = {}
    for item in out:
        prev = merged.get(item.name)
        if prev is None or (item.required and not prev.required):
            merged[item.name] = item
        elif prev.default is None and item.default is not None:
            prev.default = item.default
        if prev and prev.unit is None and item.unit is not None:
            prev.unit = item.unit
        if prev and prev.accepted_range is None and item.accepted_range is not None:
            prev.accepted_range = item.accepted_range
    return sorted(merged.values(), key=lambda x: x.name)


# trace:v1 id=impl.src-bughunt-policy_scan.-parse-env-example work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _parse_env_example(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    values: dict[str, str] = {}
    for line in path.read_text(errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key.strip()):
            values[key.strip()] = value.strip().strip("\"'")
    return values


# trace:v1 id=impl.src-bughunt-policy_scan.-looks-real-secret work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _looks_real_secret(name: str, value: str) -> bool:
    low = value.strip().lower()
    if low in PLACEHOLDER_VALUES or low.startswith(("example_", "test_")):
        return False
    if "${" in value or (value.startswith("<") and value.endswith(">")):
        return False
    if "PRIVATE KEY-----" in value:
        return True
    # Known high-signal token shapes.
    if re.match(
        r"^(?:sk-|ghp_|github_pat_|xox[baprs]-|AKIA)[A-Za-z0-9_\-]{12,}$",
        value,
    ):
        return True
    # Secret-named variables should not ship plausible long credentials.
    return bool(
        SECRET_NAME.search(name)
        and len(value) >= 16
        and re.fullmatch(r"[A-Za-z0-9_./+=:@\-]+", value),
    )


# trace:v1 id=impl.src-bughunt-policy_scan.ensure-env-example work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def ensure_env_example(
    root: Path,
    source_paths: Iterable[str],
) -> tuple[Path | None, list[EnvUse]]:
    uses = discover_env_uses(root, source_paths)
    if not uses:
        return None, []
    path = root / ".env.example"
    existing_text = path.read_text(errors="replace") if path.exists() else ""
    begin = "# BEGIN BUGHUNT MANAGED ENV CONTRACT"
    end = "# END BUGHUNT MANAGED ENV CONTRACT"
    # Preserve user-owned entries and comments; replace only BugHunt's managed block.
    outside = existing_text
    if begin in outside and end in outside:
        start = outside.index(begin)
        finish = outside.index(end, start) + len(end)
        outside = (outside[:start] + outside[finish:]).strip("\n")
    existing_values = _parse_env_example(path) if path.exists() else {}
    lines = [
        begin,
        (
            "# Generated from static environment-variable use. "
            "Never contains real secrets."
        ),
    ]
    for item in uses:
        if item.name in existing_values and item.name not in _parse_managed_keys(
            existing_text,
            begin,
            end,
        ):
            continue
        status = "REQUIRED" if item.required else "OPTIONAL"
        details = [status, f"type: {item.inferred_type}"]
        if item.default is not None and not item.secret_like:
            details.append(f"default: {item.default!r}")
        if item.unit:
            details.append(f"unit: {item.unit}")
        if item.accepted_range:
            details.append(f"accepted range: {item.accepted_range}")
        if item.default is not None and not item.secret_like:
            details.append(f"example: {item.default!r}")
        details.append(f"source: {item.path}:{item.line}")
        lines.append("# " + " | ".join(details))
        if item.secret_like or item.default is None:
            value = ""
        elif isinstance(item.default, bool):
            value = "true" if item.default else "false"
        elif isinstance(item.default, (str, int, float)):
            value = str(item.default)
        else:
            value = ""
        lines.append(f"{item.name}={value}")
    lines.append(end)
    new_text = (
        outside.rstrip() + ("\n\n" if outside.strip() else "") + "\n".join(lines) + "\n"
    )
    _ = path.write_text(new_text)
    inventory = root / ".bughunt" / "generated" / "env-contract.json"
    inventory.parent.mkdir(parents=True, exist_ok=True)
    _ = inventory.write_text(
        json.dumps(
            {"schema_version": 1, "variables": [asdict(x) for x in uses]},
            indent=2,
        )
        + "\n",
    )
    return path, uses


def _parse_managed_keys(text: str, begin: str, end: str) -> set[str]:
    if begin not in text or end not in text:
        return set()
    start = text.index(begin)
    finish = text.index(end, start)
    body = text[start:finish]
    keys: set[str] = set()
    for line in body.splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key = line.split("=", 1)[0].strip()
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
                keys.add(key)
    return keys


def _module_tokens(path: Path, root: Path) -> set[str]:
    rel = path.relative_to(root).with_suffix("")
    return {x.lower() for part in rel.parts for x in re.split(r"[_\-.]", part) if x}


# trace:v1 id=impl.src-bughunt-policy-scan.-finallyjumpvisitor work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
class _FinallyJumpVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.nodes: list[ast.Return | ast.Break | ast.Continue] = []

    # trace:v1 id=impl.src-bughunt-policy-scan.visit-return work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    @override
    def visit_Return(self, node: ast.Return) -> None:
        self.nodes.append(node)

    # trace:v1 id=impl.src-bughunt-policy-scan.visit-break work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    @override
    def visit_Break(self, node: ast.Break) -> None:
        self.nodes.append(node)

    # trace:v1 id=impl.src-bughunt-policy-scan.visit-continue work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    @override
    def visit_Continue(self, node: ast.Continue) -> None:
        self.nodes.append(node)

    # Control flow inside nested scopes does not exit the enclosing finally.
    # trace:v1 id=impl.src-bughunt-policy-scan.visit-functiondef work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    @override
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        _ = node
        return

    # trace:v1 id=impl.src-bughunt-policy-scan.visit-asyncfunctiondef work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    @override
    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        _ = node
        return

    # trace:v1 id=impl.src-bughunt-policy-scan.visit-lambda work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    @override
    def visit_Lambda(self, node: ast.Lambda) -> None:
        _ = node
        return

    # trace:v1 id=impl.src-bughunt-policy-scan.visit-classdef work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    @override
    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        _ = node
        return


def _finally_jump_nodes(tree: ast.AST) -> list[ast.Return | ast.Break | ast.Continue]:
    out: list[ast.Return | ast.Break | ast.Continue] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try) or not node.finalbody:
            continue
        visitor = _FinallyJumpVisitor()
        for stmt in node.finalbody:
            visitor.visit(stmt)
        out.extend(visitor.nodes)
    return out


# trace:v1 id=impl.src-bughunt-policy_scan.-literal-operational-kwargs work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _literal_operational_kwargs(
    tree: ast.AST,
) -> Iterable[tuple[ast.keyword, str, object]]:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg is None or not CONFIG_NAME.search(keyword.arg):
                continue
            value = _literal(keyword.value)
            if (
                isinstance(value, (str, int, float, bool))
                and not isinstance(value, str)
            ) or (isinstance(value, str) and value):
                yield keyword, keyword.arg, value


def _annotation_text(node: ast.AST | None) -> str:
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except (ValueError, TypeError):
        return ""


# trace:v1 id=impl.src-bughunt-policy_scan.-signature-annotations work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _signature_annotations(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[tuple[ast.AST, str]]:
    out: list[tuple[ast.AST, str]] = []
    args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
    if node.args.vararg is not None:
        args.append(node.args.vararg)
    if node.args.kwarg is not None:
        args.append(node.args.kwarg)
    for arg in args:
        text = _annotation_text(arg.annotation)
        if text:
            out.append((arg, text))
    if node.returns is not None:
        text = _annotation_text(node.returns)
        if text:
            out.append((node.returns, text))
    return out


# trace:v1 id=impl.src-bughunt-policy_scan.-scan-source-policies work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _scan_source_policies(
    root: Path,
    source_paths: Iterable[str],
) -> list[PolicyFinding]:
    findings: list[PolicyFinding] = []
    for path in _files(root, source_paths):
        rel = path.relative_to(root).as_posix()
        try:
            source = path.read_text(errors="replace")
            tree = ast.parse(source)
        except (OSError, SyntaxError):
            continue
        # High-confidence control-flow hazards are enforced even when Ruff or
        # ast-grep is unavailable. This intentionally overlaps Ruff B012.
        for jump in _finally_jump_nodes(tree):
            findings.append(
                PolicyFinding(
                    rel,
                    getattr(jump, "lineno", 1),
                    getattr(jump, "col_offset", 0) + 1,
                    "BHCTRL001",
                    (
                        f"`{type(jump).__name__.lower()}` inside `finally` "
                        "can suppress an active exception or override control "
                        "flow; move the jump outside the finally block"
                    ),
                    "error",
                ),
            )

        importer_tokens = _module_tokens(path, root)
        persistence_aliases: set[str] = set()
        for import_node in tree.body:
            if isinstance(import_node, ast.Import):
                for alias in import_node.names:
                    if {
                        x.lower() for x in re.split(r"[._\-]", alias.name)
                    } & PERSIST_IMPL:
                        persistence_aliases.add(
                            alias.asname or alias.name.split(".")[0],
                        )
            elif (
                isinstance(import_node, ast.ImportFrom)
                and import_node.module
                and {x.lower() for x in re.split(r"[._\-]", import_node.module)}
                & PERSIST_IMPL
            ):
                persistence_aliases.update(
                    alias.asname or alias.name for alias in import_node.names
                )
        for node in tree.body:
            imported: list[str] = []
            if isinstance(node, ast.Import):
                imported = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported = [node.module]
            for name in imported:
                imported_tokens = {x.lower() for x in re.split(r"[._\-]", name)}
                if importer_tokens & UPPER_LAYER and imported_tokens & PERSIST_IMPL:
                    findings.append(
                        PolicyFinding(
                            rel,
                            getattr(node, "lineno", 1),
                            1,
                            "BHPERS001",
                            (
                                f"higher-layer module imports persistence "
                                f"implementation detail `{name}`; expose a deliberate "
                                "repository/protocol contract instead of coupling the "
                                "layer to the storage implementation"
                            ),
                            "warning",
                        ),
                    )
                if any(
                    part.startswith("_") and not part.startswith("__")
                    for part in name.split(".")
                ):
                    findings.append(
                        PolicyFinding(
                            rel,
                            getattr(node, "lineno", 1),
                            1,
                            "BHARCH001",
                            (
                                f"module imports internal implementation "
                                f"module `{name}` across a source boundary; use a "
                                "public subsystem contract unless this dependency "
                                "is intentional"
                            ),
                            "warning",
                        ),
                    )
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name.startswith("_") and not alias.name.startswith("__"):
                        findings.append(
                            PolicyFinding(
                                rel,
                                getattr(node, "lineno", 1),
                                1,
                                "BHARCH002",
                                (
                                    f"module imports private implementation symbol "
                                    f"`{alias.name}` from `{node.module or '.'}`; "
                                    "do not couple subsystems through private "
                                    "implementation details"
                                ),
                                "warning",
                            ),
                        )
        if importer_tokens & UPPER_LAYER and persistence_aliases:
            for fn in tree.body:
                if not isinstance(
                    fn,
                    (ast.FunctionDef, ast.AsyncFunctionDef),
                ) or fn.name.startswith("_"):
                    continue
                for ann_node, annotation in _signature_annotations(fn):
                    root_name = annotation.split(".", 1)[0].split("[", 1)[0]
                    if root_name in persistence_aliases or any(
                        re.search(rf"\b{re.escape(alias)}\b", annotation)
                        for alias in persistence_aliases
                    ):
                        findings.append(
                            PolicyFinding(
                                rel,
                                getattr(ann_node, "lineno", fn.lineno),
                                1,
                                "BHPERS002",
                                (
                                    f"public higher-layer function `{fn.name}` exposes "
                                    f"persistence-specific type `{annotation}` in its "
                                    "signature; expose a domain/protocol abstraction "
                                    "unless persistence is intentionally part of the "
                                    "contract"
                                ),
                                "warning",
                            ),
                        )

        # Operational knobs hard-coded outside an obvious configuration mechanism.
        if not CONFIG_MODULE.search(rel):
            for node in tree.body:
                targets: list[str] = []
                value: ast.AST | None = None
                if isinstance(node, (ast.Assign, ast.AnnAssign)):
                    value = node.value
                    raw_targets = (
                        node.targets if isinstance(node, ast.Assign) else [node.target]
                    )
                    targets = [t.id for t in raw_targets if isinstance(t, ast.Name)]
                if not isinstance(value, ast.Constant):
                    continue
                for name in targets:
                    if CONFIG_NAME.search(name) and not name.isupper():
                        findings.append(
                            PolicyFinding(
                                rel,
                                getattr(node, "lineno", 1),
                                1,
                                "BHCFG004",
                                (
                                    f"operational configuration-like value `{name}` is "
                                    "hard-coded outside an obvious "
                                    "config/settings/constants mechanism; make it "
                                    "typed/configurable or promote it to an uppercase "
                                    "invariant constant"
                                ),
                                "note",
                            ),
                        )
        if not CONFIG_MODULE.search(rel):
            for keyword, op_name, op_value in _literal_operational_kwargs(tree):
                # Tiny invariants such as zero/one booleans are common and often
                # meaningful; still surface them as notes rather than pretending
                # every literal must be environment-driven.
                findings.append(
                    PolicyFinding(
                        rel,
                        getattr(keyword, "lineno", 1),
                        getattr(keyword, "col_offset", 0) + 1,
                        "BHCFG005",
                        (
                            f"operational keyword `{op_name}={op_value!r}` "
                            "is hard-coded at a call site; prefer "
                            "typed/config-file/env/CLI/generated configuration "
                            "unless this value is a genuine invariant"
                        ),
                        "note",
                    ),
                )
        findings.extend(_scan_unit_policies(tree, rel))
    return findings


def _test_calls(fn: ast.AST) -> list[str]:
    calls: list[str] = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            calls.append(_call_name(node.func))
    return calls


# trace:v1 id=impl.src-bughunt-policy_scan.-scan-test-policies work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _scan_test_policies(root: Path, test_paths: Iterable[str]) -> list[PolicyFinding]:
    findings: list[PolicyFinding] = []
    for path in _files(root, test_paths):
        rel = path.relative_to(root).as_posix()
        try:
            source = path.read_text(errors="replace")
            tree = ast.parse(source)
        except (OSError, SyntaxError):
            continue
        for node in tree.body:
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name.startswith("_") and not alias.name.startswith("__"):
                        findings.append(
                            PolicyFinding(
                                rel,
                                node.lineno,
                                1,
                                "BHTEST001",
                                (
                                    f"test imports private implementation symbol "
                                    f"`{alias.name}` directly; prefer asserting public "
                                    "behavior unless the private API is intentionally "
                                    "contractual"
                                ),
                                "warning",
                            ),
                        )
        for fn in ast.walk(tree):
            if not isinstance(
                fn,
                (ast.FunctionDef, ast.AsyncFunctionDef),
            ) or not fn.name.startswith("test"):
                continue
            calls = _test_calls(fn)
            exact_sequence = [c for c in calls if c.endswith("assert_has_calls")]
            mock_detail_refs = [
                c
                for c in calls
                if c.endswith(("assert_called_once_with", "assert_called_with"))
            ]
            segment = ast.get_source_segment(source, fn) or ""
            if (
                exact_sequence
                or ".mock_calls" in segment
                or ".call_args_list" in segment
            ):
                findings.append(
                    PolicyFinding(
                        rel,
                        fn.lineno,
                        1,
                        "BHTEST002",
                        (
                            f"test `{fn.name}` asserts collaborator "
                            "call sequence/internal mock history; verify "
                            "behavior/results unless call ordering is part of "
                            "the contract"
                        ),
                        "warning",
                    ),
                )
            patch_count = sum(
                1
                for c in calls
                if c.endswith(
                    ("patch", "patch.object", "mocker.patch", "monkeypatch.setattr"),
                )
                or "patch" in c.split(".")[-1].lower()
            )
            if patch_count >= 5 and len(mock_detail_refs) >= 2:
                findings.append(
                    PolicyFinding(
                        rel,
                        fn.lineno,
                        1,
                        "BHTEST004",
                        (
                            f"test `{fn.name}` heavily mocks collaborators "
                            f"({patch_count} patch operations) and asserts "
                            "orchestration details; this is brittle and can "
                            "mirror implementation rather than behavior"
                        ),
                        "warning",
                    ),
                )
            for inner in ast.walk(fn):
                if not isinstance(inner, ast.Assert) or not isinstance(
                    inner.test,
                    ast.Compare,
                ):
                    continue
                operands = [inner.test.left, *inner.test.comparators]
                long_literal = next(
                    (
                        x.value
                        for x in operands
                        if isinstance(x, ast.Constant)
                        and isinstance(x.value, str)
                        and len(x.value) >= 1000
                    ),
                    None,
                )
                if long_literal is not None:
                    findings.append(
                        PolicyFinding(
                            rel,
                            inner.lineno,
                            1,
                            "BHTEST003",
                            (
                                f"test `{fn.name}` asserts an enormous "
                                f"literal/snapshot ({len(long_literal)} characters); "
                                "prefer semantic assertions over generated "
                                "source/text snapshots"
                            ),
                            "warning",
                        ),
                    )
                string_literals = [
                    x.value
                    for x in operands
                    if isinstance(x, ast.Constant) and isinstance(x.value, str)
                ]
                other_texts = []
                for operand in operands:
                    if isinstance(operand, (ast.Name, ast.Attribute, ast.Call)):
                        with suppress(ValueError, TypeError):
                            other_texts.append(ast.unparse(operand).lower())
                if any(len(value) >= 200 for value in string_literals) and any(
                    re.search(r"(?:generated|source|code|script|sql|html|render)", text)
                    for text in other_texts
                ):
                    findings.append(
                        PolicyFinding(
                            rel,
                            inner.lineno,
                            1,
                            "BHTEST005",
                            (
                                f"test `{fn.name}` compares generated/source-like "
                                "output to a large exact string; prefer semantic "
                                "assertions unless exact source text is itself the "
                                "public contract"
                            ),
                            "warning",
                        ),
                    )
        findings.extend(_scan_unit_policies(tree, rel))
    return findings


# trace:v1 id=impl.src-bughunt-policy_scan.-looks-like-user-format-operation work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _looks_like_user_format_operation(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    param_names = {
        arg.arg.lower()
        for arg in (node.args.posonlyargs + node.args.args + node.args.kwonlyargs)
    }
    if param_names & {
        "path",
        "file",
        "filename",
        "stream",
        "archive",
        "backup",
        "data",
        "content",
        "payload",
    }:
        return True
    io_markers = (
        "open",
        "read_text",
        "write_text",
        "read_bytes",
        "write_bytes",
        "json.dump",
        "json.dumps",
        "json.load",
        "json.loads",
        "yaml.",
        "toml",
        "pickle.",
        "csv.",
        "zipfile.",
        "tarfile.",
        "encode",
        "decode",
        "shutil.make_archive",
        "shutil.unpack_archive",
    )
    for inner in ast.walk(node):
        if isinstance(inner, ast.Call):
            called = _call_name(inner.func).lower()
            if any(marker in called for marker in io_markers):
                return True
    return False


# trace:v1 id=impl.src-bughunt-policy_scan.-roundtrip-inventory work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _roundtrip_inventory(
    root: Path,
    source_paths: Iterable[str],
) -> tuple[list[tuple[str, str, str, int]], list[tuple[str, str, str, int]]]:
    """Return matched inverse pairs and one-sided export/import-like operations."""
    pairs: list[tuple[str, str, str, int]] = []
    orphans: list[tuple[str, str, str, int]] = []
    for path in _files(root, source_paths):
        try:
            tree = ast.parse(path.read_text(errors="replace"))
        except (OSError, SyntaxError):
            continue
        owners: dict[str, dict[str, ast.FunctionDef | ast.AsyncFunctionDef]] = {"": {}}
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                owners[""][node.name] = node
            elif isinstance(node, ast.ClassDef):
                owners[node.name] = {
                    child.name: child
                    for child in node.body
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                }
        rel = path.relative_to(root).as_posix()
        for owner, functions in owners.items():
            names = set(functions)
            for left_token, right_token in ROUNDTRIP_PAIRS:
                for name, node in functions.items():
                    parts = name.split("_")
                    matched_token: str | None = None
                    counterpart: str | None = None
                    if left_token in parts:
                        idx = parts.index(left_token)
                        matched_token = left_token
                        counterpart = "_".join(
                            parts[:idx] + [right_token] + parts[idx + 1 :],
                        )
                    elif right_token in parts:
                        idx = parts.index(right_token)
                        matched_token = right_token
                        counterpart = "_".join(
                            parts[:idx] + [left_token] + parts[idx + 1 :],
                        )
                    if counterpart is None:
                        continue
                    qualified = f"{owner}.{name}" if owner else name
                    qualified_counterpart = (
                        f"{owner}.{counterpart}" if owner else counterpart
                    )
                    if counterpart in names:
                        # Record each pair exactly once from the outward/export side.
                        if matched_token == left_token:
                            pairs.append(
                                (qualified, qualified_counterpart, rel, node.lineno),
                            )
                    elif _looks_like_user_format_operation(node):
                        subject_tokens = {
                            part
                            for part in parts
                            if part not in {left_token, right_token, ""}
                        }
                        infrastructure_words = {
                            "config",
                            "configured",
                            "configuration",
                            "linter",
                            "module",
                            "package",
                            "plugin",
                            "library",
                            "lib",
                            "path",
                        }
                        if not (subject_tokens & infrastructure_words):
                            orphans.append(
                                (qualified, qualified_counterpart, rel, node.lineno),
                            )
    return pairs, orphans


# trace:v1 id=impl.src-bughunt-policy_scan.-scan-roundtrip-coverage work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _scan_roundtrip_coverage(
    root: Path,
    source_paths: Iterable[str],
    test_paths: Iterable[str],
) -> list[PolicyFinding]:
    tests: list[set[str]] = []
    for path in _files(root, test_paths):
        try:
            tree = ast.parse(path.read_text(errors="replace"))
        except (OSError, SyntaxError):
            continue
        for fn in ast.walk(tree):
            if isinstance(
                fn,
                (ast.FunctionDef, ast.AsyncFunctionDef),
            ) and fn.name.startswith("test"):
                tests.append({x.split(".")[-1] for x in _test_calls(fn)})
    out: list[PolicyFinding] = []
    pairs, orphans = _roundtrip_inventory(root, source_paths)
    for export_name, import_name, rel, line in pairs:
        export_leaf = export_name.split(".")[-1]
        import_leaf = import_name.split(".")[-1]
        if any(export_leaf in calls and import_leaf in calls for calls in tests):
            continue
        out.append(
            PolicyFinding(
                rel,
                line,
                1,
                "BHRT001",
                (
                    f"supported export/import pair `{export_name}` -> `{import_name}` "
                    "has no detected round-trip test; everything exported should "
                    "come home without silent semantic loss"
                ),
                "warning",
            ),
        )
    for operation, expected, rel, line in orphans:
        leaf = operation.split(".")[-1]
        token = next(
            (tok for pair in ROUNDTRIP_PAIRS for tok in pair if tok in leaf.split("_")),
            "export/import",
        )
        out.append(
            PolicyFinding(
                rel,
                line,
                1,
                "BHRT002",
                (
                    f"`{operation}` looks like a supported {token} operation but no "
                    f"inverse `{expected}` exists alongside it; if this is a "
                    "user-owned format, provide the reverse path or explicitly "
                    "document the one-way contract"
                ),
                "warning",
            ),
        )
    return out


# trace:v1 id=impl.src-bughunt-policy_scan.scan work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def scan(
    root: Path,
    source_paths: Iterable[str],
    test_paths: Iterable[str],
) -> list[PolicyFinding]:
    findings: list[PolicyFinding] = []
    uses = discover_env_uses(root, source_paths)
    env_file = root / ".env.example"
    env_values = _parse_env_example(env_file)
    if uses and not env_file.exists():
        first = uses[0]
        findings.append(
            PolicyFinding(
                first.path,
                first.line,
                1,
                "BHCFG001",
                (
                    "environment-driven configuration detected "
                    "but `.env.example` is missing"
                ),
                "warning",
            ),
        )
    elif uses:
        for item in uses:
            if item.name not in env_values:
                findings.append(
                    PolicyFinding(
                        item.path,
                        item.line,
                        1,
                        "BHCFG002",
                        (
                            f"environment variable `{item.name}` is used in code but "
                            "missing from `.env.example`"
                        ),
                        "warning",
                    ),
                )
    if env_file.exists():
        for key, value in env_values.items():
            if _looks_real_secret(key, value):
                findings.append(
                    PolicyFinding(
                        ".env.example",
                        1,
                        1,
                        "BHCFG003",
                        (
                            f"`.env.example` contains a value for secret-like variable "
                            f"`{key}` that looks like a real credential; examples must "
                            "never contain real secrets"
                        ),
                        "error",
                    ),
                )
    findings.extend(_scan_source_policies(root, source_paths))
    findings.extend(_scan_test_policies(root, test_paths))
    findings.extend(_scan_roundtrip_coverage(root, source_paths, test_paths))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    _ = parser.add_argument("--root", type=Path, default=Path.cwd())
    _ = parser.add_argument("--source", action="append", default=[])
    _ = parser.add_argument("--test", action="append", default=[])
    args = parser.parse_args(argv)
    root = args.root.resolve()
    source = args.source or ["src"]
    tests = args.test or ["tests"]
    findings = scan(root, source, tests)
    print(json.dumps([asdict(x) for x in findings]))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
