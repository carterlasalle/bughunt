# Copyright (c) 2026 Carter LaSalle
from __future__ import annotations

import ast
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from typing_extensions import override

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

SERIALIZATION_BOUNDARIES = {
    "json.dump",
    "json.dumps",
    "send",
    "sendall",
    "put",
    "put_nowait",
    "publish",
    "emit",
    "write",
    "write_text",
    "write_bytes",
    "save",
}
VALIDATORS = {
    "model_validate",
    "model_validate_json",
    "validate_python",
    "validate_json",
    "parse_obj",
    "parse_raw",
    "loads",
    "from_dict",
    "from_json",
}
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "request", "send"}
DB_CALLS = {
    "execute",
    "executemany",
    "query",
    "filter",
    "filter_by",
    "get",
    "select",
    "scalars",
    "scalar",
}


@dataclass(frozen=True, slots=True)
class SeamFinding:
    code: str
    message: str
    path: str
    line: int
    severity: str = "warning"


# trace:v1 id=impl.src-bughunt-seam_scan.-iter-python work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _iter_python(root: Path, paths: Iterable[str]) -> Iterable[Path]:
    seen: set[Path] = set()
    for rel in paths:
        base = root / rel
        if base.is_file() and base.suffix == ".py":
            candidates = [base]
        elif base.is_dir():
            candidates = list(base.rglob("*.py"))
        else:
            continue
        for path in candidates:
            if path in seen or any(part in IGNORED_DIRS for part in path.parts):
                continue
            seen.add(path)
            yield path


# trace:v1 id=impl.src-bughunt-seam_scan.-rel work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _rel(root: Path, path: Path) -> str:
    try:
        return (
            path.resolve(strict=False)
            .relative_to(root.resolve(strict=False))
            .as_posix()
        )
    except ValueError:
        return path.as_posix()


# trace:v1 id=impl.src-bughunt-seam_scan.-call-name work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _call_name(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _string_key(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


# trace:v1 id=impl.src-bughunt-seam_scan.-dict-literal-keys work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _dict_literal_keys(node: ast.AST) -> set[str]:
    if not isinstance(node, ast.Dict):
        return set()
    return {
        key
        for raw in node.keys
        if raw is not None and (key := _string_key(raw)) is not None
    }


# trace:v1 id=impl.src-bughunt-seam_scan.-DictState work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
@dataclass(slots=True)
class _DictState:
    writes: set[str]
    reads: set[str]
    boundary: bool = False
    line: int = 1
    soft_reads: set[str] = field(default_factory=set)


# trace:v1 id=impl.src-bughunt-seam_scan.-functioncollector work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
class _FunctionCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.dicts: dict[str, _DictState] = {}
        self.http_json_lines: list[int] = []
        self.validated_names: set[str] = set()
        self.db_in_loop: list[tuple[int, str]] = []
        self._loop_depth = 0

    def _state(self, name: str, line: int) -> _DictState:
        return self.dicts.setdefault(name, _DictState(set(), set(), False, line))

    # trace:v1 id=impl.src-bughunt-seam-scan.visit-assign work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    @override
    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name) and isinstance(node.value, ast.Dict):
                st = self._state(target.id, node.lineno)
                st.writes.update(_dict_literal_keys(node.value))
            if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
                key = _string_key(target.slice)
                if key is not None:
                    self._state(target.value.id, node.lineno).writes.add(key)
        if isinstance(node.value, ast.Call):
            call = _call_name(node.value.func)
            if call.endswith(".json"):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.http_json_lines.append(node.lineno)
                        _ = self._state(target.id, node.lineno)
            if call.rsplit(".", 1)[-1] in VALIDATORS:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.validated_names.add(target.id)
        self.generic_visit(node)

    # trace:v1 id=impl.src-bughunt-seam_scan--functioncollector.visit-annassign work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
    @override
    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name) and isinstance(node.value, ast.Dict):
            self._state(node.target.id, node.lineno).writes.update(
                _dict_literal_keys(node.value),
            )
        self.generic_visit(node)

    # trace:v1 id=impl.src-bughunt-seam-scan.visit-subscript work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    @override
    def visit_Subscript(self, node: ast.Subscript) -> None:
        if isinstance(node.ctx, ast.Load) and isinstance(node.value, ast.Name):
            key = _string_key(node.slice)
            if key is not None:
                self._state(node.value.id, node.lineno).reads.add(key)
        self.generic_visit(node)

    # trace:v1 id=impl.src-bughunt-seam_scan--functioncollector.visit-call work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
    @override
    def visit_Call(self, node: ast.Call) -> None:
        call = _call_name(node.func)
        leaf = call.rsplit(".", 1)[-1]
        if isinstance(node.func, ast.Attribute) and isinstance(
            node.func.value,
            ast.Name,
        ):
            obj = node.func.value.id
            if node.func.attr in {"get", "pop", "setdefault"} and node.args:
                key = _string_key(node.args[0])
                # URL-path-shaped `.get("/...")` is an HTTP call, not a dict
                # read; recording it fabricates seam dictionaries from clients.
                if key is not None and not (
                    node.func.attr == "get" and key.startswith("/")
                ):
                    state = self._state(obj, node.lineno)
                    if node.func.attr == "setdefault":
                        state.writes.add(key)
                    else:
                        state.reads.add(key)
                        if node.func.attr == "get":
                            state.soft_reads.add(key)
        if leaf in SERIALIZATION_BOUNDARIES or call in SERIALIZATION_BOUNDARIES:
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id in self.dicts:
                    self.dicts[arg.id].boundary = True
        if leaf in VALIDATORS:
            for arg in node.args:
                if isinstance(arg, ast.Name):
                    self.validated_names.add(arg.id)
        if leaf in DB_CALLS and self._loop_depth:
            self.db_in_loop.append((node.lineno, call))
        self.generic_visit(node)

    # trace:v1 id=impl.src-bughunt-seam-scan.visit-for work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    @override
    def visit_For(self, node: ast.For) -> None:
        self._loop_depth += 1
        self.generic_visit(node)
        self._loop_depth -= 1

    # trace:v1 id=impl.src-bughunt-seam-scan.visit-asyncfor work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    @override
    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._loop_depth += 1
        self.generic_visit(node)
        self._loop_depth -= 1

    # trace:v1 id=impl.src-bughunt-seam-scan.visit-while work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    @override
    def visit_While(self, node: ast.While) -> None:
        self._loop_depth += 1
        self.generic_visit(node)
        self._loop_depth -= 1


# trace:v1 id=impl.src-bughunt-seam_scan.-function-infos work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _function_infos(
    tree: ast.AST,
) -> dict[str, tuple[ast.FunctionDef | ast.AsyncFunctionDef, str | None]]:
    out: dict[str, tuple[ast.FunctionDef | ast.AsyncFunctionDef, str | None]] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out[node.name] = (node, node.args.kwarg.arg if node.args.kwarg else None)
    return out


def _call_explicit_keys(call: ast.Call) -> set[str]:
    out = {kw.arg for kw in call.keywords if kw.arg is not None}
    for kw in call.keywords:
        if kw.arg is None:
            out.update(_dict_literal_keys(kw.value))
    return out


# trace:v1 id=impl.src-bughunt-seam_scan.-kwargs-forwards work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _kwargs_forwards(
    tree: ast.AST,
    infos: dict[str, tuple[ast.FunctionDef | ast.AsyncFunctionDef, str | None]],
) -> dict[str, str]:
    """Map wrappers to the callee they forward **kwargs to."""
    forward: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        kwarg = node.args.kwarg.arg if node.args.kwarg else None
        if kwarg:
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    callee = _call_name(child.func).rsplit(".", 1)[-1]
                    if callee in infos and any(
                        kw.arg is None
                        and isinstance(kw.value, ast.Name)
                        and kw.value.id == kwarg
                        for kw in child.keywords
                    ):
                        forward[node.name] = callee
    return forward


# trace:v1 id=impl.src-bughunt-seam_scan.-kwargs-call-keys work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _kwargs_call_keys(
    tree: ast.AST,
    infos: dict[str, tuple[ast.FunctionDef | ast.AsyncFunctionDef, str | None]],
) -> dict[str, list[tuple[int, set[str]]]]:
    """Map callees to the explicit keyword keys each call site passes."""
    call_keys: dict[str, list[tuple[int, set[str]]]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            callee = _call_name(node.func).rsplit(".", 1)[-1]
            keys = _call_explicit_keys(node)
            if callee in infos and keys:
                call_keys.setdefault(callee, []).append((node.lineno, keys))
    return call_keys


# trace:v1 id=impl.src-bughunt-seam_scan.-kwargs-drift work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _kwargs_drift(tree: ast.AST, rel: str) -> list[SeamFinding]:
    infos = _function_infos(tree)
    forward = _kwargs_forwards(tree, infos)
    call_keys = _kwargs_call_keys(tree, infos)
    findings: list[SeamFinding] = []
    for root_name, calls in call_keys.items():
        current = root_name
        visited: set[str] = set()
        while current in forward and current not in visited:
            visited.add(current)
            current = forward[current]
        terminal_info = infos.get(current)
        if not terminal_info:
            continue
        terminal, terminal_kwargs = terminal_info
        if terminal_kwargs:
            continue
        allowed = {
            arg.arg
            for arg in [
                *terminal.args.posonlyargs,
                *terminal.args.args,
                *terminal.args.kwonlyargs,
            ]
            if arg.arg not in {"self", "cls"}
        }
        for line, keys in calls:
            unexpected = sorted(keys - allowed)
            if unexpected and root_name != current:
                findings.append(
                    SeamFinding(
                        "BHSEAM002",
                        (
                            f"**kwargs forwarding chain {root_name} -> {current} can "
                            f"forward key(s) not accepted by terminal signature: "
                            f"{', '.join(unexpected)}"
                        ),
                        rel,
                        line,
                        "error",
                    ),
                )
    return findings


# trace:v1 id=impl.src-bughunt-seam_scan.-external-http-without-validation work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _external_http_without_validation(tree: ast.AST, rel: str) -> list[SeamFinding]:
    findings: list[SeamFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        collector = _FunctionCollector()
        collector.visit(node)
        for name, state in collector.dicts.items():
            # Only hard (subscript) reads of never-written keys are flagged.
            # `.get()` reads are defensive by design, and "written but not
            # read locally" is usually cross-function consumption, whole-object
            # return, or serialization — not drift. Both leniencies were proven
            # against dogfood false positives before this rule first fired.
            hard_reads = state.reads - state.soft_reads
            missing = sorted(hard_reads - state.writes) if state.boundary else []
            if missing:
                findings.append(
                    SeamFinding(
                        "BHSEAM001",
                        (
                            f"serialized/seam dictionary `{name}` reads key(s) never "
                            f"written in the same producer scope: "
                            f"{', '.join(missing)}; possible producer/consumer "
                            "key drift"
                        ),
                        rel,
                        state.line,
                        "error",
                    ),
                )
        # An HTTP .json() result that is directly indexed without any explicit
        # validation in the function is a strong seam-risk signal. We avoid
        # flagging json.loads() generally because local trusted serialization is
        # common and not automatically an external seam.
        for name, state in collector.dicts.items():
            if (
                state.reads
                and state.line in collector.http_json_lines
                and name not in collector.validated_names
            ):
                findings.append(
                    SeamFinding(
                        "BHSEAM005",
                        (
                            f"external HTTP JSON enters `{name}` and is consumed by "
                            "key without runtime schema/model validation"
                        ),
                        rel,
                        state.line,
                        "warning",
                    ),
                )
        for line, call in collector.db_in_loop:
            findings.append(
                SeamFinding(
                    "BHDB001",
                    (
                        f"database/query-like call `{call}` occurs inside a loop; "
                        "inspect for N+1/query explosion or move to a batched "
                        "operation"
                    ),
                    rel,
                    line,
                    "warning",
                ),
            )
    return findings


# trace:v1 id=impl.src-bughunt-seam_scan.-recorded-payload-gap work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _recorded_payload_gap(
    root: Path,
    source_paths: Iterable[str],
    test_paths: Iterable[str],
) -> list[SeamFinding]:
    http_sites: list[tuple[str, int]] = []
    for path in _iter_python(root, source_paths):
        try:
            tree = ast.parse(path.read_text(errors="replace"), filename=str(path))
        except (OSError, SyntaxError):
            # Unreadable or unparseable file; skipped, never fatal
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call = _call_name(node.func).lower()
                leaf = call.rsplit(".", 1)[-1]
                if leaf in HTTP_METHODS and any(
                    token in call
                    for token in ("requests", "httpx", "client", "session")
                ):
                    http_sites.append((_rel(root, path), node.lineno))
    if not http_sites:
        return []
    corpus_markers = (
        "vcr",
        "cassette",
        "responses",
        "respx",
        "recorded_payload",
        "fixture_payload",
    )
    for path in _iter_python(root, test_paths):
        try:
            text = path.read_text(errors="replace").lower()
        except OSError:
            # One bad file never fails a scan; skipped
            continue
        if any(marker in text for marker in corpus_markers):
            return []
    site_path, site_line = http_sites[0]
    return [
        SeamFinding(
            "BHSEAM006",
            (
                f"{len(http_sites)} external HTTP call site(s) detected but no "
                "recorded-response/cassette payload regression corpus was found "
                "in tests"
            ),
            site_path,
            site_line,
            "warning",
        ),
    ]


# trace:v1 id=impl.src-bughunt-seam_scan.-time-boundary-gap work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _time_boundary_gap(
    root: Path,
    source_paths: Iterable[str],
    test_paths: Iterable[str],
) -> list[SeamFinding]:
    sites: list[tuple[str, int]] = []
    for path in _iter_python(root, source_paths):
        try:
            tree = ast.parse(path.read_text(errors="replace"), filename=str(path))
        except (OSError, SyntaxError):
            # Unreadable or unparseable file; skipped, never fatal
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call = _call_name(node.func)
                if call in {
                    "datetime.now",
                    "datetime.utcnow",
                    "date.today",
                    "time.time",
                    "time.monotonic",
                } or call.endswith(".now"):
                    sites.append((_rel(root, path), node.lineno))
    if not sites:
        return []
    markers = (
        "freezegun",
        "freeze_time",
        "time_machine",
        "travel(",
        "leap",
        "dst",
        "timezone",
    )
    for path in _iter_python(root, test_paths):
        try:
            text = path.read_text(errors="replace").lower()
        except OSError:
            # One bad file never fails a scan; skipped
            continue
        if any(marker in text for marker in markers):
            return []
    site_path, site_line = sites[0]
    return [
        SeamFinding(
            "BHTIME001",
            (
                f"{len(sites)} wall-clock/time boundary call(s) detected but no "
                "DST/leap/year-rollover time-control test evidence was found"
            ),
            site_path,
            site_line,
            "warning",
        ),
    ]


# trace:v1 id=impl.src-bughunt-seam_scan.-producer-consumer-key-drift work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _producer_consumer_key_drift(tree: ast.AST, rel: str) -> list[SeamFinding]:
    """Pair local dict-return producers with their consumers.

    This deliberately requires a direct local call and a statically-known dict
    return shape, which keeps the signal much stronger than global variable-name
    matching while still catching common json.loads/adapter drift patterns.
    """
    producers: dict[str, tuple[set[str], int]] = {}
    for node in getattr(tree, "body", []):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        keysets: list[set[str]] = []
        for child in ast.walk(node):
            if isinstance(child, ast.Return) and isinstance(child.value, ast.Dict):
                keys = _dict_literal_keys(child.value)
                if keys:
                    keysets.append(keys)
        if keysets and all(keys == keysets[0] for keys in keysets[1:]):
            producers[node.name] = (keysets[0], node.lineno)
    if not producers:
        return []

    findings: list[SeamFinding] = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        assigned: dict[str, tuple[str, int]] = {}
        reads: dict[str, set[str]] = {}
        for child in ast.walk(fn):
            if isinstance(child, ast.Assign) and isinstance(child.value, ast.Call):
                callee = _call_name(child.value.func).rsplit(".", 1)[-1]
                if callee in producers:
                    for target in child.targets:
                        if isinstance(target, ast.Name):
                            assigned[target.id] = (callee, child.lineno)
            if (
                isinstance(child, ast.Subscript)
                and isinstance(child.ctx, ast.Load)
                and isinstance(child.value, ast.Name)
            ):
                key = _string_key(child.slice)
                if key is not None:
                    reads.setdefault(child.value.id, set()).add(key)
            if (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Attribute)
                and isinstance(child.func.value, ast.Name)
                and child.func.attr in {"get", "pop"}
                and child.args
            ):
                key = _string_key(child.args[0])
                if key is not None:
                    reads.setdefault(child.func.value.id, set()).add(key)
        for var, (producer, line) in assigned.items():
            expected = producers[producer][0]
            unexpected = sorted(reads.get(var, set()) - expected)
            if unexpected:
                findings.append(
                    SeamFinding(
                        "BHSEAM003",
                        (
                            f"consumer of `{producer}()` reads key(s) absent from the "
                            f"producer's statically-known return shape: "
                            f"{', '.join(unexpected)}"
                        ),
                        rel,
                        line,
                        "error",
                    ),
                )
    return findings


def _class_fields(tree: ast.AST) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for node in getattr(tree, "body", []):
        if not isinstance(node, ast.ClassDef):
            continue
        fields: set[str] = set()
        for child in node.body:
            if isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name):
                fields.add(child.target.id)
            elif isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name) and not target.id.startswith("_"):
                        fields.add(target.id)
        if fields:
            out[node.name] = fields
    return out


# trace:exempt reason=internal-detail
def _load_schema_doc(path: Path) -> object:
    """Best-effort schema-doc load; unparseable files are simply not schemas."""
    try:
        raw = path.read_text(errors="replace")
    except OSError:
        return None
    if path.suffix == ".json":
        import json

        try:
            return json.loads(raw)
        except ValueError:
            return None
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        return None
    try:
        return yaml.safe_load(raw)
    except yaml.YAMLError:
        return None


# trace:v1 id=impl.src-bughunt-seam_scan.-schema-drift work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _schema_drift(root: Path, source_paths: Iterable[str]) -> list[SeamFinding]:
    models: dict[str, tuple[set[str], str, int]] = {}
    for path in _iter_python(root, source_paths):
        try:
            tree = ast.parse(path.read_text(errors="replace"), filename=str(path))
        except (OSError, SyntaxError):
            # Unreadable or unparseable file; skipped, never fatal
            continue
        for name, fields in _class_fields(tree).items():
            _ = models.setdefault(name, (fields, _rel(root, path), 1))

    findings: list[SeamFinding] = []
    schema_files: list[Path] = []
    for suffix in ("*.json", "*.yaml", "*.yml"):
        schema_files.extend(root.rglob(suffix))
    for path in schema_files:
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        data = _load_schema_doc(path)
        if data is None:
            continue
        candidates: list[tuple[str, dict[str, object]]] = []
        if isinstance(data, dict):
            title = data.get("title")
            if isinstance(title, str) and isinstance(data.get("properties"), dict):
                candidates.append((title, data))
            components = data.get("components")
            schemas = (
                components.get("schemas") if isinstance(components, dict) else None
            )
            if isinstance(schemas, dict):
                candidates.extend(
                    (str(name), schema)
                    for name, schema in schemas.items()
                    if isinstance(schema, dict)
                )
            defs = data.get("$defs") or data.get("definitions")
            if isinstance(defs, dict):
                candidates.extend(
                    (str(name), schema)
                    for name, schema in defs.items()
                    if isinstance(schema, dict)
                )
        for name, schema in candidates:
            model = models.get(name)
            props = schema.get("properties")
            if not model or not isinstance(props, dict):
                continue
            model_fields, model_path, _ = model
            schema_fields = {str(x) for x in props}
            missing_code = sorted(schema_fields - model_fields)
            missing_schema = sorted(model_fields - schema_fields)
            if missing_code or missing_schema:
                detail = []
                if missing_code:
                    detail.append("schema-only: " + ", ".join(missing_code[:12]))
                if missing_schema:
                    detail.append("code-only: " + ", ".join(missing_schema[:12]))
                findings.append(
                    SeamFinding(
                        "BHSEAM004",
                        (
                            f"schema `{name}` and Python class `{name}` have drifted "
                            f"({'; '.join(detail)}); synchronize schema/model or "
                            "declare intentional translation"
                        ),
                        model_path,
                        1,
                        "warning",
                    ),
                )
    return findings


# trace:v1 id=impl.src-bughunt-seam_scan.scan-seams work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def scan_seams(
    root: Path,
    source_paths: Iterable[str],
    test_paths: Iterable[str],
) -> list[SeamFinding]:
    findings: list[SeamFinding] = []
    for path in _iter_python(root, source_paths):
        try:
            tree = ast.parse(path.read_text(errors="replace"), filename=str(path))
        except (OSError, SyntaxError):
            # Unreadable or unparseable file; skipped, never fatal
            continue
        rel = _rel(root, path)
        findings.extend(_kwargs_drift(tree, rel))
        findings.extend(_producer_consumer_key_drift(tree, rel))
        findings.extend(_external_http_without_validation(tree, rel))
    findings.extend(_schema_drift(root, source_paths))
    findings.extend(_recorded_payload_gap(root, source_paths, test_paths))
    findings.extend(_time_boundary_gap(root, source_paths, test_paths))
    # Stable order keeps agent queues deterministic.
    return sorted(findings, key=lambda f: (f.path, f.line, f.code, f.message))


# trace:v1 id=impl.src-bughunt-seam_scan.main work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def main(argv: list[str] | None = None) -> int:
    import json
    import sys

    args = list(argv or sys.argv[1:])
    if not args:
        return 0
    root = Path(args.pop(0)).resolve()
    source_paths = args[0].split(",") if args else ["src"]
    test_paths = args[1].split(",") if len(args) > 1 else ["tests"]
    findings = scan_seams(root, source_paths, test_paths)
    print(
        json.dumps(
            {
                "findings": [
                    f.__dict__
                    if hasattr(f, "__dict__")
                    else {
                        "code": f.code,
                        "message": f.message,
                        "path": f.path,
                        "line": f.line,
                        "severity": f.severity,
                    }
                    for f in findings
                ],
            },
        ),
    )
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
