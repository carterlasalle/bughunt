from __future__ import annotations

import ast
import json
import re
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
    "dist",
    "build",
    ".bughunt",
}

FUZZ_NAME = re.compile(
    r"(^|_)(parse|parser|decode|deserialize|loads?|from_bytes|from_string|tokenize|lex|"
    r"read_message|parse_message|unpack|unmarshal|decompress|validate)(_|$)",
    re.IGNORECASE,
)

IDEMPOTENT_NAMES = {
    "normalize",
    "normalise",
    "canonicalize",
    "canonicalise",
    "dedupe",
    "deduplicate",
    "clamp",
}

ROUNDTRIP_TOKENS = (
    ("encode", "decode"),
    ("serialize", "deserialize"),
    ("serialise", "deserialise"),
    ("dumps", "loads"),
    ("compress", "decompress"),
    ("pack", "unpack"),
    ("marshal", "unmarshal"),
    ("export", "import"),
    ("backup", "restore"),
)

REFERENCE_TOKENS = {"reference", "ref", "baseline", "naive", "slow", "simple"}
OPTIMIZED_TOKENS = {
    "fast",
    "optimized",
    "optimised",
    "opt",
    "vectorized",
    "vectorised",
    "accelerated",
}

BOUNDARY_PREFIXES = (
    "open",
    "pathlib.Path.open",
    "pathlib.Path.read_text",
    "pathlib.Path.read_bytes",
    "pathlib.Path.write_text",
    "pathlib.Path.write_bytes",
    "requests.",
    "httpx.",
    "aiohttp.",
    "urllib.request.",
    "socket.",
    "subprocess.",
    "os.system",
    "os.remove",
    "os.unlink",
    "os.replace",
    "os.rename",
    "os.mkdir",
    "os.makedirs",
    "shutil.",
    "sqlite3.connect",
    "boto3.",
)

SINK_CALLS = (
    "os.system",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "eval",
    "exec",
    "pickle.loads",
)

SOURCE_CALLS = (
    "input",
    "builtins.input",
    "sys.stdin.read",
    "sys.stdin.readline",
)

FAULT_TEST_MARKERS = (
    "monkeypatch",
    "patch(",
    "patch.object",
    "side_effect",
    "pytest.raises",
    "raises(",
    "oserror",
    "ioerror",
    "timeouterror",
    "timeout",
    "connectionerror",
    "connection_error",
    "permissionerror",
    "filenotfounderror",
)


@dataclass(slots=True)
class DiscoveredTarget:
    kind: str
    name: str
    confidence: str
    runnable: bool
    reason: str
    command: list[str] | None = None
    source: str | None = None
    metadata: dict | None = None


@dataclass(slots=True)
class FunctionInfo:
    module: str
    name: str
    qualname: str
    path: Path
    relative_path: str
    line: int
    params: list[tuple[str, str | None]]
    return_annotation: str | None
    required_count: int
    is_async: bool
    has_raise: bool
    boundary_calls: list[tuple[str, int]]


@dataclass(slots=True)
class PysaModel:
    model: str
    kind: str
    symbol: str
    evidence: str
    source: str
    line: int


# trace:v1 id=impl.src-bughunt-discovery.infer-source-paths work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def infer_source_paths(root: Path) -> list[str]:
    """Infer first-party Python roots when a repo has no usable BugHunt config."""
    candidates: list[str] = []
    if (root / "src").is_dir() and any((root / "src").rglob("*.py")):
        candidates.append("src")
    for common in ("app", "lib"):
        base = root / common
        if base.is_dir() and any(base.rglob("*.py")) and common not in candidates:
            candidates.append(common)
    # Flat-layout packages. Avoid obvious tooling/content directories.
    ignored = EXCLUDED | {
        "tests",
        "test",
        "docs",
        "examples",
        "scripts",
        "tools",
        "migrations",
    }
    for child in sorted(root.iterdir() if root.exists() else []):
        if child.name in ignored or not child.is_dir():
            continue
        if (child / "__init__.py").exists():
            candidates.append(child.name)
    if candidates:
        return list(dict.fromkeys(candidates))
    if any(
        path.is_file() and path.suffix == ".py"
        for path in root.iterdir()
        if root.exists()
    ):
        return ["."]
    return ["src"]


def infer_test_paths(root: Path) -> list[str]:
    for name in ("tests", "test"):
        if (root / name).is_dir():
            return [name]
    return ["tests"]


def _python_files(root: Path, source_paths: Iterable[str]) -> Iterable[Path]:
    for rel in source_paths:
        base = root / rel
        if not base.exists():
            continue
        for path in base.rglob("*.py"):
            if not any(part in EXCLUDED for part in path.parts):
                yield path


def _test_python_files(root: Path) -> Iterable[Path]:
    for dirname in ("tests", "test"):
        base = root / dirname
        if base.exists():
            for path in base.rglob("*.py"):
                if not any(part in EXCLUDED for part in path.parts):
                    yield path


def _module_name(root: Path, path: Path, source_paths: Iterable[str]) -> str | None:
    for rel in source_paths:
        base = (root / rel).resolve()
        try:
            sub = path.resolve().relative_to(base)
        except ValueError:
            continue
        parts = list(sub.with_suffix("").parts)
        if parts and parts[-1] == "__init__":
            parts.pop()
        return ".".join(parts) if parts else None
    return None


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = _call_name(node.value)
        return f"{left}.{node.attr}" if left else node.attr
    return ""


# trace:v1 id=impl.src-bughunt-discovery.-annotation-text work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _annotation_text(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    try:
        return ast.unparse(node).replace("typing.", "")
    except Exception:  # noqa: BLE001 - unparse fallback: any AST shape must degrade to the name heuristic
        return _call_name(node) or None


def _annotation_name(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _call_name(node)
    if isinstance(node, ast.Subscript):
        return _call_name(node.value)
    return None


# trace:v1 id=impl.src-bughunt-discovery.-required-positional-count work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _required_positional_count(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    method: bool = False,
) -> int:
    total = len(fn.args.posonlyargs) + len(fn.args.args)
    required = total - len(fn.args.defaults)
    if (
        method
        and total
        and (fn.args.posonlyargs + fn.args.args)[0].arg in {"self", "cls"}
    ):
        required -= 1
    return max(0, required)


def _explicit_raises(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    names: set[str] = set()
    doc = ast.get_docstring(fn) or ""
    for match in re.finditer(
        r"(?m)^\s*(?:Raises?:\s*)?([A-Z][A-Za-z0-9_]*(?:Error|Exception))\s*[:\-]",
        doc,
    ):
        names.add(match.group(1))
    for node in ast.walk(fn):
        if not isinstance(node, ast.Raise) or node.exc is None:
            continue
        exc = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
        name = _call_name(exc)
        if name and re.fullmatch(r"[A-Za-z_][\w.]*", name):
            names.add(name)
    return sorted(names)


# trace:v1 id=impl.src-bughunt-discovery.-literal-seeds work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _literal_seeds(
    root: Path,
    function_name: str,
    limit: int = 64,
) -> list[tuple[bytes, str]]:
    seeds: list[tuple[bytes, str]] = []
    for path in _test_python_files(root):
        try:
            tree = ast.parse(path.read_text(errors="replace"))
        except (SyntaxError, OSError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            called = _call_name(node.func).split(".")[-1]
            if called != function_name:
                continue
            value = node.args[0]
            if isinstance(value, ast.Constant):
                if isinstance(value.value, bytes):
                    seeds.append((value.value, "bytes"))
                elif isinstance(value.value, str):
                    seeds.append((value.value.encode("utf-8"), "str"))
            if len(seeds) >= limit:
                return seeds
    return seeds


# trace:v1 id=impl.src-bughunt-discovery.-is-boundary-call work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _is_boundary_call(name: str) -> bool:
    lowered = name.lower()
    return any(
        lowered == prefix.lower() or lowered.startswith(prefix.lower())
        for prefix in BOUNDARY_PREFIXES
    )


# trace:v1 id=impl.src-bughunt-discovery.-function-infos work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _function_infos(root: Path, source_paths: list[str]) -> list[FunctionInfo]:
    infos: list[FunctionInfo] = []
    for path in _python_files(root, source_paths):
        try:
            tree = ast.parse(path.read_text(errors="replace"))
        except (SyntaxError, OSError):
            continue
        module = _module_name(root, path, source_paths)
        if not module:
            continue
        rel = str(path.relative_to(root))
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            params = [
                (arg.arg, _annotation_text(arg.annotation))
                for arg in (node.args.posonlyargs + node.args.args)
            ]
            boundaries: list[tuple[str, int]] = []
            for inner in ast.walk(node):
                if isinstance(inner, ast.Call):
                    called = _call_name(inner.func)
                    if _is_boundary_call(called):
                        boundaries.append(
                            (called, getattr(inner, "lineno", node.lineno)),
                        )
            infos.append(
                FunctionInfo(
                    module=module,
                    name=node.name,
                    qualname=f"{module}.{node.name}",
                    path=path,
                    relative_path=rel,
                    line=node.lineno,
                    params=params,
                    return_annotation=_annotation_text(node.returns),
                    required_count=_required_positional_count(node),
                    is_async=isinstance(node, ast.AsyncFunctionDef),
                    has_raise=any(isinstance(x, ast.Raise) for x in ast.walk(node)),
                    boundary_calls=boundaries,
                ),
            )
    return infos


# trace:v1 id=impl.src-bughunt-discovery.-strategy-expr work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _strategy_expr(annotation: str | None) -> str | None:
    if annotation is None:
        return None
    ann = annotation.replace(" ", "")
    simple = {
        "str": "st.text()",
        "builtins.str": "st.text()",
        "bytes": "st.binary()",
        "builtins.bytes": "st.binary()",
        "bytearray": "st.binary().map(bytearray)",
        "int": "st.integers()",
        "builtins.int": "st.integers()",
        "float": "st.floats(allow_nan=False, allow_infinity=False)",
        "builtins.float": "st.floats(allow_nan=False, allow_infinity=False)",
        "bool": "st.booleans()",
        "builtins.bool": "st.booleans()",
    }
    if ann in simple:
        return simple[ann]
    optional = re.fullmatch(r"(?:Optional\[(.+)\]|(.+)\|None|None\|(.+))", ann)
    if optional:
        inner = next(x for x in optional.groups() if x)
        inner_strategy = _strategy_expr(inner)
        return f"st.one_of(st.none(), {inner_strategy})" if inner_strategy else None
    generic = re.fullmatch(r"(list|set|frozenset)\[(.+)\]", ann)
    if generic:
        inner = _strategy_expr(generic.group(2))
        if not inner:
            return None
        fn = {"list": "lists", "set": "sets", "frozenset": "frozensets"}[
            generic.group(1)
        ]
        return f"st.{fn}({inner}, max_size=32)"
    generic = re.fullmatch(r"dict\[(.+),(.+)\]", ann)
    if generic:
        key = _strategy_expr(generic.group(1))
        value = _strategy_expr(generic.group(2))
        if key and value:
            return f"st.dictionaries({key}, {value}, max_size=32)"
    tuple_match = re.fullmatch(r"tuple\[(.+)\]", ann)
    if tuple_match and "," in tuple_match.group(1):
        bits = tuple(x.strip() for x in tuple_match.group(1).split(","))
        strategies = [_strategy_expr(x) for x in bits]
        if all(strategies):
            return "st.tuples(" + ", ".join(str(x) for x in strategies) + ")"
    return None


# trace:v1 id=impl.src-bughunt-discovery.-safe-campaign-function work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _safe_campaign_function(info: FunctionInfo) -> bool:
    return (
        not info.is_async and not info.boundary_calls and 1 <= info.required_count <= 3
    )


def _same_signature(a: FunctionInfo, b: FunctionInfo) -> bool:
    if a.required_count != b.required_count or len(a.params) != len(b.params):
        return False
    if [x[1] for x in a.params] != [x[1] for x in b.params]:
        return False
    return a.return_annotation == b.return_annotation


def _name_variant(name: str, tokens: set[str]) -> tuple[str, str] | None:
    parts = name.split("_")
    for idx, part in enumerate(parts):
        if part in tokens:
            base = "_".join(parts[:idx] + parts[idx + 1 :])
            if base:
                return base, part
    return None


# trace:v1 id=impl.src-bughunt-discovery.-equivalence-helper work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _equivalence_helper() -> str:
    return """def _equivalent(left, right):
    if isinstance(left, float) and isinstance(right, float):
        return math.isclose(left, right, rel_tol=1e-9, abs_tol=1e-12)
    if (
        isinstance(left, (list, tuple))
        and isinstance(right, type(left))
        and len(left) == len(right)
    ):
        return all(_equivalent(a, b) for a, b in zip(left, right))
    if (
        isinstance(left, dict)
        and isinstance(right, dict)
        and left.keys() == right.keys()
    ):
        return all(_equivalent(left[k], right[k]) for k in left)
    return left == right
"""


# trace:v1 id=impl.src-bughunt-discovery.-write-property-harness work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _write_property_harness(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "# Auto-generated by BugHunt from high-confidence repository evidence.\n"
        "from __future__ import annotations\n\n"
        "import importlib\n"
        "import math\n"
        "from hypothesis import given, settings, strategies as st\n\n"
        + _equivalence_helper()
        + "\n"
        + body,
    )


# trace:v1 id=impl.src-bughunt-discovery.discover-custom-campaigns work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def discover_custom_campaigns(
    root: Path,
    source_paths: list[str],
) -> list[DiscoveredTarget]:
    infos = _function_infos(root, source_paths)
    by_module: dict[str, list[FunctionInfo]] = {}
    for info in infos:
        by_module.setdefault(info.module, []).append(info)

    generated = root / ".bughunt" / "generated" / "campaigns"
    generated.mkdir(parents=True, exist_ok=True)
    out: list[DiscoveredTarget] = []
    seen: set[tuple[str, str]] = set()

    # Differential pairs such as foo_reference/foo_fast or foo_naive/foo_optimized.
    for module, members in by_module.items():
        refs: dict[str, FunctionInfo] = {}
        opts: dict[str, FunctionInfo] = {}
        for info in members:
            ref = _name_variant(info.name, REFERENCE_TOKENS)
            opt = _name_variant(info.name, OPTIMIZED_TOKENS)
            if ref:
                refs[ref[0]] = info
            if opt:
                opts[opt[0]] = info
        for base in sorted(refs.keys() & opts.keys()):
            reference, optimized = refs[base], opts[base]
            if not (
                _safe_campaign_function(reference)
                and _safe_campaign_function(optimized)
            ):
                continue
            if not _same_signature(reference, optimized):
                continue
            strategies = [
                _strategy_expr(annotation) for _, annotation in reference.params
            ]
            if not strategies or not all(strategies):
                continue
            target_name = f"{module}.{base}:differential"
            if ("custom-differential", target_name) in seen:
                continue
            seen.add(("custom-differential", target_name))
            harness = generated / (
                f"test_differential_"
                f"{re.sub(r'[^A-Za-z0-9_]+', '_', module + '_' + base)}.py"
            )
            arguments = ", ".join(name for name, _ in reference.params)
            decorators = ", ".join(
                f"{name}={strategy}"
                for (name, _), strategy in zip(
                    reference.params,
                    strategies,
                    strict=True,
                )
            )
            body = f"""_module = importlib.import_module({module!r})
_reference = getattr(_module, {reference.name!r})
_optimized = getattr(_module, {optimized.name!r})


def _outcome(fn, *args):
    try:
        return ("ok", fn(*args))
    except Exception as exc:
        return ("error", type(exc))


@given({decorators})
@settings(max_examples=2000, deadline=None)
def test_bughunt_differential({arguments}):
    left = _outcome(_reference, {arguments})
    right = _outcome(_optimized, {arguments})
    assert left[0] == right[0]
    if left[0] == "error":
        assert left[1] is right[1]
    else:
        assert _equivalent(left[1], right[1])
"""
            _write_property_harness(harness, body)
            out.append(
                DiscoveredTarget(
                    kind="custom-differential",
                    name=target_name,
                    confidence="high",
                    runnable=True,
                    reason=(
                        f"matched reference implementation {reference.name} to "
                        f"optimized implementation {optimized.name}; typed signatures "
                        "agree and neither touches an external boundary"
                    ),
                    source=reference.relative_path,
                    command=[
                        "uv",
                        "run",
                        "pytest",
                        "-q",
                        str(harness.relative_to(root)),
                        "--tb=short",
                    ],
                    metadata={
                        "oracle": reference.qualname,
                        "implementation": optimized.qualname,
                        "generated_harness": str(harness.relative_to(root)),
                        "evidence": (
                            "reference/optimized naming + equal "
                            "typed signature + no detected I/O "
                            "boundary"
                        ),
                    },
                ),
            )

    # Round-trip pairs such as encode/decode and serialize/deserialize.
    for module, members in by_module.items():
        names = {info.name: info for info in members}
        for encoder_token, decoder_token in ROUNDTRIP_TOKENS:
            for encoder in members:
                parts = encoder.name.split("_")
                if encoder_token not in parts:
                    continue
                idx = parts.index(encoder_token)
                decoder_name = "_".join(
                    parts[:idx] + [decoder_token] + parts[idx + 1 :],
                )
                decoder = names.get(decoder_name)
                if decoder is None:
                    continue
                if not (
                    _safe_campaign_function(encoder)
                    and _safe_campaign_function(decoder)
                ):
                    continue
                if encoder.required_count != 1 or decoder.required_count != 1:
                    continue
                enc_in = encoder.params[0][1]
                enc_out = encoder.return_annotation
                dec_in = decoder.params[0][1]
                dec_out = decoder.return_annotation
                if not enc_in or not enc_out or enc_out != dec_in or dec_out != enc_in:
                    continue
                strategy = _strategy_expr(enc_in)
                if not strategy:
                    continue
                key = f"{module}.{encoder.name}<->{decoder.name}"
                if ("custom-roundtrip", key) in seen:
                    continue
                seen.add(("custom-roundtrip", key))
                harness = (
                    generated
                    / f"test_roundtrip_{re.sub(r'[^A-Za-z0-9_]+', '_', key)}.py"
                )
                arg_name = encoder.params[0][0]
                body = f"""_module = importlib.import_module({module!r})
_encode = getattr(_module, {encoder.name!r})
_decode = getattr(_module, {decoder.name!r})


@given({arg_name}={strategy})
@settings(max_examples=2000, deadline=None)
def test_bughunt_roundtrip({arg_name}):
    encoded = _encode({arg_name})
    decoded = _decode(encoded)
    assert _equivalent(decoded, {arg_name})
"""
                _write_property_harness(harness, body)
                out.append(
                    DiscoveredTarget(
                        kind="custom-roundtrip",
                        name=key,
                        confidence="high",
                        runnable=True,
                        reason=(
                            "inverse naming and annotations form "
                            "an exact A -> B -> A round-trip with "
                            "no detected external boundary"
                        ),
                        source=encoder.relative_path,
                        command=[
                            "uv",
                            "run",
                            "pytest",
                            "-q",
                            str(harness.relative_to(root)),
                            "--tb=short",
                        ],
                        metadata={
                            "generated_harness": str(harness.relative_to(root)),
                            "strategy": strategy,
                        },
                    ),
                )

    # Idempotence properties for functions whose name and type signature
    # strongly imply it.
    for info in infos:
        if info.name not in IDEMPOTENT_NAMES or not _safe_campaign_function(info):
            continue
        if info.required_count != 1 or len(info.params) != 1:
            continue
        input_ann = info.params[0][1]
        if not input_ann or info.return_annotation != input_ann or info.has_raise:
            continue
        strategy = _strategy_expr(input_ann)
        if not strategy:
            continue
        key = f"{info.qualname}:idempotence"
        harness = (
            generated
            / f"test_idempotence_{re.sub(r'[^A-Za-z0-9_]+', '_', info.qualname)}.py"
        )
        arg_name = info.params[0][0]
        body = f"""_module = importlib.import_module({info.module!r})
_target = getattr(_module, {info.name!r})


@given({arg_name}={strategy})
@settings(max_examples=2000, deadline=None)
def test_bughunt_idempotence({arg_name}):
    once = _target({arg_name})
    twice = _target(once)
    assert _equivalent(twice, once)
"""
        _write_property_harness(harness, body)
        out.append(
            DiscoveredTarget(
                kind="custom-idempotence",
                name=key,
                confidence="high",
                runnable=True,
                reason=(
                    "function name implies canonical/idempotent "
                    "transformation, input/output annotations match, "
                    "no explicit raise, and no detected external "
                    "boundary"
                ),
                source=info.relative_path,
                command=[
                    "uv",
                    "run",
                    "pytest",
                    "-q",
                    str(harness.relative_to(root)),
                    "--tb=short",
                ],
                metadata={
                    "generated_harness": str(harness.relative_to(root)),
                    "strategy": strategy,
                },
            ),
        )

    # Fault-injection *coverage* campaign. This does not guess desired failure
    # behavior; it deterministically reports first-party I/O boundaries for which
    # no nearby test appears to exercise an injected failure path.
    fault_rows: list[dict[str, object]] = []
    test_texts: list[tuple[str, str]] = []
    for test_path in _test_python_files(root):
        try:
            tree = ast.parse(test_path.read_text(errors="replace"))
            source = test_path.read_text(errors="replace")
        except (SyntaxError, OSError):
            continue
        for node in ast.walk(tree):
            if isinstance(
                node,
                (ast.FunctionDef, ast.AsyncFunctionDef),
            ) and node.name.startswith("test"):
                segment = ast.get_source_segment(source, node) or ""
                test_texts.append((node.name, segment.lower()))
    for info in infos:
        if not info.boundary_calls:
            continue
        for call, line in info.boundary_calls:
            needle = info.name.lower()
            covered = any(
                needle in body and any(marker in body for marker in FAULT_TEST_MARKERS)
                for _, body in test_texts
            )
            if not covered:
                fault_rows.append(
                    {
                        "path": info.relative_path,
                        "line": line,
                        "function": info.qualname,
                        "boundary": call,
                    },
                )
    inventory = generated / "fault_boundaries.json"
    inventory.write_text(
        json.dumps({"schema_version": 1, "uncovered": fault_rows}, indent=2) + "\n",
    )
    checker = generated / "check_fault_boundaries.py"
    checker.write_text(
        """# Auto-generated by BugHunt. Reports untested external-failure surfaces.
from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
data = json.loads(
    (ROOT / ".bughunt/generated/campaigns/fault_boundaries.json").read_text()
)
rows = data.get("uncovered", [])
for row in rows:
    print(
        f"{row['path']}:{row['line']}:1: warning: external boundary "
        f"{row['boundary']} in {row['function']} has no detected "
        "fault-injection test [BHFAULT001]"
    )
sys.exit(1 if rows else 0)
""",
    )
    if fault_rows:
        out.append(
            DiscoveredTarget(
                kind="custom-fault-coverage",
                name="external-failure-surface-coverage",
                confidence="high",
                runnable=True,
                reason=(
                    f"{len(fault_rows)} first-party external boundary call(s) lack "
                    "a detected fault-injection test; reports coverage gaps "
                    "without guessing desired recovery semantics"
                ),
                source=str(inventory.relative_to(root)),
                command=["uv", "run", "python", str(checker.relative_to(root))],
                metadata={
                    "generated_checker": str(checker.relative_to(root)),
                    "inventory": str(inventory.relative_to(root)),
                    "uncovered_boundaries": len(fault_rows),
                },
            ),
        )

    return out


# trace:v1 id=impl.src-bughunt-discovery.discover-pysa-models work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def discover_pysa_models(root: Path, source_paths: list[str]) -> list[PysaModel]:
    models: list[PysaModel] = []
    for path in _python_files(root, source_paths):
        try:
            tree = ast.parse(path.read_text(errors="replace"))
        except (SyntaxError, OSError):
            continue
        module = _module_name(root, path, source_paths)
        if not module:
            continue
        rel = str(path.relative_to(root))
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            params = [arg.arg for arg in (node.args.posonlyargs + node.args.args)]
            source_evidence: str | None = None
            sink_params: set[str] = set()
            sink_evidence: dict[str, str] = {}
            for inner in ast.walk(node):
                if isinstance(inner, ast.Return) and inner.value is not None:
                    for returned in ast.walk(inner.value):
                        if isinstance(returned, ast.Call):
                            called = _call_name(returned.func)
                            if called in SOURCE_CALLS:
                                source_evidence = f"returns value from {called}"
                        if isinstance(returned, (ast.Attribute, ast.Subscript)):
                            text = _call_name(
                                returned
                                if isinstance(returned, ast.Attribute)
                                else returned.value,
                            )
                            if text.startswith(
                                (
                                    "request.args",
                                    "request.form",
                                    "request.values",
                                    "request.json",
                                ),
                            ):
                                source_evidence = f"returns value from {text}"
                if isinstance(inner, ast.Call):
                    called = _call_name(inner.func)
                    if called not in SINK_CALLS:
                        continue
                    for arg in inner.args:
                        if isinstance(arg, ast.Name) and arg.id in params:
                            sink_params.add(arg.id)
                            sink_evidence[arg.id] = f"passed directly to {called}"
            sig_parts: list[str] = []
            for param in params:
                if param in sink_params:
                    sig_parts.append(f"{param}: TaintSink[BugHuntSensitiveOperation]")
                else:
                    sig_parts.append(param)
            qualified = f"{module}.{node.name}"
            if source_evidence:
                models.append(
                    PysaModel(
                        model=(
                            f"def {qualified}({', '.join(params)}) -> "
                            "TaintSource[BugHuntUserControlled]: ..."
                        ),
                        kind="source",
                        symbol=qualified,
                        evidence=source_evidence,
                        source=rel,
                        line=node.lineno,
                    ),
                )
            if sink_params:
                models.append(
                    PysaModel(
                        model=f"def {qualified}({', '.join(sig_parts)}): ...",
                        kind="sink",
                        symbol=qualified,
                        evidence="; ".join(
                            f"{name} {sink_evidence[name]}"
                            for name in sorted(sink_params)
                        ),
                        source=rel,
                        line=node.lineno,
                    ),
                )
    # Stable unique models.
    dedup: dict[str, PysaModel] = {}
    for model in models:
        dedup[model.model] = model
    return list(dedup.values())


# trace:v1 id=impl.src-bughunt-discovery.write-pysa-models work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def write_pysa_models(root: Path, models: list[PysaModel]) -> Path:
    path = root / ".bughunt" / "configs" / "pysa" / "bughunt.pysa"
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Auto-generated by BugHunt from high-confidence direct-flow evidence.",
        "# Each model is accompanied by source evidence in generated/pysa-models.json.",
        "",
    ]
    lines.extend(model.model for model in models)
    path.write_text("\n".join(lines).rstrip() + "\n")
    evidence = root / ".bughunt" / "generated" / "pysa-models.json"
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(
        json.dumps(
            {"schema_version": 1, "models": [asdict(m) for m in models]},
            indent=2,
        )
        + "\n",
    )
    return path


# trace:v1 id=impl.src-bughunt-discovery.-inferred-rejection-exceptions work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _inferred_rejection_exceptions(fn: ast.FunctionDef) -> list[str]:
    """Conservative exceptions that represent malformed-input rejection, not crashes."""
    names = set(_explicit_raises(fn))
    if FUZZ_NAME.search(fn.name):
        names.update({"ValueError", "UnicodeError", "EOFError"})
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        called = _call_name(node.func)
        if called.startswith("zlib.decompress"):
            names.add("zlib.error")
        elif called.startswith("struct.unpack"):
            names.add("struct.error")
        elif called.startswith(("base64.", "binascii.")):
            names.add("binascii.Error")
        elif called.startswith("pickle.loads"):
            names.add("pickle.UnpicklingError")
    return sorted(names)


# trace:v1 id=impl.src-bughunt-discovery.discover-atheris work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def discover_atheris(
    root: Path,
    source_paths: list[str],
    run_count: int = 250_000,
) -> list[DiscoveredTarget]:
    out: list[DiscoveredTarget] = []
    generated = root / ".bughunt" / "generated" / "atheris"
    generated.mkdir(parents=True, exist_ok=True)

    for path in _python_files(root, source_paths):
        try:
            tree = ast.parse(path.read_text(errors="replace"))
        except (SyntaxError, OSError):
            continue
        module = _module_name(root, path, source_paths)
        if not module:
            continue

        candidates: list[tuple[ast.FunctionDef, str, str | None]] = []
        for node in tree.body:
            if isinstance(node, ast.FunctionDef):
                candidates.append((node, node.name, None))
            elif isinstance(node, ast.ClassDef):
                for child in node.body:
                    if not isinstance(child, ast.FunctionDef):
                        continue
                    decorators = {_call_name(x) for x in child.decorator_list}
                    if "staticmethod" in decorators or "classmethod" in decorators:
                        candidates.append(
                            (child, f"{node.name}.{child.name}", node.name),
                        )

        for node, callable_name, class_name in candidates:
            leaf = node.name
            if leaf.startswith("_") or not FUZZ_NAME.search(leaf):
                continue
            method = class_name is not None
            if _required_positional_count(node, method=method) != 1:
                continue
            if node.args.kwonlyargs and any(x is None for x in node.args.kw_defaults):
                continue
            args = node.args.posonlyargs + node.args.args
            if method and args and args[0].arg in {"self", "cls"}:
                args = args[1:]
            if not args:
                continue
            annotation = _annotation_name(args[0].annotation)
            seeds_typed = _literal_seeds(root, leaf)
            inferred_type: str | None = None
            seed_types = {kind for _, kind in seeds_typed}
            if annotation is None and len(seed_types) == 1:
                inferred_type = next(iter(seed_types))
            effective = annotation or inferred_type
            if effective not in {
                None,
                "str",
                "bytes",
                "bytearray",
                "memoryview",
                "builtins.str",
                "builtins.bytes",
                "builtins.bytearray",
            }:
                continue

            target_id = re.sub(r"[^A-Za-z0-9_.-]+", "_", f"{module}.{callable_name}")
            harness = generated / f"{target_id.replace('.', '_')}.py"
            corpus_dir = generated / "corpus" / target_id.replace(".", "_")
            corpus_dir.mkdir(parents=True, exist_ok=True)
            seeds = [seed for seed, _ in seeds_typed]
            seed_values = [
                b"",
                b"0",
                b"1",
                b"{}",
                b"[]",
                b"null",
                b"\x00",
                b"\xff",
                *seeds,
            ]
            for i, seed in enumerate(dict.fromkeys(seed_values)):
                (corpus_dir / f"seed-{i:03d}").write_bytes(seed)
            explicit = _inferred_rejection_exceptions(node)
            exc_literals = repr(explicit)
            if effective in {"str", "builtins.str"}:
                converter = "data.decode('utf-8', errors='replace')"
            elif effective in {"bytearray", "builtins.bytearray"}:
                converter = "bytearray(data)"
            elif effective == "memoryview":
                converter = "memoryview(data)"
            else:
                converter = "data"
            target_access = (
                f"getattr(_module, {leaf!r})"
                if not class_name
                else f"getattr(getattr(_module, {class_name!r}), {leaf!r})"
            )
            harness.write_text(
                (
                    "# Auto-generated by BugHunt from a high/medium "
                    "confidence parser boundary.\n"
                    "from __future__ import annotations\n"
                    "\n"
                    "import builtins\n"
                    "import importlib\n"
                    "from pathlib import Path\n"
                    "import sys\n"
                    "\n"
                    "_BUGHUNT_ROOT = Path(__file__).resolve().parents[2]\n"
                    '_ATHERIS_RUNTIME = _BUGHUNT_ROOT / "runtime" / "atheris"\n'
                    "if _ATHERIS_RUNTIME.exists():\n"
                    "    sys.path.insert(0, str(_ATHERIS_RUNTIME))\n"
                    "\n"
                    "import atheris\n"
                    "\n"
                    f"MODULE = {module!r}\n"
                    f"EXPLICIT_RAISES = {exc_literals}\n"
                    "\n"
                    "with atheris.instrument_imports():\n"
                    "    _module = importlib.import_module(MODULE)\n"
                    "\n"
                    f"_target = {target_access}\n"
                    "\n"
                    "def _expected_exceptions():\n"
                    "    found = []\n"
                    "    for dotted in EXPLICIT_RAISES:\n"
                    "        candidate = None\n"
                    "        if hasattr(_module, dotted):\n"
                    "            candidate = getattr(_module, dotted)\n"
                    '        elif hasattr(builtins, dotted.split(".")[-1]):\n'
                    '            candidate = getattr(builtins, dotted.split(".")[-1])\n'
                    '        elif "." in dotted:\n'
                    "            try:\n"
                    '                owner, attr = dotted.rsplit(".", 1)\n'
                    "                candidate = getattr(importlib.import_module(owner)"
                    ", attr)\n"
                    "            except (ImportError, AttributeError):\n"
                    "                candidate = None\n"
                    "        if isinstance(candidate, type) and "
                    "issubclass(candidate, Exception):\n"
                    "            found.append(candidate)\n"
                    "    return tuple(found)\n"
                    "\n"
                    "_EXPECTED = _expected_exceptions()\n"
                    "\n"
                    "@atheris.instrument_func\n"
                    "def TestOneInput(data: bytes) -> None:\n"
                    f"    value = {converter}\n"
                    "    try:\n"
                    "        _target(value)\n"
                    "    except _EXPECTED:\n"
                    "        return\n"
                    "\n"
                    "atheris.Setup(sys.argv, TestOneInput)\n"
                    "atheris.Fuzz()\n"
                ),
            )
            confidence = (
                "high"
                if annotation is not None or inferred_type is not None
                else "medium"
            )
            out.append(
                DiscoveredTarget(
                    kind="atheris",
                    name=f"{module}.{callable_name}",
                    confidence=confidence,
                    runnable=True,
                    reason=(
                        (
                            "parser/decoder has exactly one fuzzable "
                            "input with explicit type evidence; "
                            "harness generated"
                        )
                        if annotation is not None
                        else (
                            "parser/decoder has exactly one input "
                            "and test call sites consistently establish "
                            "its input type; harness generated"
                        )
                        if inferred_type
                        else (
                            "parser/decoder has exactly one unannotated "
                            "input; bytes harness generated as "
                            "a medium-confidence target"
                        )
                    ),
                    source=str(path.relative_to(root)),
                    command=[
                        "uv",
                        "run",
                        "python",
                        str(harness.relative_to(root)),
                        str(corpus_dir.relative_to(root)),
                        f"-atheris_runs={run_count}",
                    ],
                    metadata={
                        "annotation": annotation,
                        "inferred_type": inferred_type,
                        "explicit_raises": explicit,
                        "generated_harness": str(harness.relative_to(root)),
                        "seed_corpus": str(corpus_dir.relative_to(root)),
                        "seed_count": len(list(corpus_dir.iterdir())),
                    },
                ),
            )
    return out


# trace:v1 id=impl.src-bughunt-discovery.-local-url work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _local_url(url: str) -> bool:
    return bool(
        re.match(
            r"^https?://(127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\])(?::\d+)?(?:/|$)",
            url.strip(),
            re.IGNORECASE,
        ),
    )


# trace:v1 id=impl.src-bughunt-discovery.-openapi-server work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _openapi_server(path: Path) -> str | None:
    text = path.read_text(errors="replace")
    if path.suffix.lower() == ".json":
        try:
            data = json.loads(text)
            for server in data.get("servers", []):
                url = server.get("url") if isinstance(server, dict) else None
                if isinstance(url, str) and _local_url(url):
                    return url
            host = data.get("host")
            base = data.get("basePath", "")
            schemes = data.get("schemes") or ["http"]
            if isinstance(host, str) and host.split(":")[0] in {
                "localhost",
                "127.0.0.1",
                "0.0.0.0",
            }:
                return f"{schemes[0]}://{host}{base}"
        except json.JSONDecodeError:
            return None
    for match in re.finditer(r"""(?m)^\s*-?\s*url\s*:\s*["']?([^"'\s]+)""", text):
        if _local_url(match.group(1)):
            return match.group(1)
    return None


# trace:v1 id=impl.src-bughunt-discovery.-looks-openapi work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _looks_openapi(path: Path) -> bool:
    try:
        head = path.read_text(errors="replace")[:80_000]
    except OSError:
        return False
    return bool(
        re.search(r"""(?m)^\s*(openapi|swagger)\s*[:"]""", head)
        or '"openapi"' in head
        or '"swagger"' in head,
    )


# trace:v1 id=impl.src-bughunt-discovery.discover-schemathesis work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def discover_schemathesis(
    root: Path,
    source_paths: list[str],
    max_examples: int = 500,
) -> list[DiscoveredTarget]:
    out: list[DiscoveredTarget] = []
    generated = root / ".bughunt" / "generated" / "schemathesis"
    generated.mkdir(parents=True, exist_ok=True)

    for path in _python_files(root, source_paths):
        try:
            tree = ast.parse(path.read_text(errors="replace"))
        except (SyntaxError, OSError):
            continue
        module = _module_name(root, path, source_paths)
        if not module:
            continue
        fastapi_factories: set[str] = set()
        for candidate in tree.body:
            if not isinstance(candidate, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for inner in ast.walk(candidate):
                if (
                    isinstance(inner, ast.Return)
                    and isinstance(inner.value, ast.Call)
                    and _call_name(inner.value.func).endswith("FastAPI")
                ):
                    fastapi_factories.add(candidate.name)
                    break
        for node in tree.body:
            targets: list[str] = []
            value = None
            if isinstance(node, ast.Assign):
                value = node.value
                targets = [
                    target.id for target in node.targets if isinstance(target, ast.Name)
                ]
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                value = node.value
                targets = [node.target.id]
            if not isinstance(value, ast.Call):
                continue
            called = _call_name(value.func)
            if not (
                called.endswith("FastAPI") or called.split(".")[-1] in fastapi_factories
            ):
                continue
            for app_name in targets:
                target_id = re.sub(r"[^A-Za-z0-9_.-]+", "_", f"{module}.{app_name}")
                harness = generated / f"test_{target_id.replace('.', '_')}.py"
                harness.write_text(
                    (
                        "# Auto-generated by BugHunt for in-process "
                        "Schemathesis fuzzing.\n"
                        "from __future__ import annotations\n"
                        "\n"
                        "import importlib\n"
                        "import schemathesis\n"
                        "from hypothesis import settings\n"
                        "\n"
                        f"_module = importlib.import_module({module!r})\n"
                        f"_app = getattr(_module, {app_name!r})\n"
                        'schema = schemathesis.openapi.from_asgi("/openapi.json", '
                        "_app)\n"
                        "\n"
                        "@schema.parametrize()\n"
                        f"@settings(max_examples={max_examples}, deadline=None)\n"
                        "def test_bughunt_api(case):\n"
                        "    case.call_and_validate()\n"
                        "\n"
                        "StateMachine = schema.as_state_machine()\n"
                        "TestCase = StateMachine.TestCase\n"
                        "TestCase.settings = settings(\n"
                        f"    max_examples=min({max_examples}, 200),\n"
                        "    stateful_step_count=10,\n"
                        "    deadline=None,\n"
                        ")\n"
                    ),
                )
                out.append(
                    DiscoveredTarget(
                        kind="schemathesis",
                        name=f"{module}.{app_name}",
                        confidence="high",
                        runnable=True,
                        reason=(
                            "FastAPI application detected; using "
                            "Schemathesis ASGI in-process transport"
                        ),
                        source=str(path.relative_to(root)),
                        command=[
                            "uv",
                            "run",
                            "pytest",
                            "-q",
                            str(harness.relative_to(root)),
                            "--tb=short",
                        ],
                        metadata={
                            "transport": "asgi",
                            "schema_path": "/openapi.json",
                            "generated_harness": str(harness.relative_to(root)),
                            "max_examples_hint": max_examples,
                        },
                    ),
                )

    # Flask/Werkzeug apps are safe to fuzz in-process only when this module also
    # exposes an explicit local OpenAPI endpoint; otherwise there is no schema
    # contract for Schemathesis to drive accurately.
    for path in _python_files(root, source_paths):
        try:
            tree = ast.parse(path.read_text(errors="replace"))
        except (SyntaxError, OSError):
            continue
        module = _module_name(root, path, source_paths)
        if not module:
            continue
        flask_apps: set[str] = set()
        schema_routes: dict[str, str] = {}
        for node in tree.body:
            if (
                isinstance(node, ast.Assign)
                and isinstance(node.value, ast.Call)
                and _call_name(node.value.func).endswith("Flask")
            ):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        flask_apps.add(target.id)
        if not flask_apps:
            continue
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call) or not decorator.args:
                    continue
                called = _call_name(decorator.func)
                if not called.endswith((".route", ".get")):
                    continue
                owner = called.rsplit(".", 1)[0]
                if owner not in flask_apps:
                    continue
                route = decorator.args[0]
                if (
                    isinstance(route, ast.Constant)
                    and isinstance(route.value, str)
                    and route.value
                    in {"/openapi.json", "/swagger.json", "/api/openapi.json"}
                ):
                    schema_routes[owner] = route.value
        for app_name, schema_path in schema_routes.items():
            target_id = re.sub(r"[^A-Za-z0-9_.-]+", "_", f"{module}.{app_name}")
            harness = generated / f"test_wsgi_{target_id.replace('.', '_')}.py"
            harness.write_text(
                "# Auto-generated by BugHunt for in-process Schemathesis "
                "WSGI fuzzing.\n"
                "from __future__ import annotations\n\n"
                "import importlib\n"
                "import schemathesis\n"
                "from hypothesis import settings\n\n"
                f"_module = importlib.import_module({module!r})\n"
                f"_app = getattr(_module, {app_name!r})\n"
                f"schema = schemathesis.openapi.from_wsgi({schema_path!r}, _app)\n\n"
                "@schema.parametrize()\n"
                f"@settings(max_examples={max_examples}, deadline=None)\n"
                "def test_bughunt_api(case):\n"
                "    case.call_and_validate()\n",
            )
            out.append(
                DiscoveredTarget(
                    kind="schemathesis",
                    name=f"{module}.{app_name}",
                    confidence="high",
                    runnable=True,
                    reason=(
                        f"Flask application and explicit {schema_path} OpenAPI route "
                        "detected; using Schemathesis WSGI in-process transport"
                    ),
                    source=str(path.relative_to(root)),
                    command=[
                        "uv",
                        "run",
                        "pytest",
                        "-q",
                        str(harness.relative_to(root)),
                        "--tb=short",
                    ],
                    metadata={
                        "transport": "wsgi",
                        "schema_path": schema_path,
                        "generated_harness": str(harness.relative_to(root)),
                    },
                ),
            )

    # Schema files are safe to auto-run only when their server points at localhost.
    for path in root.rglob("*"):
        if not path.is_file() or any(part in EXCLUDED for part in path.parts):
            continue
        if path.suffix.lower() not in {".json", ".yaml", ".yml"} or not _looks_openapi(
            path,
        ):
            continue
        rel = str(path.relative_to(root))
        url = _openapi_server(path)
        if url:
            out.append(
                DiscoveredTarget(
                    kind="schemathesis",
                    name=rel,
                    confidence="high",
                    runnable=True,
                    reason="OpenAPI schema with local-only server URL detected",
                    source=rel,
                    command=[
                        "uv",
                        "run",
                        "st",
                        "--config-file",
                        ".bughunt/configs/schemathesis.toml",
                        "run",
                        rel,
                        "--url",
                        url,
                        "--max-examples",
                        str(max_examples),
                        "--continue-on-failure",
                        "--checks",
                        "all",
                        "--output-truncate",
                        "false",
                    ],
                    metadata={"transport": "http-local", "url": url},
                ),
            )
        else:
            out.append(
                DiscoveredTarget(
                    kind="schemathesis-candidate",
                    name=rel,
                    confidence="medium",
                    runnable=False,
                    reason=(
                        "OpenAPI schema detected but no localhost "
                        "base URL; refusing to auto-run against "
                        "an unknown/remote server"
                    ),
                    source=rel,
                    metadata={
                        "needs": "explicit local base URL or importable ASGI app",
                    },
                ),
            )

    dedup: dict[tuple[str, str], DiscoveredTarget] = {}
    for cand in out:
        key = (cand.kind, cand.name)
        previous = dedup.get(key)
        if previous is None or (cand.runnable and not previous.runnable):
            dedup[key] = cand
    return list(dedup.values())


# trace:v1 id=impl.src-bughunt-discovery.discover-all work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def discover_all(
    root: Path,
    source_paths: list[str],
    *,
    atheris_runs: int = 250_000,
    schemathesis_examples: int = 500,
) -> list[DiscoveredTarget]:
    targets = discover_schemathesis(root, source_paths, schemathesis_examples)
    targets.extend(discover_atheris(root, source_paths, atheris_runs))
    targets.extend(discover_custom_campaigns(root, source_paths))
    models = discover_pysa_models(root, source_paths)
    write_pysa_models(root, models)
    registry = root / ".bughunt" / "generated" / "targets.json"
    registry.parent.mkdir(parents=True, exist_ok=True)
    registry.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "targets": [asdict(target) for target in targets],
                "pysa_models": [asdict(model) for model in models],
            },
            indent=2,
        )
        + "\n",
    )
    return targets


def load_generated_targets(root: Path) -> list[DiscoveredTarget]:
    path = root / ".bughunt" / "generated" / "targets.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
        return [DiscoveredTarget(**item) for item in data.get("targets", [])]
    except (OSError, json.JSONDecodeError, TypeError):
        return []
