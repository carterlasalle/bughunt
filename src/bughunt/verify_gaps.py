# Copyright (c) 2026 Carter LaSalle
"""Direct-verification gaps over the System IR graph.

Three cheapest high-signal graph rules, computed from the cached System IR
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

BHVERIFY002 — unverified boundary fault path: a module-level public function
that calls an external boundary (HTTP, subprocess, socket, database) and has
no detected failure-path test. A happy-path test proves the success branch
only, and the failure branches (timeout, refused connection, non-zero exit,
malformed response, lost acknowledgement) are where boundary code actually
breaks. The finding lists the boundary calls it saw; "detected" is
load-bearing because a fault can also be injected through a fake server or a
fixture this scan cannot see. Emitted only when neither rule above already
owns the symbol, so one function never collects two gap findings.
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

STUB_RAISES = {"NotImplementedError"}

# External boundary calls whose failure paths are worth verifying. Qualified
# rather than bare where a bare name is ambiguous (`send`/`write`/`connect`
# match half a tree); the leaves in BOUNDARY_LEAVES are unambiguous enough to
# match on their own. Precision over recall: an unlisted boundary costs a
# missed signal, while a wrongly listed one costs a false finding.
EXTERNAL_BOUNDARIES = frozenset(
    {
        # HTTP and RPC clients
        "requests.request",
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.patch",
        "requests.delete",
        "requests.head",
        "requests.Session",
        "httpx.request",
        "httpx.get",
        "httpx.post",
        "httpx.put",
        "httpx.delete",
        "httpx.stream",
        "httpx.Client",
        "httpx.AsyncClient",
        "urllib.request.urlopen",
        "urllib.request.Request",
        "aiohttp.ClientSession",
        "aiohttp.request",
        "websockets.connect",
        "websocket.create_connection",
        # process and shell
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "os.system",
        "os.popen",
        "os.execv",
        "os.execvp",
        "os.spawnv",
        # sockets
        "socket.socket",
        "socket.create_connection",
        "socket.getaddrinfo",
        # databases, queues, object stores
        "sqlite3.connect",
        "psycopg.connect",
        "psycopg2.connect",
        "asyncpg.connect",
        "pymysql.connect",
        "mysql.connector.connect",
        "MySQLdb.connect",
        "sqlalchemy.create_engine",
        "redis.Redis",
        "redis.from_url",
        "boto3.client",
        "boto3.resource",
        "botocore.client",
        "pymongo.MongoClient",
        "elasticsearch.Elasticsearch",
        "kafka.KafkaProducer",
        "kafka.KafkaConsumer",
        "pika.BlockingConnection",
    }
)

# Leaf names that are the boundary on their own, whatever the receiver is.
BOUNDARY_LEAVES = frozenset(
    {
        "urlopen",
        "create_connection",
        "getaddrinfo",
        "Popen",
        "check_output",
        "check_call",
        "create_engine",
        "MongoClient",
    }
)

# Database execution: the receiver name carries no usable information (`cur`,
# `c`, `tx`, `session`), so the leaf is the only signal. `execute` exists on
# non-SQL objects too, which is why the finding calls these candidate
# boundaries instead of SQL calls.
DB_EXEC_LEAVES = frozenset({"execute", "executemany"})

# Evidence that a test exercises a failure path rather than only the success
# path. Substring tokens, each one an exception type, a failure-injection call,
# or a documented wrong-result idiom. Kept short and specific: a broad word like
# "timeout" matches `timeout=5` in a happy-path test and would suppress every
# real finding.
FAILURE_MARKERS = (
    "pytest.raises",
    "raises(",
    "side_effect",
    "raise_for_status",
    "TimeoutError",
    "TimeoutExpired",
    "socket.timeout",
    "ReadTimeout",
    "ConnectTimeout",
    "ConnectionError",
    "ConnectionResetError",
    "ConnectionRefusedError",
    "BrokenPipeError",
    "CalledProcessError",
    "HTTPError",
    "RequestException",
    "ClientError",
    "JSONDecodeError",
    "UnicodeDecodeError",
    "OperationalError",
    "IntegrityError",
    "PermissionError",
    "FileNotFoundError",
    "NotADirectoryError",
    "OSError",
    "IOError",
    "CancelledError",
    "KeyboardInterrupt",
)

# A test whose own name promises a failure path counts as evidence even without
# a marker in the body (`def test_retries_on_429`). Words are stems so
# "fails"/"failed"/"refused" all match. The absence vocabulary ("without",
# "missing", "none") is included on purpose: `test_llvm_executable_without_
# toolchain_is_none` injects the boundary's degradation through a doubled
# collaborator, with no exception name anywhere in the body.
FAILURE_NAME_WORDS = (
    "fail",
    "error",
    "timeout",
    "retr",
    "unavailable",
    "refus",
    "reject",
    "broken",
    "interrupt",
    "cancel",
    "degrade",
    "fallback",
    "raise",
    "denied",
    "exhaust",
    "partial",
    "missing",
    "without",
    "absent",
    "none",
    "empty",
    "invalid",
    "malformed",
    "incomplete",
    "unsupported",
    "unset",
    "disabled",
    "stale",
    "conflict",
    "corrupt",
)


# trace:v1 id=impl.src-bughunt-verify-gaps.-graph work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _graph(root: Path) -> tuple[dict[str, object] | None, str | None]:
    """Cached System IR payload, with the reason when it is unusable.

    The reason is load-bearing: an unavailable graph is otherwise
    indistinguishable from a clean tree, and the ring's contract
    (system_ir_adapter) is that a failing index/export is an error, never clean.
    """
    from bughunt.system_ir_adapter import export

    cache, error = export(root)
    if error is not None:
        return None, error
    if cache is None:
        return None, "system-ir export produced no cache"
    try:
        payload = json.loads(cache.read_text())
    except OSError as exc:
        return None, f"cannot read {cache}: {exc}"
    except json.JSONDecodeError:
        return None, f"{cache} is not valid JSON"
    data = payload.get("system_ir")
    if not isinstance(data, dict):
        return None, f"{cache} carries no system_ir payload"
    return data, None


# trace:v1 id=impl.src-bughunt-verify-gaps.-load-graph work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _load_graph(root: Path) -> dict[str, object] | None:
    """Cached System IR payload, or None when the graph is unavailable."""
    return _graph(root)[0]


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
        mentioned |= _mentioned_symbols(tree, imported, _module_locals(tree))
    return mentioned


# trace:v1 id=impl.src-bughunt-verify-gaps.-dotted-name work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _dotted_name(node: ast.AST) -> str:
    """`requests.get` for an attribute chain, `` for anything else.

    A call whose callee is itself a call or an await (`get_client().fetch()`)
    has no stable dotted name and resolves to the empty string, which never
    matches a boundary.
    """
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not parts:
        return current.id if isinstance(current, ast.Name) else ""
    if not isinstance(current, ast.Name):
        return ""
    parts.append(current.id)
    return ".".join(reversed(parts))


# trace:v1 id=impl.src-bughunt-verify-gaps.-import-aliases work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _import_aliases(tree: ast.Module) -> dict[str, str]:
    """Local root name -> real dotted prefix, so `r.get` resolves under `as r`."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    root = alias.name.split(".")[0]
                    aliases[root] = root
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


# trace:v1 id=impl.src-bughunt-verify-gaps.-resolve-alias work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _resolve_alias(dotted: str, aliases: dict[str, str]) -> str:
    """Rewrite a call's first segment through the file's import aliases."""
    head, _, rest = dotted.partition(".")
    base = aliases.get(head)
    if base is None:
        return dotted
    return f"{base}.{rest}" if rest else base


# trace:v1 id=impl.src-bughunt-verify-gaps.-boundary-calls work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _boundary_calls(tree: ast.Module, start: object) -> list[str]:
    """Dotted external-boundary calls in the function opening at `start`.

    Nested defs are skipped: their calls belong to the nested function, which
    the graph reports as its own symbol.
    """
    if not isinstance(start, int):
        return []
    function: ast.FunctionDef | ast.AsyncFunctionDef | None = None
    for node in ast.walk(tree):
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.lineno == start
        ):
            function = node
            break
    if function is None:
        return []
    aliases = _import_aliases(tree)
    found: set[str] = set()
    stack: list[ast.AST] = list(function.body)
    while stack:
        node = stack.pop()
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
        ):
            continue
        if isinstance(node, ast.Call):
            dotted = _resolve_alias(_dotted_name(node.func), aliases)
            leaf = dotted.rsplit(".", 1)[-1] if dotted else ""
            if (
                dotted in EXTERNAL_BOUNDARIES
                or leaf in BOUNDARY_LEAVES
                or leaf in DB_EXEC_LEAVES
            ):
                found.add(dotted)
        stack.extend(ast.iter_child_nodes(node))
    return sorted(found)


# trace:v1 id=impl.src-bughunt-verify-gaps.-failure-path-tests work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _failure_path_tests(root: Path) -> set[tuple[str, str]]:
    """(module, name) pairs named inside a test that shows failure handling.

    Same import-then-name heuristic as `_test_mentions`, narrowed to test
    functions that promise a failure in their own name or carry a failure
    marker in the body. Only suppressions flow from this: a fault injected
    through a fake server, a subprocess fixture, or a separate integration
    repository is invisible here and simply yields no suppression.
    """
    covered: set[tuple[str, str]] = set()
    test_dir = root / "tests"
    if not test_dir.is_dir():
        return covered
    for path in sorted(test_dir.rglob("*.py")):
        try:
            source = path.read_text(errors="replace")
            tree = ast.parse(source)
        except (OSError, SyntaxError):
            continue
        imported: set[tuple[str, str]] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    imported.add((node.module, alias.asname or alias.name))
        if not imported:
            continue
        module_locals = _module_locals(tree)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not any(word in node.name for word in FAILURE_NAME_WORDS):
                segment = ast.get_source_segment(source, node) or ""
                if not any(marker in segment for marker in FAILURE_MARKERS):
                    continue
            covered |= _mentioned_symbols(node, imported, module_locals)
    return covered


# trace:v1 id=impl.src-bughunt-verify-gaps.-absolute-import work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _absolute_import(node: ast.ImportFrom, importer_module: str) -> str | None:
    """Absolute dotted source of an ImportFrom, resolving relative levels.

    `from .runners import X` inside `bughunt/cli.py` is `bughunt.runners`, which
    is the module the graph records for the symbol. Without this the re-export
    scan misses every in-package import and re-exported symbols look untested.
    """
    if node.level == 0:
        return node.module
    package = importer_module.split(".")[:-1]
    if node.level > 1:
        drop = node.level - 1
        package = package[:-drop] if drop <= len(package) else []
    if node.module:
        package = [*package, node.module]
    return ".".join(package) or None


# trace:v1 id=impl.src-bughunt-verify-gaps.-module-locals work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _module_locals(tree: ast.Module) -> dict[str, str]:
    """Local name -> the module path it stands for, for tests that import a module.

    `from bughunt.semantic import crosshair_confirm` binds a *module*, so
    `crosshair_confirm.confirm(...)` inside the test verifies the symbol that
    lives in `bughunt.semantic.crosshair_confirm`. Relative imports are skipped:
    test trees are not packages, so their relative forms resolve to nothing
    useful.
    """
    locals_: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    locals_[alias.asname] = alias.name
                else:
                    root = alias.name.split(".")[0]
                    locals_[root] = root
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                locals_[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return locals_


# trace:v1 id=impl.src-bughunt-verify-gaps.-mentioned-symbols work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _mentioned_symbols(
    scope: ast.AST,
    imported: set[tuple[str, str]],
    module_locals: dict[str, str],
) -> set[tuple[str, str]]:
    """(module, name) pairs `scope` reaches, bare or through a module attribute."""
    names = {n.id for n in ast.walk(scope) if isinstance(n, ast.Name)}
    names |= {n.attr for n in ast.walk(scope) if isinstance(n, ast.Attribute)}
    out = {(module, name) for module, name in imported if name in names}
    for node in ast.walk(scope):
        if not isinstance(node, ast.Attribute):
            continue
        root: ast.expr = node
        while isinstance(root, ast.Attribute):
            root = root.value
        if not isinstance(root, ast.Name):
            continue
        base = module_locals.get(root.id)
        if base is None:
            continue
        chain = _dotted_name(node).split(".")
        rest = chain[1:] if chain and chain[0] == root.id else []
        if len(rest) >= 2:
            out.add((f"{base}.{'.'.join(rest[:-1])}", rest[-1]))
        elif len(rest) == 1:
            out.add((base, rest[0]))
    return out


# trace:v1 id=impl.src-bughunt-verify-gaps.scan work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def scan(root: Path) -> list[dict[str, object]]:
    """Compute verification gaps from the cached System IR."""
    data = _load_graph(root)
    if not data:
        return []
    return _scan_graph(root, data)


# trace:v1 id=impl.src-bughunt-verify-gaps.-scan-graph work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _scan_graph(root: Path, data: dict[str, object]) -> list[dict[str, object]]:
    """Apply the gap rules to an already-loaded System IR payload."""
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
    failure_path = _failure_path_tests(root)
    trees: dict[str, ast.Module | None] = {}

    # trace:exempt reason=internal-detail
    def tree_of(file: str) -> ast.Module | None:
        if file in trees:
            return trees[file]
        try:
            parsed: ast.Module | None = ast.parse(
                (root / file).read_text(errors="replace")
            )
        except (OSError, SyntaxError):
            parsed = None
        trees[file] = parsed
        return parsed

    # A test that imports the symbol from a package's convenience module
    # (`from bughunt.cli import reset_tool_dir`) verifies the symbol that lives
    # in `bughunt.runners` just as directly. Re-exports are how real packages
    # expose their surface, so the mention match has to follow them.
    reexports: dict[tuple[str, str], set[str]] = {}
    src_dir = root / "src"
    if src_dir.is_dir():
        for path in sorted(src_dir.rglob("*.py")):
            src_file = path.relative_to(root).as_posix()
            tree = tree_of(src_file)
            if tree is None:
                continue
            module = module_of(src_file)
            for node in ast.walk(tree):
                if not isinstance(node, ast.ImportFrom):
                    continue
                source = _absolute_import(node, module)
                if source is None:
                    continue
                for alias in node.names:
                    reexports.setdefault((source, alias.name), set()).add(module)

    # trace:exempt reason=internal-detail
    def mention_keys(module: str, name: str) -> set[tuple[str, str]]:
        keys = {(module, name)}
        keys |= {(other, name) for other in reexports.get((module, name), set())}
        return keys

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
        start = attributes.get("start_line")
        if not _module_level(root, file, start):
            continue
        line = start if isinstance(start, int) else 1
        keys = mention_keys(module_of(file), name)
        has_direct_test = symbol_id in tested or not keys.isdisjoint(mentioned)
        if not has_direct_test:
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
                            f"`{name}` has no detected direct test; its "
                            f"verification is transitive through tested callees "
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
                continue
        # Neither rule above owns this symbol, so the boundary fault path is the
        # next thing worth naming: a happy-path test says nothing about a
        # timeout, a refused connection, or a non-zero exit.
        if not keys.isdisjoint(failure_path):
            continue
        tree = tree_of(file)
        if tree is None:
            continue
        boundaries = _boundary_calls(tree, line)
        if boundaries:
            out.append(
                {
                    "tool": "verify-gaps",
                    "code": "BHVERIFY002",
                    "path": file,
                    "line": line,
                    "severity": "warning",
                    "message": (
                        f"`{name}` calls external boundaries "
                        f"({', '.join(boundaries[:4])}) with no detected "
                        "failure-path test"
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
    data, reason = _graph(root)
    if data is None:
        # An SCC workspace with no usable graph is a blind spot, not a clean
        # tree. Report the reason so a scan never reads PASS for a rule that
        # did not run (the ring's contract: a failing export is never clean).
        detail = reason or "unavailable"
        print(
            json.dumps(
                {
                    "findings": [
                        {
                            "tool": "verify-gaps",
                            "code": "BHVERIFY003",
                            "path": str(root),
                            "line": 1,
                            "severity": "error",
                            "message": (
                                "System IR graph unavailable, verify-gaps did "
                                f"not run: {detail}"
                            ),
                        }
                    ],
                    "error": detail,
                }
            )
        )
        return 2
    findings = _scan_graph(root, data)
    print(json.dumps({"findings": findings}))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
