# Copyright (c) 2026 Carter LaSalle
"""Dataflow: intraprocedural AST facts joined to SCC call edges.

Per file, every function becomes a Summary: parameter values, return
values, call sites with argument values, and name bindings. SCC's
resolved caller→callee edges then carry argument values across
function boundaries (forward) to a fixed point with a cycle cutoff.
Confidence is the minimum along a path: a chain is only as strong as
its weakest fact.
"""

from __future__ import annotations

import ast
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing_extensions import override

from ..graph.facts import GraphFacts
from . import infer
from .domains import units as domains_units
from .domains import dtype as domains_dtype
from .model import SemanticValue, combine

MAX_REVISITS = 3


# trace:v1 id=impl.src-bughunt-semantic-flow.call-site work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
@dataclass(slots=True)
class CallSite:
    lineno: int
    func_name: str | None
    args: list[SemanticValue] = field(default_factory=list)
    keywords: dict[str, SemanticValue] = field(default_factory=dict)
    arg_names: list[str | None] = field(default_factory=list)


# trace:v1 id=impl.src-bughunt-semantic-flow.summary work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
@dataclass(slots=True)
class Summary:
    file: str
    qualname: str
    params: dict[str, SemanticValue] = field(default_factory=dict)
    param_order: list[str] = field(default_factory=list)
    returns: list[SemanticValue] = field(default_factory=list)
    calls: list[CallSite] = field(default_factory=list)
    bindings: dict[str, SemanticValue] = field(default_factory=dict)
    call_results: list[tuple[str, int]] = field(default_factory=list)
    assign_nodes: list[tuple[str, ast.expr]] = field(default_factory=list)
    return_nodes: list[ast.expr] = field(default_factory=list)
    derefs: list[tuple[int, str, SemanticValue]] = field(default_factory=list)
    guarded: set[str] = field(default_factory=set)
    aliases: dict[str, str] = field(default_factory=dict)


# trace:v1 id=impl.src-bughunt-semantic-flow.extractor work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
class _Extractor(ast.NodeVisitor):
    """One pass per file: summaries with intraprocedural values."""

    # trace:v1 id=impl.src-bughunt-semantic-flow.extractor-init work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    def __init__(self, file: str) -> None:
        self.file = file
        self.summaries: dict[str, Summary] = {}
        self._prefix: list[str] = []
        self._active: list[Summary] = []
        self._env: list[dict[str, SemanticValue]] = []
        self._aliases: dict[str, str] = {}

    # trace:v1 id=impl.src-bughunt-semantic-flow._current work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    def _current(self) -> Summary | None:
        return self._active[-1] if self._active else None

    # trace:v1 id=impl.src-bughunt-semantic-flow.visit-functiondef work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    @override
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function(node.name, node.args, node.body)

    # trace:v1 id=impl.src-bughunt-semantic-flow.visit-asyncfunctiondef work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    @override
    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function(node.name, node.args, node.body)

    # trace:v1 id=impl.src-bughunt-semantic-flow.-function work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    def _function(self, name: str, args: ast.arguments, body: list[ast.stmt]) -> None:
        qualname = ".".join([*self._prefix, name])
        summary = Summary(file=self.file, qualname=qualname)
        for arg in (*args.args, *args.kwonlyargs):
            value = infer.evidence_for_name(arg.arg)
            if arg.annotation is not None:
                annotated = infer.evidence_for_annotation(ast.unparse(arg.annotation))
                if annotated is not None:
                    value = annotated if value is None else combine(value, annotated)
            if value is None:
                value = SemanticValue(provenance=f"param:{arg.arg}")
            summary.params[arg.arg] = value
            summary.param_order.append(arg.arg)
        self.summaries[qualname] = summary
        self._prefix.append(name)
        self._active.append(summary)
        self._env.append(dict(summary.params))
        for stmt in body:
            self.visit(stmt)
        summary.aliases = dict(self._aliases)
        _ = self._env.pop()
        _ = self._active.pop()
        _ = self._prefix.pop()

    # trace:v1 id=impl.src-bughunt-semantic-flow.visit-classdef work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    @override
    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._prefix.append(node.name)
        for stmt in node.body:
            self.visit(stmt)
        _ = self._prefix.pop()

    # trace:v1 id=impl.src-bughunt-semantic-flow.visit-assign work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    @override
    def visit_Assign(self, node: ast.Assign) -> None:
        self._bind(node.value, [t for t in node.targets if isinstance(t, ast.Name)])
        self.generic_visit(node)

    # trace:v1 id=impl.src-bughunt-semantic-flow.visit-annassign work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    @override
    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name) and node.value is not None:
            self._bind(node.value, [node.target])
        self.generic_visit(node)

    # trace:v1 id=impl.src-bughunt-semantic-flow.-bind work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    def _bind(self, value_node: ast.expr, targets: list[ast.Name]) -> None:
        summary = self._current()
        if summary is None or not self._env:
            return
        value = self._expr(value_node)
        if isinstance(value_node, ast.Call):
            for target in targets:
                summary.call_results.append((target.id, value_node.lineno))
        for target in targets:
            summary.assign_nodes.append((target.id, value_node))
            named = infer.evidence_for_name(target.id)
            bound = combine(named, value) if named is not None else value
            self._env[-1][target.id] = bound
            summary.bindings[target.id] = bound

    # trace:v1 id=impl.src-bughunt-semantic-flow.visit-return work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    @override
    def visit_Return(self, node: ast.Return) -> None:
        summary = self._current()
        if summary is not None and node.value is not None:
            summary.returns.append(self._expr(node.value))
            summary.return_nodes.append(node.value)
        self.generic_visit(node)

    # trace:v1 id=impl.src-bughunt-semantic-flow.visit-call work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    @override
    def visit_Call(self, node: ast.Call) -> None:
        summary = self._current()
        if summary is not None:
            site = CallSite(
                lineno=node.lineno,
                func_name=_dotted(node.func),
                args=[self._expr(a) for a in node.args],
                keywords={
                    kw.arg: self._expr(kw.value) for kw in node.keywords if kw.arg
                },
                arg_names=[_name_of(a) for a in node.args],
            )
            summary.calls.append(site)
            if isinstance(node.func, ast.Attribute) and isinstance(
                node.func.value, ast.Name
            ):
                summary.derefs.append(
                    (node.lineno, node.func.value.id, self._expr(node.func.value))
                )
            if (
                isinstance(node.func, ast.Name)
                and node.func.id == "isinstance"
                and node.args
                and isinstance(node.args[0], ast.Name)
            ):
                summary.guarded.add(node.args[0].id)
        self.generic_visit(node)

    # trace:v1 id=impl.src-bughunt-semantic-flow.visit-compare work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    @override
    def visit_Compare(self, node: ast.Compare) -> None:
        summary = self._current()
        if summary is not None and any(
            isinstance(op, (ast.Is, ast.IsNot)) for op in node.ops
        ):
            for side in [node.left, *node.comparators]:
                if isinstance(side, ast.Name):
                    summary.guarded.add(side.id)
        self.generic_visit(node)

    # trace:v1 id=impl.src-bughunt-semantic-flow.visit-if work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    @override
    def visit_If(self, node: ast.If) -> None:
        summary = self._current()
        if summary is not None:
            test = node.test
            if isinstance(test, ast.Name):
                summary.guarded.add(test.id)
            elif isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
                for value in test.values:
                    if isinstance(value, ast.Name):
                        summary.guarded.add(value.id)
            elif (
                isinstance(test, ast.UnaryOp)
                and isinstance(test.op, ast.Not)
                and isinstance(test.operand, ast.Name)
                and any(
                    isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue))
                    for stmt in node.body
                )
            ):
                summary.guarded.add(test.operand.id)
        self.generic_visit(node)

    # trace:v1 id=impl.src-bughunt-semantic-flow.visit-import work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    @override
    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._aliases[alias.asname or alias.name.split(".")[0]] = alias.name
        self.generic_visit(node)

    # trace:v1 id=impl.src-bughunt-semantic-flow.visit-importfrom work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    @override
    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            for alias in node.names:
                self._aliases[alias.asname or alias.name] = (
                    f"{node.module}.{alias.name}"
                )
        self.generic_visit(node)

    # trace:v1 id=impl.src-bughunt-semantic-flow.-expr work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    def _expr(self, node: ast.expr) -> SemanticValue:
        return _eval_node(
            node,
            lambda name: next(
                (env[name] for env in reversed(self._env) if name in env), None
            ),
            self._aliases,
        )


# trace:v1 id=impl.src-bughunt-semantic-flow.-eval-node work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _eval_node(
    node: ast.expr,
    lookup: Callable[[str], SemanticValue | None],
    aliases: dict[str, str] | None = None,
) -> SemanticValue:
    """Evaluate an expression against a name→value lookup."""
    if isinstance(node, ast.Name):
        hit = lookup(node.id)
        if hit is not None:
            return hit
        named = infer.evidence_for_name(node.id)
        return (
            named if named is not None else SemanticValue(provenance=f"name:{node.id}")
        )
    if isinstance(node, ast.Attribute):
        named = infer.evidence_for_name(node.attr)
        return (
            named
            if named is not None
            else SemanticValue(provenance=f"attr:{node.attr}")
        )
    if isinstance(node, ast.Constant):
        return SemanticValue(
            python_type=type(node.value).__name__,
            provenance=f"literal:{node.value!r}",
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return domains_units.transfer_div(
            _eval_node(node.left, lookup, aliases),
            _eval_node(node.right, lookup, aliases),
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub)):
        left = _eval_node(node.left, lookup, aliases)
        right = _eval_node(node.right, lookup, aliases)
        promoted = domains_dtype.transfer_arith(left, right)
        if promoted is not None:
            return promoted
        return domains_units.transfer_additive(left, right)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mult, ast.MatMult)):
        left = _eval_node(node.left, lookup, aliases)
        right = _eval_node(node.right, lookup, aliases)
        promoted = domains_dtype.transfer_arith(left, right)
        if promoted is not None:
            return promoted
        return domains_units.transfer_mul(left, right)
    if isinstance(node, ast.Call):
        dotted = _dotted(node.func)
        canonical = _canonicalize(dotted, aliases)
        if canonical in infer.SOURCE_CONTRACTS:
            return infer.SOURCE_CONTRACTS[canonical]
        if canonical is not None and (
            canonical.endswith("datetime.now") or canonical == "now"
        ):
            aware = any(keyword.arg == "tz" for keyword in node.keywords)
            if not aware and node.args:
                first = node.args[0]
                aware = not (isinstance(first, ast.Constant) and first.value is None)
            if aware:
                return SemanticValue(
                    nominal="instant",
                    timezone="aware",
                    provenance=f"call:{dotted}",
                    confidence=0.90,
                )
            return SemanticValue(
                nominal="instant",
                timezone="naive",
                provenance=f"call:{dotted}",
                confidence=0.90,
            )
        if dotted is not None and dotted.endswith(".get") and len(node.args) == 1:
            return SemanticValue(
                nullable=True,
                provenance=f"call:{dotted}",
                confidence=0.60,
            )
        short = dotted.split(".")[-1] if dotted else ""
        if short in {"encode"} and isinstance(node.func, ast.Attribute):
            return SemanticValue(
                encoding="bytes",
                provenance=f"call:{dotted}",
                confidence=0.85,
            )
        if short in {"decode"} and isinstance(node.func, ast.Attribute):
            return SemanticValue(
                encoding="utf8",
                provenance=f"call:{dotted}",
                confidence=0.85,
            )
        if short == "recv":
            return SemanticValue(
                encoding="bytes",
                provenance=f"call:{dotted}",
                confidence=0.80,
            )
        if short == "astype" and node.args and isinstance(node.func, ast.Attribute):
            target = domains_dtype.normalize_dtype(ast.unparse(node.args[0]))
            receiver = _eval_node(node.func.value, lookup, aliases)
            if target is not None:
                provenance = f"call:{dotted}"
                if receiver.dtype is not None and domains_dtype.is_narrower(
                    receiver.dtype, target
                ):
                    provenance = (
                        f"narrow:{receiver.dtype}->{target} ({receiver.provenance})"
                    )
                return SemanticValue(
                    dtype=target,
                    shape=receiver.shape,
                    provenance=provenance,
                    confidence=min(receiver.confidence or 0.70, 0.90),
                )
        if canonical in domains_dtype.NUMPY_CONSTRUCTORS:
            return _numpy_value(node)
        if short == "reshape" and isinstance(node.func, ast.Attribute):
            return _reshape_value(
                node, _eval_node(node.func.value, lookup, aliases), dotted
            )
        return SemanticValue(provenance=f"call:{dotted or '?'}")
    return SemanticValue(provenance=f"expr:{type(node).__name__}")


# trace:v1 id=impl.src-bughunt-semantic-flow.-dotted work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _dotted(node: ast.expr) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


# trace:v1 id=impl.src-bughunt-semantic-flow.-canonicalize work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _canonicalize(dotted: str | None, aliases: dict[str, str] | None) -> str | None:
    """Expand an import alias root (`np.zeros` → `numpy.zeros`)."""
    if dotted is None:
        return None
    if not aliases:
        return dotted
    root, _, rest = dotted.partition(".")
    target = aliases.get(root)
    if target is None:
        return dotted
    return target if not rest else f"{target}.{rest}"


# trace:v1 id=impl.src-bughunt-semantic-flow.-reshape-value work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _reshape_value(
    node: ast.Call, receiver: SemanticValue, dotted: str | None
) -> SemanticValue:
    """Reshape totals: literal totals must agree with the known shape."""
    dims: list[int] = []
    for arg in node.args:
        target = arg.elts if isinstance(arg, (ast.Tuple, ast.List)) else [arg]
        for elt in target:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, int):
                dims.append(elt.value)
            elif (
                isinstance(elt, ast.UnaryOp)
                and isinstance(elt.op, ast.USub)
                and isinstance(elt.operand, ast.Constant)
                and elt.operand.value == 1
            ):
                dims.append(-1)
            else:
                return SemanticValue(
                    dtype=receiver.dtype,
                    shape=None,
                    provenance=f"call:{dotted or 'reshape'}",
                    confidence=receiver.confidence,
                )
    if receiver.shape is not None and all(isinstance(d, int) for d in receiver.shape):
        have = 1
        for dim in receiver.shape:
            have *= int(dim)
        want = 1
        for dim in dims:
            want *= dim
        if -1 not in dims and have != want:
            return SemanticValue(
                dtype=receiver.dtype,
                shape=tuple(dims),
                provenance=(
                    f"shape-clash:reshape {have} elements into {want} "
                    f"({receiver.provenance})"
                ),
                confidence=0.75,
            )
    return SemanticValue(
        dtype=receiver.dtype,
        shape=tuple(dims) if dims else None,
        provenance=f"call:{dotted or 'reshape'}",
        confidence=receiver.confidence,
    )


# trace:v1 id=impl.src-bughunt-semantic-flow.-numpy-value work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _numpy_value(node: ast.Call) -> SemanticValue:
    """Array value from a NumPy constructor: dtype + concrete shape."""
    dtype: str | None = None
    for keyword in node.keywords:
        if keyword.arg == "dtype":
            dtype = domains_dtype.normalize_dtype(ast.unparse(keyword.value))
    shape: tuple[str | int, ...] | None = None
    if node.args and isinstance(node.args[0], (ast.Tuple, ast.List)):
        dims: list[str | int] = []
        for elt in node.args[0].elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, int):
                dims.append(elt.value)
            else:
                dims.append("?")
        shape = tuple(dims)
    return SemanticValue(
        dtype=dtype,
        shape=shape,
        provenance=f"call:{_dotted(node.func) or 'numpy'}",
        confidence=0.90 if dtype is not None else 0.50,
    )


# trace:v1 id=impl.src-bughunt-semantic-flow.-short work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _short(key: str) -> str:
    """Short function name for a possibly file-prefixed summary key."""
    return key.split("::")[-1].split(".")[-1]


# trace:v1 id=impl.src-bughunt-semantic-flow.-name-of work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _name_of(node: ast.expr) -> str | None:
    """The bare name an argument expression refers to, if any."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


# trace:v1 id=impl.src-bughunt-semantic-flow.extract-file work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def extract_file(path: Path, root: Path) -> dict[str, Summary]:
    try:
        tree = ast.parse(path.read_text(errors="replace"))
    except (OSError, SyntaxError, ValueError):
        return {}
    extractor = _Extractor(str(path.relative_to(root)))
    extractor.visit(tree)
    return extractor.summaries


# trace:v1 id=impl.src-bughunt-semantic-flow.propagate work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def propagate(
    summaries: dict[str, Summary],
    facts: GraphFacts,
    *,
    max_passes: int = 5,
) -> dict[str, Summary]:
    """Push values along SCC-resolved edges to a fixed point.

    Each pass strengthens callee params from caller bindings, then
    re-derives every summary's bindings and returns from its recorded
    assignment/return nodes. Passes repeat until nothing strengthens
    or the budget runs out, so values computed from strengthened
    params (like `x / 100`) converge instead of freezing stale.
    """
    index: dict[str, list[str]] = {}
    for key in summaries:
        index.setdefault(_short(key), []).append(key)
    for _ in range(max_passes):
        changed = False
        for summary in summaries.values():
            for site in summary.calls:
                callee = resolve(summaries, facts, summary, site, index)
                if callee is None:
                    continue
                for name, value in _bind_args(callee, site, summary).items():
                    old = callee.params.get(name)
                    if old is None or value.confidence > old.confidence:
                        callee.params[name] = value
                        changed = True
        for summary in summaries.values():
            if _finalize(summary, summaries, facts, index):
                changed = True
        if not changed:
            break
    return summaries


# trace:v1 id=impl.src-bughunt-semantic-flow.-finalize work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _finalize(
    summary: Summary,
    summaries: dict[str, Summary],
    facts: GraphFacts,
    index: dict[str, list[str]],
) -> bool:
    """Re-derive bindings and returns from nodes. True if strengthened."""
    changed = False
    env: dict[str, SemanticValue] = dict(summary.params)
    for target, node in summary.assign_nodes:
        value = _eval_node(node, env.get)
        if isinstance(node, ast.Call):
            called = _call_for(summaries, facts, summary, node, index)
            if called is not None and called.returns:
                value = called.returns[0]
                for extra in called.returns[1:]:
                    value = combine(value, extra)
        old = env.get(target)
        if old is None or value.confidence > old.confidence:
            env[target] = value
            changed = True
    summary.bindings = {
        name: value for name, value in env.items() if name not in summary.params
    }
    returns = [_eval_node(node, env.get) for node in summary.return_nodes]
    if returns and (
        len(returns) != len(summary.returns)
        or any(
            new.confidence > old.confidence
            for new, old in zip(returns, summary.returns)
        )
    ):
        summary.returns = returns
        changed = True
    return changed


# trace:v1 id=impl.src-bughunt-semantic-flow.-call-for work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _call_for(
    summaries: dict[str, Summary],
    facts: GraphFacts,
    summary: Summary,
    node: ast.Call,
    index: dict[str, list[str]],
) -> Summary | None:
    """Resolve a call AST node to its unique SCC-confirmed callee."""
    for site in summary.calls:
        if site.lineno == node.lineno and site.func_name == _dotted(node.func):
            return resolve(summaries, facts, summary, site, index)
    return None


# trace:v1 id=impl.src-bughunt-semantic-flow.resolve work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def resolve(
    summaries: dict[str, Summary],
    facts: GraphFacts,
    summary: Summary,
    site: CallSite,
    index: dict[str, list[str]],
) -> Summary | None:
    """The unique SCC-confirmed callee for a site, else None."""
    if site.func_name is None:
        return None
    short = site.func_name.split(".")[-1]
    targets = [
        t
        for t in index.get(short, [])
        if _edge_confirmed(facts, summaries, summary, summaries[t])
    ]
    if len(targets) != 1:
        return None
    return summaries[targets[0]]


# trace:v1 id=impl.src-bughunt-semantic-flow.-edge-confirmed work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _edge_confirmed(
    facts: GraphFacts, summaries: dict[str, Summary], caller: Summary, callee: Summary
) -> bool:
    """An SCC edge caller→callee (confidence ≥ 0.5) confirms inlining."""
    _ = summaries
    caller_short = caller.qualname.split(".")[-1]
    callee_short = callee.qualname.split(".")[-1]
    for edge in facts.calls:
        if (
            edge.caller.file == caller.file
            and edge.caller.name.split(".")[-1] == caller_short
            and edge.callee.file == callee.file
            and edge.callee.name.split(".")[-1] == callee_short
            and edge.confidence >= 0.5
        ):
            return True
    return False


# trace:v1 id=impl.src-bughunt-semantic-flow.-bind-args work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _bind_args(
    callee: Summary, site: CallSite, caller: Summary
) -> dict[str, SemanticValue]:
    bound: dict[str, SemanticValue] = {}
    names = site.arg_names + [None] * (len(site.args) - len(site.arg_names))
    for name, value, arg_name in zip(callee.param_order, site.args, names):
        effective = value
        if arg_name is not None and arg_name in caller.bindings:
            candidate = caller.bindings[arg_name]
            if candidate.confidence >= value.confidence:
                effective = candidate
        if effective.confidence > 0:
            bound[name] = effective
    for name, value in site.keywords.items():
        if name in callee.params and value.confidence > 0:
            bound[name] = value
    return bound
