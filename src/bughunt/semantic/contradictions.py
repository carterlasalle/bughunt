# Copyright (c) 2026 Carter LaSalle
"""Contradiction detectors: semantic values vs sink contracts.

BHUNIT004 fires when a value carrying Time[ms] (or any dimension/unit
incompatible with the sink) reaches a sink with a known contract such
as ``time.sleep`` requiring Time[s] — including across function
boundaries via propagated summaries. Name-only evidence without a
contract sink stays silent; a valid ``/1000`` conversion is recognized
upstream and never contradicts.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..graph.facts import GraphFacts
from . import infer
from .flow import CallSite, Summary, extract_file, propagate, resolve
from .model import HIGH_CONFIDENCE, MEDIUM_CONFIDENCE, SemanticValue


# trace:v1 id=impl.src-bughunt-semantic-contradictions.contradiction work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
@dataclass(slots=True)
class Contradiction:
    code: str
    message: str
    file: str
    caller: str
    sink: str
    lineno: int
    confidence: float


# trace:v1 id=impl.src-bughunt-semantic-contradictions.scan-sinks work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def scan_sinks(summaries: dict[str, Summary], facts: GraphFacts) -> list[Contradiction]:
    """Check every call site against known sink contracts."""
    _ = facts
    out: list[Contradiction] = []
    for key, summary in summaries.items():
        for site in summary.calls:
            if site.func_name is None or not site.args:
                continue
            required = _sink_for(site.func_name)
            if required is None:
                continue
            actual = _final_arg(summary, site, 0)
            clash = _clash(actual, required)
            if clash is None:
                continue
            code, message = clash
            confidence = min(actual.confidence, required.confidence)
            sources = _source_count(actual)
            if confidence >= HIGH_CONFIDENCE or (
                confidence >= MEDIUM_CONFIDENCE and sources >= 2
            ):
                out.append(
                    Contradiction(
                        code=code,
                        message=message,
                        file=summary.file,
                        caller=key,
                        sink=site.func_name,
                        lineno=site.lineno,
                        confidence=confidence,
                    )
                )
    return out


# trace:v1 id=impl.src-bughunt-semantic-contradictions.-sink-for work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _sink_for(dotted: str) -> SemanticValue | None:
    short = dotted.split(".")[-1]
    for name, contract in infer.SINK_CONTRACTS.items():
        if name.split(".")[-1] == short or name == dotted:
            return contract
    return None


# trace:v1 id=impl.src-bughunt-semantic-contradictions.-final-arg work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _final_arg(summary: Summary, site: CallSite, position: int) -> SemanticValue:
    """Resolve a sink argument through post-propagation bindings/params."""
    snapshot = site.args[position]
    name = site.arg_names[position] if position < len(site.arg_names) else None
    if name is not None:
        for scope in (summary.bindings, summary.params):
            if name in scope and scope[name].confidence >= snapshot.confidence:
                return scope[name]
    return snapshot


# trace:v1 id=impl.src-bughunt-semantic-contradictions.-clash work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _clash(actual: SemanticValue, required: SemanticValue) -> tuple[str, str] | None:
    if (
        actual.encoding is not None
        and required.encoding is not None
        and actual.encoding != required.encoding
    ):
        return "BHSEM009", (
            f"encoding mismatch: value carries {actual.encoding} "
            f"({actual.provenance}) but {required.provenance} requires "
            f"{required.encoding}"
        )
    if not actual.dimension or not required.dimension:
        return None
    if "bad-divisor" in actual.provenance:
        return "BHUNIT004", (
            f"milliseconds divided by a non-1000 factor flow into "
            f"{required.provenance}; expected Time[s], observed Time[ms] "
            f"with an invalid conversion"
        )
    if actual.dimension != required.dimension:
        return "BHUNIT004", (
            f"dimension mismatch: value carries {actual.dimension} "
            f"({actual.provenance}) but {required.provenance} requires "
            f"{required.dimension}"
        )
    if (
        actual.unit is not None
        and required.unit is not None
        and actual.unit != required.unit
    ):
        return "BHUNIT004", (
            f"unit mismatch: value carries {actual.unit} "
            f"({actual.provenance}) but {required.provenance} requires "
            f"{required.unit}"
        )
    return None


# trace:v1 id=impl.src-bughunt-semantic-contradictions.-source-count work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _source_count(actual: SemanticValue) -> int:
    ranks = {
        "annotation",
        "api-contract",
        "schema",
        "docstring",
        "name",
        "comment",
        "conversion",
    }
    count = 0
    for token in actual.provenance.replace("+", " ").replace("/", " ").split():
        if token.split(":")[0] in ranks:
            count += 1
    return count


# trace:v1 id=impl.src-bughunt-semantic-contradictions.scan work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def scan(root: Path, files: list[Path], facts: GraphFacts) -> list[Contradiction]:
    """End-to-end: extract, propagate over SCC edges, check sinks."""
    summaries: dict[str, Summary] = {}
    for path in files:
        for qualname, summary in extract_file(path, root).items():
            summaries[f"{summary.file}::{qualname}"] = summary
    summaries = propagate(summaries, facts)
    return (
        scan_sinks(summaries, facts)
        + scan_nominal(summaries, facts)
        + scan_tags(summaries)
        + scan_nullable(summaries)
    )


# trace:v1 id=impl.src-bughunt-semantic-contradictions.scan-nominal work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def scan_nominal(
    summaries: dict[str, Summary], facts: GraphFacts
) -> list[Contradiction]:
    """BHSEM001/002/008: nominal/frame mismatch across resolved calls.

    When a resolved callee parameter carries a nominal domain (user-id,
    instant, ...) or frame (world, camera) and the caller's argument
    value carries a different one, the representations agree but the
    meanings do not.
    """
    _ = facts
    index: dict[str, list[str]] = {}
    for key in summaries:
        index.setdefault(key.split("::")[-1].split(".")[-1], []).append(key)
    out: list[Contradiction] = []
    for key, summary in summaries.items():
        for site in summary.calls:
            if site.func_name is None:
                continue
            callee = resolve(summaries, facts, summary, site, index)
            if callee is None:
                continue
            for position, value in enumerate(site.args):
                if position >= len(callee.param_order):
                    break
                param = callee.params[callee.param_order[position]]
                actual = _final_named(summary, site, position, value)
                hit = _nominal_clash(actual, param)
                if hit is None:
                    continue
                code, message = hit
                confidence = min(actual.confidence, param.confidence)
                if confidence >= HIGH_CONFIDENCE or (
                    confidence >= MEDIUM_CONFIDENCE
                    and _source_count(actual) + _source_count(param) >= 2
                ):
                    out.append(
                        Contradiction(
                            code=code,
                            message=message,
                            file=summary.file,
                            caller=key,
                            sink=site.func_name,
                            lineno=site.lineno,
                            confidence=confidence,
                        )
                    )
    return out


# trace:v1 id=impl.src-bughunt-semantic-contradictions.-final-named work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _final_named(
    summary: Summary, site: CallSite, position: int, snapshot: SemanticValue
) -> SemanticValue:
    """Bindings-aware argument value for nominal comparison."""
    name = site.arg_names[position] if position < len(site.arg_names) else None
    if name is not None:
        for scope in (summary.bindings, summary.params):
            if name in scope and scope[name].confidence >= snapshot.confidence:
                return scope[name]
    return snapshot


# trace:v1 id=impl.src-bughunt-semantic-contradictions.-nominal-clash work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _nominal_clash(
    actual: SemanticValue, param: SemanticValue
) -> tuple[str, str] | None:
    if (
        actual.nominal is not None
        and param.nominal is not None
        and actual.nominal != param.nominal
    ):
        code = (
            "BHSEM002"
            if {actual.nominal, param.nominal} <= {"instant", "duration"}
            else "BHSEM001"
        )
        return code, (
            f"nominal-domain mismatch: argument carries {actual.nominal} "
            f"({actual.provenance}) but parameter expects {param.nominal} "
            f"({param.provenance})"
        )
    if (
        actual.frame is not None
        and param.frame is not None
        and actual.frame != param.frame
    ):
        return "BHSEM008", (
            f"coordinate-frame mismatch: argument in {actual.frame} "
            f"({actual.provenance}) but parameter expects {param.frame} "
            f"({param.provenance})"
        )
    if (
        actual.unit is not None
        and param.unit is not None
        and actual.unit != param.unit
        and {actual.unit, param.unit} <= {"percent", "fraction"}
    ):
        return "BHSEM007", (
            f"scale mismatch: argument carries {actual.unit} "
            f"({actual.provenance}) but parameter expects {param.unit} "
            f"({param.provenance})"
        )
    shape_clash = _shape_clash(actual, param)
    if shape_clash is not None:
        return "BHSEM006", shape_clash
    return None


# trace:v1 id=impl.src-bughunt-semantic-contradictions.-shape-clash work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _shape_clash(actual: SemanticValue, param: SemanticValue) -> str | None:
    """Symbolic/concrete shape disagreement dimension by dimension."""
    if actual.shape is None or param.shape is None:
        return None
    if len(actual.shape) != len(param.shape):
        return (
            f"shape-rank mismatch: argument has {len(actual.shape)} dims "
            f"({actual.provenance}) but parameter expects "
            f"{len(param.shape)} ({param.provenance})"
        )
    for have, want in zip(actual.shape, param.shape):
        if have == "?" or want == "?":
            continue
        if have != want:
            return (
                f"shape mismatch: argument {actual.shape} "
                f"({actual.provenance}) but parameter expects {param.shape} "
                f"({param.provenance})"
            )
    return None


# trace:v1 id=impl.src-bughunt-semantic-contradictions.scan-tags work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def scan_tags(summaries: dict[str, Summary]) -> list[Contradiction]:
    """BHUNIT004/BHSEM002: contradiction tags left by transfer rules."""
    out: list[Contradiction] = []
    for key, summary in summaries.items():
        values: list[tuple[str, SemanticValue]] = [
            (name, value)
            for name, value in list(summary.bindings.items())
            + [(n, p) for n, p in summary.params.items()]
            + [(f"return@{i}", r) for i, r in enumerate(summary.returns)]
        ]
        for name, value in values:
            hit = _tag_for(value)
            if hit is None:
                continue
            code, tag = hit
            if value.confidence >= HIGH_CONFIDENCE or (
                value.confidence >= MEDIUM_CONFIDENCE and _source_count(value) >= 2
            ):
                out.append(
                    Contradiction(
                        code=code,
                        message=tag,
                        file=summary.file,
                        caller=key,
                        sink=name,
                        lineno=0,
                        confidence=value.confidence,
                    )
                )
    return out


# trace:v1 id=impl.src-bughunt-semantic-contradictions.-tag-for work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _tag_for(value: SemanticValue) -> tuple[str, str] | None:
    """Map a transfer-rule tag to (rule code, message)."""
    provenance = value.provenance
    table = (
        ("dimension-clash:", "BHUNIT004", "dimension mismatch"),
        ("instant-clash:", "BHSEM002", "instant added to instant"),
        ("tz-clash:", "BHSEM003", "aware mixed with naive datetime"),
        ("narrow:", "BHSEM004", "dtype narrowing"),
        ("promotion-risk:", "BHSEM005", "unsafe dtype promotion"),
        ("shape-clash:", "BHSEM006", "reshape total mismatch"),
    )
    for prefix, code, label in table:
        if provenance.startswith(prefix):
            return code, (f"{label}: {provenance} (confidence {value.confidence:.2f})")
    return None


# trace:v1 id=impl.src-bughunt-semantic-contradictions.scan-nullable work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def scan_nullable(summaries: dict[str, Summary]) -> list[Contradiction]:
    """BHSEM010: method call on a possibly-None value without a guard.

    Sources are single-argument ``.get()`` and other nullable-typed
    values. Guard evidence is any ``is``/``is not`` comparison on the
    name in the same function; direction is not modeled, so severity
    stays warning and confidence is capped at 0.60.
    """
    out: list[Contradiction] = []
    for key, summary in summaries.items():
        for lineno, name, value in summary.derefs:
            if not value.nullable or name in summary.guarded:
                continue
            confidence = min(value.confidence, 0.60)
            if confidence >= MEDIUM_CONFIDENCE:
                out.append(
                    Contradiction(
                        code="BHSEM010",
                        message=(
                            f"possible None dereference: {name} may be None "
                            f"({value.provenance}) with no `is None` guard "
                            f"in {key}"
                        ),
                        file=summary.file,
                        caller=key,
                        sink=name,
                        lineno=lineno,
                        confidence=confidence,
                    )
                )
    return out
