# Copyright (c) 2026 Carter LaSalle
"""Normalized System IR facts for BugHunt's graph-backed detectors.

SCC remains the canonical who-calls-whom source. This module only
normalizes the cached ``system-ir.json`` export into typed facts with
provenance and confidence preserved — it never re-derives call
resolution. Anything about WHAT flows (arguments, returns,
assignments) comes from BugHunt's own AST pass joined to these edges.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


# trace:v1 id=impl.src-bughunt-graph-facts.symbol work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
@dataclass(frozen=True, slots=True)
class Symbol:
    """A callable/value symbol: canonical URI, file, short name."""

    uri: str
    file: str
    name: str


# trace:v1 id=impl.src-bughunt-graph-facts.call-edge work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
@dataclass(frozen=True, slots=True)
class CallEdge:
    caller: Symbol
    callee: Symbol
    confidence: float


# trace:v1 id=impl.src-bughunt-graph-facts.boundary-sink work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
@dataclass(frozen=True, slots=True)
class BoundarySink:
    """A symbol reaching an external API (e.g. ``time.sleep``)."""

    symbol: Symbol
    external: str
    confidence: float


# trace:v1 id=impl.src-bughunt-graph-facts.test-link work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
@dataclass(frozen=True, slots=True)
class TestLink:
    """Heuristic symbol↔test association. Supporting evidence only."""

    symbol: Symbol
    test: str
    confidence: float


# trace:v1 id=impl.src-bughunt-graph-facts.graph-facts work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
@dataclass(slots=True)
class GraphFacts:
    symbols: dict[str, Symbol] = field(default_factory=dict)
    calls: list[CallEdge] = field(default_factory=list)
    calls_from: dict[str, list[CallEdge]] = field(default_factory=dict)
    calls_to: dict[str, list[CallEdge]] = field(default_factory=dict)
    sinks: list[BoundarySink] = field(default_factory=list)
    tests: list[TestLink] = field(default_factory=list)
    evidence_lines: dict[str, int] = field(default_factory=dict)


# trace:v1 id=impl.src-bughunt-graph-facts.-symbol-of work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _symbol_of(uri: str, cache: dict[str, Symbol]) -> Symbol:
    hit = cache.get(uri)
    if hit is not None:
        return hit
    rest = uri.split("://", 1)[1] if "://" in uri else uri
    parts = rest.split("/")
    if len(parts) >= 4:
        file = "/".join(parts[2:-1])
        name = parts[-1]
    else:  # pragma: no cover - defensive: malformed URIs never match
        file, name = "", uri
    sym = Symbol(uri=uri, file=file, name=name)
    cache[uri] = sym
    return sym


# trace:v1 id=impl.src-bughunt-graph-facts.load work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def load(cache_path: Path) -> GraphFacts:
    """Load normalized facts from a cached System IR export payload."""
    facts = GraphFacts()
    try:
        payload = json.loads(cache_path.read_text())
    except (OSError, ValueError):
        return facts
    if not isinstance(payload, dict):
        return facts
    system_ir = payload.get("system_ir", payload)
    if not isinstance(system_ir, dict):
        return facts
    symbols: dict[str, Symbol] = facts.symbols
    for rel in system_ir.get("relationships", []):
        if not isinstance(rel, dict):
            continue
        predicate = rel.get("predicate")
        try:
            confidence = float(rel.get("confidence", 0.0))
        except (TypeError, ValueError):
            continue
        if predicate == "calls":
            caller = _symbol_of(str(rel.get("subject", "")), symbols)
            callee = _symbol_of(str(rel.get("object", "")), symbols)
            edge = CallEdge(caller, callee, confidence)
            facts.calls.append(edge)
            facts.calls_from.setdefault(caller.uri, []).append(edge)
            facts.calls_to.setdefault(callee.uri, []).append(edge)
        elif predicate == "crosses_boundary":
            sym = _symbol_of(str(rel.get("subject", "")), symbols)
            external = str(rel.get("object", "")).split("/")[-1]
            facts.sinks.append(BoundarySink(sym, external, confidence))
        elif predicate == "tested_by":
            sym = _symbol_of(str(rel.get("subject", "")), symbols)
            test = str(rel.get("object", "")).split("/")[-1]
            facts.tests.append(TestLink(sym, test, confidence))
    for item in system_ir.get("evidence", []):
        if not isinstance(item, dict):
            continue
        symbol = item.get("symbol")
        line = item.get("start_line")
        if isinstance(symbol, str) and isinstance(line, int):
            facts.evidence_lines[symbol] = line
    return facts
