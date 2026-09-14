# Copyright (c) 2026 Carter LaSalle
"""Semantic abstract values and the evidence-confidence system.

A value is never modeled as merely ``float`` or ``ndarray``. Every
program point carries a SemanticValue: the Python representation plus
every semantic facet any domain can prove about it, each with the
provenance and confidence of the evidence behind it.
"""

from __future__ import annotations

import dataclasses

from dataclasses import dataclass, field


EVIDENCE_RANK: dict[str, float] = {
    "annotation": 1.00,
    "api-contract": 0.98,
    "schema": 0.95,
    "docstring": 0.85,
    "name": 0.80,
    "comment": 0.75,
    "conversion": 0.70,
    "magnitude": 0.20,
}

HIGH_CONFIDENCE = 0.70
MEDIUM_CONFIDENCE = 0.45
FLOOR_CONFIDENCE = 0.10


# trace:v1 id=impl.src-bughunt-semantic-model.semantic-value work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
@dataclass(slots=True)
class SemanticValue:
    python_type: str | None = None
    dimension: dict[str, int] = field(default_factory=dict)
    unit: str | None = None
    nominal: str | None = None
    dtype: str | None = None
    shape: tuple[str | int, ...] | None = None
    numeric_range: tuple[float, float] | None = None
    nullable: bool = False
    timezone: str | None = None
    encoding: str | None = None
    frame: str | None = None
    provenance: str = "unknown"
    confidence: float = 0.0

    # trace:v1 id=impl.src-bughunt-semantic-model.semantic-value.with-evidence work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    def with_evidence(self, kind: str, provenance: str) -> SemanticValue:
        """Copy carrying the confidence of a new evidence kind."""
        rank = EVIDENCE_RANK.get(kind, FLOOR_CONFIDENCE)
        merged = dataclasses.replace(self)
        merged.provenance = provenance
        merged.confidence = min(self.confidence, rank) if self.confidence else rank
        return merged


# trace:v1 id=impl.src-bughunt-semantic-model.combine work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def combine(first: SemanticValue, second: SemanticValue) -> SemanticValue:
    """Conservative join: keep a facet only when both sides agree."""
    out = dataclasses.replace(first, dimension=dict(first.dimension))
    if first.unit != second.unit:
        out.unit = None
    if first.nominal != second.nominal:
        out.nominal = None
    if first.dtype != second.dtype:
        out.dtype = None
    if first.shape != second.shape:
        out.shape = None
    if first.timezone != second.timezone:
        out.timezone = None
    if first.encoding != second.encoding:
        out.encoding = None
    if first.frame != second.frame:
        out.frame = None
    if first.dimension != second.dimension:
        out.dimension = {}
    out.nullable = first.nullable or second.nullable
    out.confidence = max(FLOOR_CONFIDENCE, min(first.confidence, second.confidence))
    out.provenance = f"{first.provenance}+{second.provenance}"
    return out
