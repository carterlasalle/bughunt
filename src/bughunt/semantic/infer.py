# Copyright (c) 2026 Carter LaSalle
"""Evidence → semantic facts: names, annotations, API contracts.

Every fact carries the rank of its source. Names are useful but weak;
annotations and known API contracts dominate. Nothing here fires a
finding — it only produces SemanticValues for propagation.
"""

from __future__ import annotations

import re

from .model import SemanticValue

_NAME_SUFFIXES: tuple[tuple[str, dict[str, int], str | None], ...] = (
    ("_ms", {"time": 1}, "ms"),
    ("_millis", {"time": 1}, "ms"),
    ("_s", {"time": 1}, "s"),
    ("_sec", {"time": 1}, "s"),
    ("_seconds", {"time": 1}, "s"),
    ("_deg", {"angle": 1}, "deg"),
    ("_degrees", {"angle": 1}, "deg"),
    ("_rad", {"angle": 1}, "rad"),
    ("_radians", {"angle": 1}, "rad"),
    ("_pct", {}, "percent"),
    ("_percent", {}, "percent"),
    ("_bits", {"data": 1}, "bits"),
    ("_bytes", {"data": 1}, "bytes"),
    ("_m", {"length": 1}, "m"),
    ("_km", {"length": 1}, "km"),
    ("_cm", {"length": 1}, "cm"),
    ("_mm", {"length": 1}, "mm"),
    ("_kg", {"mass": 1}, "kg"),
    ("_hz", {"frequency": 1}, "hz"),
)
_INSTANT_HINTS = ("_at", "_ts", "_time", "_timestamp", "_instant", "_when")
_DURATION_HINTS = ("_delay", "_elapsed", "_duration", "_timeout", "_interval")
_FRAME_SUFFIXES: tuple[tuple[str, str], ...] = (
    ("_world", "world"),
    ("_camera", "camera"),
    ("_cam", "camera"),
    ("_local", "local"),
)
_FRACTION_HINTS = (
    "_ratio",
    "_fraction",
    "_alpha",
    "_opacity",
    "_probability",
    "_share",
)


SINK_CONTRACTS: dict[str, SemanticValue] = {
    "time.sleep": SemanticValue(
        dimension={"time": 1},
        unit="s",
        provenance="api-contract:time.sleep",
        confidence=0.98,
    ),
    "asyncio.sleep": SemanticValue(
        dimension={"time": 1},
        unit="s",
        provenance="api-contract:asyncio.sleep",
        confidence=0.98,
    ),
    "socket.settimeout": SemanticValue(
        dimension={"time": 1},
        unit="s",
        provenance="api-contract:socket.settimeout",
        confidence=0.98,
    ),
    "threading.timer": SemanticValue(
        dimension={"time": 1},
        unit="s",
        provenance="api-contract:threading.Timer",
        confidence=0.98,
    ),
    "hashlib.md5": SemanticValue(
        encoding="bytes",
        provenance="api-contract:hashlib.md5",
        confidence=0.98,
    ),
    "hashlib.sha256": SemanticValue(
        encoding="bytes",
        provenance="api-contract:hashlib.sha256",
        confidence=0.98,
    ),
    "hashlib.sha1": SemanticValue(
        encoding="bytes",
        provenance="api-contract:hashlib.sha1",
        confidence=0.98,
    ),
}


SOURCE_CONTRACTS: dict[str, SemanticValue] = {
    "time.monotonic": SemanticValue(
        dimension={"time": 1},
        unit="s",
        nominal="instant",
        provenance="api-contract:time.monotonic",
        confidence=0.98,
    ),
    "time.time": SemanticValue(
        dimension={"time": 1},
        unit="s",
        nominal="instant",
        provenance="api-contract:time.time",
        confidence=0.98,
    ),
    "datetime.now": SemanticValue(
        nominal="instant",
        timezone="naive",
        provenance="api-contract:datetime.now",
        confidence=0.98,
    ),
    "datetime.utcnow": SemanticValue(
        nominal="instant",
        timezone="naive",
        provenance="api-contract:datetime.utcnow",
        confidence=0.98,
    ),
}


# trace:v1 id=impl.src-bughunt-semantic-infer.evidence-for-name work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def evidence_for_name(name: str) -> SemanticValue | None:
    """Name-suffix and stem evidence (rank: name). None when silent."""
    lowered = name.lower()
    for suffix, dimension, unit in _NAME_SUFFIXES:
        if lowered.endswith(suffix):
            value = SemanticValue(
                dimension=dict(dimension), unit=unit, provenance=f"name:{name}"
            )
            return value.with_evidence("name", f"name:{name}")
    for hint in _INSTANT_HINTS:
        if lowered.endswith(hint):
            return SemanticValue(
                nominal="instant", provenance=f"name:{name}", confidence=0.0
            ).with_evidence("name", f"name:{name}")
    for hint in _DURATION_HINTS:
        if lowered.endswith(hint):
            return SemanticValue(
                nominal="duration", provenance=f"name:{name}", confidence=0.0
            ).with_evidence("name", f"name:{name}")
    if lowered.endswith("_id"):
        stem = lowered[: -len("_id")].split("_")[-1]
        if stem and stem != "id":
            return SemanticValue(
                nominal=stem, provenance=f"name:{name}", confidence=0.0
            ).with_evidence("name", f"name:{name}")
    for suffix, frame in _FRAME_SUFFIXES:
        if lowered.endswith(suffix):
            return SemanticValue(
                frame=frame, provenance=f"name:{name}", confidence=0.0
            ).with_evidence("name", f"name:{name}")
    for hint in _FRACTION_HINTS:
        if lowered.endswith(hint):
            return SemanticValue(
                unit="fraction", provenance=f"name:{name}", confidence=0.0
            ).with_evidence("name", f"name:{name}")
    return None


# trace:v1 id=impl.src-bughunt-semantic-infer.evidence-for-annotation work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def evidence_for_annotation(annotation: str) -> SemanticValue | None:
    """Annotation evidence (rank: annotation). None when silent."""
    text = annotation.strip().split("[")[0].split(".")[-1]
    mapping: dict[str, SemanticValue] = {
        "timedelta": SemanticValue(
            dimension={"time": 1}, nominal="duration", confidence=0.0
        ),
        "datetime": SemanticValue(nominal="instant", confidence=0.0),
        "date": SemanticValue(nominal="instant", confidence=0.0),
        "bytes": SemanticValue(encoding="bytes", confidence=0.0),
        "str": SemanticValue(encoding="utf8", confidence=0.0),
    }
    hit = mapping.get(text)
    if hit is None:
        hit = _jaxtyping_shape(annotation.strip())
    if hit is None:
        return None
    return hit.with_evidence("annotation", f"annotation:{annotation}")


# trace:v1 id=impl.src-bughunt-semantic-infer.-jaxtyping-shape work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _jaxtyping_shape(annotation: str) -> SemanticValue | None:
    """`Float[Tensor, "batch channels"]` → symbolic shape (rank: annotation)."""
    text = annotation.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        text = text[1:-1]
    match = re.match(r'^\s*(\w+)\s*\[\s*\w+\s*,\s*"([^"]+)"\s*\]\s*$', text)
    if match is None:
        return None
    kind, dims = match.group(1), match.group(2)
    if kind not in {"Float", "Int", "Bool", "Complex", "Array"}:
        return None
    shape = tuple(dim for dim in dims.split() if dim)
    if not shape:
        return None
    return SemanticValue(shape=shape, confidence=0.0)
