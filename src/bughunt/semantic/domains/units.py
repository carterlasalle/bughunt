# Copyright (c) 2026 Carter LaSalle
"""Units/time domain: dimension algebra and conversion recognition.

Transfer rules: additive ops require compatible dimensions; mul/div
compose; a Time value divided by ~1000 is a recognized ms→s
conversion, any other divisor into a seconds sink is a contradiction
carried by the resulting value for the contradiction layer.
"""

from __future__ import annotations

from ..model import SemanticValue


# trace:v1 id=impl.src-bughunt-semantic-domains-units.compatible work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def compatible(first: SemanticValue, second: SemanticValue) -> bool:
    """Same dimension claim, or either side claims nothing."""
    if not first.dimension or not second.dimension:
        return True
    return first.dimension == second.dimension


# trace:v1 id=impl.src-bughunt-semantic-domains-units.transfer-additive work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def transfer_additive(first: SemanticValue, second: SemanticValue) -> SemanticValue:
    """`+`/`-`: keep the dimension only when both sides agree."""
    out = SemanticValue(
        dimension=dict(first.dimension) or dict(second.dimension),
        unit=first.unit if first.unit == second.unit else None,
        timezone=first.timezone if first.timezone == second.timezone else None,
        provenance=f"{first.provenance}+{second.provenance}",
        confidence=min(first.confidence, second.confidence),
    )
    if first.dimension and second.dimension and first.dimension != second.dimension:
        out.provenance = f"dimension-clash:{out.provenance}"
    if first.nominal == "instant" and second.nominal == "instant":
        out.provenance = f"instant-clash:{out.provenance}"
    if {first.timezone, second.timezone} == {"aware", "naive"}:
        out.provenance = f"tz-clash:{out.provenance}"
    return out


# trace:v1 id=impl.src-bughunt-semantic-domains-units.transfer-mul work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def transfer_mul(first: SemanticValue, second: SemanticValue) -> SemanticValue:
    """`*`: compose dimension exponents."""
    dimension = dict(first.dimension)
    for axis, power in second.dimension.items():
        dimension[axis] = dimension.get(axis, 0) + power
        if dimension[axis] == 0:
            del dimension[axis]
    return SemanticValue(
        dimension=dimension,
        provenance=f"{first.provenance}*{second.provenance}",
        confidence=min(first.confidence, second.confidence),
    )


# trace:v1 id=impl.src-bughunt-semantic-domains-units.transfer-div work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def transfer_div(numerator: SemanticValue, denominator: SemanticValue) -> SemanticValue:
    """`/` with conversion recognition.

    Time[ms] / 1000 → Time[s]; percent / 100 → fraction (both valid
    transformations). Any other divisor on a Time[ms] value keeps
    Time[ms] with a ``bad-divisor`` tag the contradiction layer reads
    when the value reaches a seconds sink.
    """
    if numerator.unit == "percent":
        factor = _literal_factor(denominator)
        if factor is not None and 99.0 <= factor <= 101.0:
            return SemanticValue(
                dimension={},
                unit="fraction",
                provenance=f"{numerator.provenance}/100",
                confidence=min(numerator.confidence, denominator.confidence or 1.0),
            )
    if numerator.dimension == {"time": 1} and numerator.unit == "ms":
        factor = _literal_factor(denominator)
        if factor is not None and 999.0 <= factor <= 1001.0:
            return SemanticValue(
                dimension={"time": 1},
                unit="s",
                provenance=f"{numerator.provenance}/1000",
                confidence=min(numerator.confidence, denominator.confidence or 1.0),
            )
        return SemanticValue(
            dimension={"time": 1},
            unit="ms",
            provenance=f"bad-divisor:{numerator.provenance}/{denominator.provenance}",
            confidence=min(numerator.confidence, 0.80),
        )
    dimension = dict(numerator.dimension)
    for axis, power in denominator.dimension.items():
        dimension[axis] = dimension.get(axis, 0) - power
        if dimension[axis] == 0:
            del dimension[axis]
    return SemanticValue(
        dimension=dimension,
        provenance=f"{numerator.provenance}/{denominator.provenance}",
        confidence=min(numerator.confidence, denominator.confidence),
    )


# trace:v1 id=impl.src-bughunt-semantic-domains-units.-literal-factor work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _literal_factor(value: SemanticValue) -> float | None:
    try:
        return float(value.provenance.split("literal:")[1])
    except (IndexError, ValueError):
        return None
