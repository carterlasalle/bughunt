# Copyright (c) 2026 Carter LaSalle
"""Dtype/shape domain: NumPy promotion, narrowing, reshape totals.

Active only when a file imports numpy (checked by callers via the
dtype evidence actually present — no numpy dtypes inferred means no
findings). Transfer rules follow NumPy promotion semantics: mixed
signed/unsigned integer widths risk precision loss, and explicit
casts to a smaller representation narrow.
"""

from __future__ import annotations

from ..model import SemanticValue


_DTYPE_WIDTH: dict[str, int] = {
    "bool": 1,
    "int8": 8,
    "uint8": 8,
    "int16": 16,
    "uint16": 16,
    "int32": 32,
    "uint32": 32,
    "float16": 16,
    "int64": 64,
    "uint64": 64,
    "float32": 32,
    "float64": 64,
    "complex64": 64,
    "complex128": 128,
}

_FLOATS = {"float16", "float32", "float64"}
_INTS = {"int8", "int16", "int32", "int64"}
_UINTS = {"uint8", "uint16", "uint32", "uint64"}


NUMPY_CONSTRUCTORS = frozenset(
    {
        "numpy.zeros",
        "numpy.ones",
        "numpy.empty",
        "numpy.full",
        "numpy.array",
        "numpy.asarray",
        "numpy.arange",
    }
)


# trace:v1 id=impl.src-bughunt-semantic-domains-dtype.normalize work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def normalize_dtype(text: str) -> str | None:
    """`np.float32` / `numpy.int8` / `float32` → canonical name or None."""
    short = text.split(".")[-1].strip("'\"")
    return short if short in _DTYPE_WIDTH else None


# trace:v1 id=impl.src-bughunt-semantic-domains-dtype.is-narrower work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def is_narrower(source: str, target: str) -> bool:
    """True when casting source→target can lose range or precision."""
    if source == target:
        return False
    if source in _FLOATS and target in _INTS | _UINTS:
        return True
    source_width = _DTYPE_WIDTH.get(source, 0)
    target_width = _DTYPE_WIDTH.get(target, 0)
    if source in _FLOATS and target in _FLOATS:
        return target_width < source_width
    if source in _INTS | _UINTS and target in _INTS | _UINTS:
        unsigned_to_signed = source in _UINTS and target in _INTS
        return target_width < source_width or (
            unsigned_to_signed and target_width <= source_width
        )
    return False


# trace:v1 id=impl.src-bughunt-semantic-domains-dtype.transfer-arith work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def transfer_arith(first: SemanticValue, second: SemanticValue) -> SemanticValue | None:
    """Promotion risks for arithmetic on two known dtypes.

    Returns a tagged value when the combination risks precision loss
    (uint64 with any signed integer promotes toward float64), else
    None so the caller keeps the plain units transfer.
    """
    left, right = first.dtype, second.dtype
    if left is None or right is None or left == right:
        return None
    pair = {left, right}
    risky = (
        ("uint64" in pair and bool(pair & (_INTS | _FLOATS)))
        or (left in _FLOATS and right in _INTS | _UINTS)
        or (right in _FLOATS and left in _INTS | _UINTS)
    )
    if not risky:
        return None
    return SemanticValue(
        dtype=None,
        provenance=(
            f"promotion-risk:{first.provenance}+{second.provenance} "
            f"({left}+{right} may lose integer precision)"
        ),
        confidence=min(first.confidence, second.confidence),
    )
