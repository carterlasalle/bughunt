# Unit tracking and dtype narrowing (deferred)

<!-- trace:v1 id=SPEC-BUG-UNITS01 type=spec work=WORK-BUG-06107X2Q -->

Status: TODO. The naming-convention layer (BHUNIT001/002/003 in
`policy_scan.py`, documented in `DEFAULT_RULES.md`) is built and dogfooded.
These two deeper layers are explicitly deferred with revival triggers.

## Requirements

### Taint-style unit tracking (deferred)

<!-- trace:v1 id=REQ-BUG-UNITS02 type=requirement work=WORK-BUG-06107X2Q derived_from=SPEC-BUG-UNITS01 -->

Treat unit annotations as taint labels through arithmetic (`ms / 1000`
becomes `s`; `s + ms` is an error) over the seam/scan infrastructure.

Revival trigger: the naming layer is adopted AND a real tree under
analysis carries unit annotations worth tracking. A dimension-type engine
with no annotated arithmetic to watch is unprovable; do not build it
until the precondition exists.

### Dtype narrowing (deferred)

<!-- trace:v1 id=REQ-BUG-UNITS03 type=requirement work=WORK-BUG-06107X2Q derived_from=SPEC-BUG-UNITS01 -->

Flag `float32` vs `float64` confusion and int/float truncation at
numpy/torch/pandas boundaries.

Revival trigger: a target ecosystem that centers those libraries. This
tree does not use them, so the defense would ship with no dogfood.
Same rule: no target, no defense.
