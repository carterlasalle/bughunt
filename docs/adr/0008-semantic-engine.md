<!-- trace:exempt reason=design-record-no-product-behavior -->
# ADR-008: Semantic correctness engine on the SCC graph skeleton

<!-- trace:exempt reason=design-record-no-product-behavior -->
## Context

Type-correct but semantically wrong code (`timeout_ms` into
`time.sleep`, `uint64 + int64`, naive vs aware datetimes) passes
every existing ring: Ruff, mypy strict, basedpyright max-recall, ty,
Pyrefly, CodeQL quality. The gap is values that share a
representation but belong to incompatible semantic domains. Prior
art was deferred in `docs/specs/unit-tracking-future.md` for lack of
an interprocedural substrate; the SCC export (1395 resolved call
edges measured on this tree) now provides it. Full spec:
`docs/specs/semantic-engine.md` (SPEC-BUG-SEM01).

<!-- trace:exempt reason=design-record-no-product-behavior -->
## Decision

- Build one abstract-interpretation engine (`src/bughunt/semantic/`,
  `src/bughunt/graph/`) over a single `SemanticValue` struct with
  per-domain transfer functions — not 200 isolated AST rules.
- SCC remains the canonical who-calls-whom source; BugHunt extracts
  only intraprocedural facts (args, returns, assignments) and joins
  them to SCC edges. No second call graph.
- Contradictions fire only at high confidence (≥0.70) or medium
  (≥0.45) with two independent evidence sources; weaker signals stay
  silent. CrossHair confirms contradicted constraints on pure
  functions; it never invents semantics.
- New modules only; `cli.py` gets one `add()` per defense. Runtime
  observation comes from our own coverage executed-line sets —
  `scc runtime` has zero ingested observations and is not consumed.

<!-- trace:exempt reason=design-record-no-product-behavior -->
## Alternatives

Per-domain isolated linters (rejected: the ms→s bug crosses function
boundaries; isolated rules cannot see it). Full SMT-first verifier
(rejected: uncalibrated solver-backed warnings become a
false-positive machine; solver confirms, engine decides).
Reimplementing call resolution in Python (rejected: SCC already
resolves 1395 edges with confidence; duplication drifts).

<!-- trace:exempt reason=design-record-no-product-behavior -->
## Consequences

New rule IDs BHUNIT004, BHSEM001–010, BHCONC001, BHOBS001 plus the
PTC concept ports ship with positive/negative/adversarial fixtures
and BugCorpus lifecycle. Dogfood must stay false-positive-free:
a finding on this tree is a fixed bug or a calibration fix.
