<!-- trace:exempt reason=design-record-no-product-behavior -->
# ADR-009: Data-invariant layer over SemanticValue

<!-- trace:exempt reason=design-record-no-product-behavior -->
## Context

ADR-008 built the semantic engine for unit/nominal/timezone/dtype/shape
contradictions over the SCC call skeleton. A SunStack PR review (CodeRabbit
+ Codex findings, analyzed 2026-09-23) showed the next gap lives one layer
up: **semantic invariants over data, intervals, artifacts, and config
provenance**. Nearly every finding in that review is deterministic — no LLM
needed — but no existing ring catches it: not Ruff-all, type checkers,
Semgrep, CodeQL, seam analysis, or the current semantic facets.

The four highest-value families, in order: `BHMISS001` missingness
destruction (unknown measurement → fabricated zero → quantitative sink),
`BHDF001` stale derived DataFrame columns, `BHINT001/2` interval semantics
(half-open selection into adjacent-sample integrators; trailing value used
as forward interval), and `BHART002` artifact freshness contracts that omit
build-time config dependencies. These generalize far beyond the originating
repo (derived financial metrics, ML features, caches, model files).

<!-- trace:exempt reason=design-record-no-product-behavior -->
## Decision

- Extend `SemanticValue` with four facets per the analysis: `missingness`
  (`unknown | measured | imputed | measured_zero`), `time_basis`
  (`utc | local_wall | naive_unknown`), `interval_alignment`
  (`point | trailing | leading | centered`), `dependencies` (symbolic set).
  Conservative join in `combine()`: keep only on agreement, like every
  existing facet.
- One new native defense module `src/bughunt/data_scan.py` (pure AST,
  intraprocedural + tiny column-level SSA), wired as one `add()` per
  defense following the ADR-008 pattern. NOT Semgrep: the OSS engine is
  intraprocedural for taint and cannot do cross-function DataFrame
  relationships.
- Cheap local shapes go to the existing generators: ast-grep rules for
  `splitlines()[0]`, `fillna(0)` hot pattern, runtime `assert`,
  repo-relative package resources, BEGIN-without-END; Semgrep rules for
  boolean-env denylist, duplicated version constants, hardcoded success
  claims. One external addition only: `check-wheel-contents` is out of
  scope (new dependency); the static resource rule + wheel smoke cover it.
- `BHPKG002` = installed-artifact runtime smoke (build wheel, isolated
  venv install, import + `--help`/`doctor` probes from an empty cwd) plus
  the static repo-layout resource rule. `BHINV001` = normalized
  string/enum predicate equivalence over inferred domains (tiny
  set-equivalence, no SAT solver). `BHMETA002` = paired quality-metadata
  taint inside seam_scan (suffix family `_complete/_coverage/_valid/
  _stale/_version/_confidence/_source`).
- Every shipped rule gets positive + negative + adversarial fixtures and
  the BugCorpus detector lifecycle (SPEC-BUG-COMPLY01), same as ADR-008.

<!-- trace:exempt reason=design-record-no-product-behavior -->
## Alternatives

Per-family isolated lint rules without the facet model (rejected: the
fillna→sink and local-wall→utc bugs cross call boundaries; facets on the
shared `SemanticValue` struct carry evidence interprocedurally for free).
Full pandas symbolic execution (rejected: uncalibrated; the column-SSA +
name/shape evidence approach stays silent below confidence instead of
guessing). Adding more off-the-shelf scanners (rejected: the review itself
concludes BugHunt already has enough scanners; the missing layer is its
own invariants, not more tools). `check-wheel-contents` as the packaging
fix alone (rejected: it compares trees, it cannot know code secretly
expects `../../../data/...` — the static rule + smoke test cover both).

<!-- trace:exempt reason=design-record-no-product-behavior -->
## Consequences

New rule IDs BHMISS001, BHDF001, BHINT001/2, BHART001/2, BHMETA001/2,
BHTIME002, BHSEQ001, BHCTRL002, BHCFG006/7/8, BHINV001, BHCONST001,
BHFMT001, BHEVID004, BHPKG002. Dogfood rule from ADR-008 still holds:
zero new findings on this tree without a planted-bug proof first.
`protocol` precedent applies: new pure-AST defenses run over first-party
sources with one `add()` each and `findings_exit_codes={1}`.
