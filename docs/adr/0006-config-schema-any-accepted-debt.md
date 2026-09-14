<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
# ADR-006: Config-schema Any is accepted debt with a receipt

<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
## Context

Under the PARANOID mypy config (`disallow_any_expr`), ~1930 expression-Any
findings (1188 "type contains Any", 742 "has type Any", per the
20260913-193107 report) propagate from two honest dynamic origins:
`Config.raw: dict[str, Any]` (`cli.py`) and `tomllib.loads`. The
propagations are diffuse (~4 per line, no dense cluster) across config
plumbing: every `.get()` chain reintroduces `Any` at the next call site,
so per-site fixes do not compound.

<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
## Decision

Accept as debt with this receipt rather than a TypedDict rewrite:

- The origin type is *true*: parsed TOML is genuinely `dict[str, Any]`,
  and user configs extend the schema. A TypedDict would assert knowledge
  the runtime does not enforce, and `dict` invariance repoisons on the
  first imprecise field — so the rewrite buys churn, not safety.
- Sink-adjacent boundaries are closed individually and stay closed:
  `no-any-return` 4 to 0 (`_toml_project`, `Config.project`,
  `_provider_name` isinstance-narrowed with a malformed-config regression
  test; `_literal` carries the single documented `cast`).
- Backstops for unknown-to-sink flows are the taint defense, the
  S603/S607 argv audit, and the BC-000001 regression tests — not the
  expression count.

<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
## Alternatives

Full TypedDict schema with migration code (rejected: several hundred
lines plus permanent sync tax, failure mode is a lie); per-section casts
(rejected: silences without verifying); narrowed accessors with partial
migration (rejected: two config-read systems indefinitely).

<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
## Consequences

The ~1900 expression-Any findings remain visible as known strict debt.
Revisit trigger: any *sink-adjacent* Any finding (unknown flowing into
subprocess/exec/import) is fixed individually. Effort that would chase
the count goes to coverage and complexity instead.
