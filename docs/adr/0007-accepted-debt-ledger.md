<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
# ADR-007: Accepted-debt ledger (debt.toml)

<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
## Context

Known debt (e.g. the ~1900 config-schema Any propagations in ADR-006)
clogs fix queues and top signals, training reviewers to ignore the very
sections where a new real finding would appear. Deleting or silently
suppressing the debt would hide that future finding instead.

<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
## Decision

- `debt.toml` (tracked, user-owned) records accepted debt as
  per-signal-per-file entries: signal key, paths, recorded count, reason.
- Matching is exact signal key plus path. Accepted findings leave the fix
  queue, top signals, hotspots, risk map, and correlations, but stay
  visible in a dedicated report section with recorded-vs-live deltas.
- Defense statuses and health are untouched: debt separates noise, never
  inflates health.
- `bughunt debt snapshot` records counts from the latest report (exact
  signals required, reason required); `bughunt debt review` diffs the
  ledger and exits 1 on growth, so new findings surface as deltas.
- A malformed ledger fails open (marks nothing) with a loud warning —
  the safe direction is visible findings, never silent ones.
- `debt.toml` is trace-excluded like `uv.lock`: generated data, not behavior.

<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
## Alternatives

Per-finding fingerprint ledger (rejected: 1900 line-drift-proof entries
are heavier than ~140 signal groups with no more precision); baseline
files that delete matched findings from reports (rejected: invisible debt
cannot show growth deltas); scoping the rules instead (rejected: the
rules stay on for targets — the debt is ours, not the product's).

<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
## Consequences

Debt growth is a CI-usable signal (`debt review` exit code). Stale
entries (live below recorded) are visible in review and re-snapshotted;
entries at zero are removed.
