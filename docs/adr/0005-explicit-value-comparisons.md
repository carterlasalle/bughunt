<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
# ADR-005: Explicit value comparisons stay; emptiness simplifies

<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
## Context

Three checkers pull in different directions. Pylint's
`use-implicit-booleaness` family wants `rc == 0` and `x == []` rewritten as
truthiness. Pyrefly's `implicit-bool` (preset `all`) forbids truthiness
tests outright — 863 hits on idiomatic `if x:` — demanding explicit
`bool()` conversions everywhere. Both cannot be right, and neither is
uniformly right: `rc == 0` compares a domain value (exit codes, counts),
while `x == []` tests emptiness.

<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
## Decision

- Value comparisons stay explicit: `== 0` on status codes and counts,
  `is None` (never `== None`, a latent `__eq__`-override bug vector).
- Emptiness simplifies: `== []` / `== ''` / `== {}` become truthiness
  (the pylint non-zero variant stays on).
- Scope pylint `use-implicit-booleaness-not-comparison-to-zero` in the
  generated template: every surviving `== 0` is a status code.
- Set `implicit-bool = false` in the generated pyrefly template: the rule
  contradicts the emptiness direction and would mandate 863 explicit
  conversions. The Any trail (`unknown-argument-type`, `explicit-any`)
  stays on.

<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
## Alternatives

Rewrite all 863 conditions explicitly (rejected: destroys readability for
zero bug value); rewrite status codes as truthiness (rejected: `if
proc.returncode:` states the failure contract worse than `!= 0`).

<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
## Consequences

Checker conflict resolved by product judgment, recorded here so the next
`implicit-bool` or `to-zero` finding cites this ADR instead of reopening it.
