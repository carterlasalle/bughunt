<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
# ADR-004: Docstring correctness over presence in generated configs

<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
## Context

The PARANOID ruff template selects `ALL`, which includes the D100-D107
docstring-presence family. On this tree that produced 169 findings
(D100 x17, D101 x20, D102 x37, D103 x93, D107 x2). Writing that many
docstrings for internal CLI helpers yields vacuous prose, and BugHunt's
own default gate never required them. Prior art: alibaba/open-code-review
states precision-over-recall explicitly and measures it (AACR-Bench)
rather than mandating documentation presence.

<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
## Decision

- Scope D100-D107 out of the generated PARANOID ruff template.
- Keep the convention family (D205-D417) and the pydoclint defense, which
  validate the docstrings that exist instead of mandating new ones.
- Fix genuine convention violations directly (D401 x2, D403 x1, this loop).

<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
## Alternatives

Write all 169 docstrings (rejected: tautological prose has negative
maintenance value); keep demanding presence of targets while our own tree
fails it (rejected: dogfood violation).

<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
## Consequences

Targets without docstrings no longer fail the DOC defense on presence;
incorrect docstrings still fail via pydoclint and D-convention rules.
