<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
# BugHunt hotfix 0.5.1

This hotfix makes default rule selection correctness-first and fixes maximal-scan ergonomics.

- `bughunt skipmutmut` runs the full `all` profile except mutation testing.
- `bughunt all --skip-mutmut` and `bughunt all --skip mutmut` are equivalent.
- `bughunt run all` is accepted in addition to `bughunt run --profile all`.
- Explicit skips remain visible as `SKIPPED`; they never masquerade as a pass.
- Maximal auto-install does not install explicitly skipped engines.
- Existing user-owned mutmut config is now coverage-checked instead of blindly reported `EXISTING`.
- BugHunt-managed mutmut config is refreshed when inferred source/test roots change.
- Semgrep defaults are correctness-first: `p/default` + 7 bundled high-signal reliability rules. Security-audit/secrets packs are opt-in with `[semgrep] include_security = true`.
