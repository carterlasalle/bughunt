<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
# Rule-source audit for BugHunt defaults

BugHunt optimizes for **correctness bugs first**. Security rules are useful, but security-only packs should not define the core default.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Semgrep

Best upstream source for Python bug patterns: `semgrep/semgrep-rules/python/lang/correctness`. Particularly valuable concepts include cached generators, unconsumed executor results, mutation during iteration, file-handle lifetime mistakes, sync sleep in async code, and temporary-file flush/order mistakes. BugHunt ships independently-authored equivalents for the highest-signal subset rather than vendoring Semgrep's specially licensed rule files.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## CodeQL

Keep GitHub's Python `security-and-quality` suite. Despite the name, it contains a very large reliability/correctness set: wrong call arguments, call-to-non-callable, equality/hash mismatches, file-not-closed, incorrect iterator protocols, loop-variable capture, uninitialized locals, wrong special-method signatures, mixed returns, unreachable code/handlers, regex/format-string mistakes, and many more. GitHub Security Lab Community Packs are excellent audit material but skew security, so they are not core BugHunt defaults.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## ast-grep

`coderabbitai/ast-grep-essentials` is a well-constructed multi-language AST rule pack, but its Python rules are security-only. Use it as a pattern-authoring reference and optional security source. Core BugHunt ast-grep should remain an independently tested correctness pack.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## OpenGrep

Prefer running BugHunt's Semgrep-compatible correctness YAML under OpenGrep as an optional independent engine rather than maintaining a second rule corpus. `qodana/opengrep-sast-rules` and `AikidoSec/opengrep-rules` are useful security/supply-chain sources, not strong core correctness defaults. Avoid the archived legacy `opengrep/opengrep-rules` pack.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## anti-slop concepts worth porting to Python

High-value future native/static detectors: precise-value -> broad `Any/object` -> `typing.cast` back to narrow; chained casts; unsafe broad dictionary contracts; reducer accumulator copying; risky casts requiring nearby `SAFETY:` justification; and implementation-coupled module patching in tests. Do not mechanically port rules whose language semantics differ (`filter().map()` is lazy in Python, `isinstance` is idiomatic, and blanket `getattr` bans would be noisy).

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Additional correctness rule-mining sources for 0.6+

The next native-rule expansion should mine SpotBugs, Google Error Prone, SonarSource Python inspections, JetBrains Python inspections, Beizer's bug taxonomy, IBM ODC, and correctness-oriented CWE concepts. The promotion pipeline is always semantic: identify a real failure class, implement the narrow syntactic cases in ast-grep/Semgrep, move cross-function/dataflow cases to CodeQL/BugHunt native analysis, and require positive/negative/adversarial fixtures.

Trail of Bits Semgrep material is valuable audit research, but BugHunt should cherry-pick correctness-relevant concepts rather than making a security pack the correctness baseline. `p/default` plus BugHunt-owned correctness YAML remains the deterministic Semgrep floor.

`wemake-python-styleguide` is available as an explicit advisory helper because it contains checks Ruff does not implement, but its opinionated/style-heavy rules do not count toward correctness health. Framework Pylint plugins are capability-selected: Django and Odoo plugins are loaded when the framework is actually detected and the plugin is available.
