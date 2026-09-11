<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
# Complexity budgets

BugHunt treats complexity as a defect-risk and testability signal. It deliberately uses several independent metrics because no single complexity score captures every way code becomes hard to reason about.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Default budgets

```toml
[complexity]
cyclomatic_warn = 10
cyclomatic_error = 20
cognitive_max = 10
function_loc_warn = 80
function_loc_error = 150
file_loc_warn = 500
file_loc_error = 1200
abc_warn = 30
abc_error = 45
js_file_kb_warn = 500
css_file_kb_warn = 250
wasm_file_kb_warn = 2000
bundle_kb_warn = 1500
```

These are deliberately aggressive defaults for a repository whose goal is maximum defect discovery. Tune them when the domain provides better evidence, but do not raise a budget merely to make a dashboard green.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Independent checks

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### Cyclomatic / McCabe

BugHunt computes its own function-level branch-path estimate (`BHCX001`) and also enables Ruff `C901` with max complexity 10. Lizard provides a second independent CCN implementation and cross-language coverage.

The goal is to identify functions whose number of independent execution paths makes exhaustive reasoning/testing difficult.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### Cognitive complexity

Complexipy runs with a maximum allowed score of 10. Cognitive complexity is intentionally separate from McCabe: it tries to reflect how difficult nested/control-flow structure is for a person to understand.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### LOC

BugHunt checks both function and file LOC, and Lizard contributes NLOC/function limits.

**Do not split a coherent file into nonsense fragments merely to satisfy LOC.** Refactor at real cohesion, ownership, state, API, or subsystem boundaries.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### ABC

BugHunt computes an ABC magnitude from assignments (A), branches/calls (B), and conditions (C):

```text
sqrt(A² + B² + C²)
```

The tuple is included in every finding so the reason for a high score is inspectable rather than opaque.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### Maintainability

Radon's Maintainability Index is included as an additional independent signal. BugHunt reports low MI rather than using it as the sole gate.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### Frontend / built assets

When applicable build roots exist (`dist`, `build`, `.next/static`, `public/assets`, `static`), BugHunt checks individual JavaScript/CSS/WASM files and aggregate built-asset size.

Source complexity and shipped asset complexity are separate risks; both matter in mixed Python/web repositories.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Anti-gaming rule

A complexity finding means: reduce the amount of state/branching/knowledge that must be held in one reasoning unit, or increase the verification around it.

It does **not** mean:

- create one-line forwarding functions solely to lower scores;
- move conditionals into opaque helpers with no coherent responsibility;
- split a cohesive state machine among arbitrary files;
- hide dependencies behind dynamic lookup;
- weaken tests because a function is difficult to exercise.

BugHunt cannot perfectly prove metric gaming statically. V2 should compare call-graph/state complexity before and after refactors so apparent metric improvements that merely relocate complexity can be detected.
