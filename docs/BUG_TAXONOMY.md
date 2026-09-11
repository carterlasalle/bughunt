<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
# BugHunt Bug Taxonomy and Rule-Mining Roadmap

BugHunt is correctness-first. A new detector should answer a recognizable defect class, not merely add another source of style warnings.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Runtime report taxonomy

BugHunt normalizes findings into an ODC-like classification so coverage can be measured by defect kind rather than raw tool count:

- assignment / initialization
- checking / validation
- algorithm / calculation
- timing / serialization / concurrency
- interface / contract / seam
- function / behavior
- build / package / merge
- documentation / executable specification

The report preserves the original tool/rule identifier and evidence; taxonomy is an additional lens, never a destructive replacement.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Taxonomies to mine for new detectors

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### Boris Beizer — Software Testing Techniques, Taxonomy of Bugs

Use the chapter-2 taxonomy as a broad completeness checklist: requirements/features, structural, data, implementation, integration, system, and test defects. For each leaf class ask: which BugHunt defense can detect it, prevent it, or exercise it? Uncovered leaves become V2 detector hypotheses.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### IBM Orthogonal Defect Classification (ODC)

ODC is the preferred report-level vocabulary because its defect types align well with detector coverage: assignment/initialization, checking, algorithm, timing/serialization, interface/messages, function, build/package/merge, and documentation. BugHunt should expose zero-coverage ODC classes prominently.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### SpotBugs and Google Error Prone

Their Java bug-pattern catalogs are valuable *rule-mining corpora*. Port semantics, not syntax. High-value candidates include ignored results, broken equality/hash contracts, incorrect collection mutation, impossible conditions, lifecycle/resource errors, exceptional-control-flow mistakes, time/unit mistakes, and API misuse. Start with ast-grep for local syntax, Semgrep for relational patterns, and CodeQL for cross-function/dataflow cases.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### SonarSource Python and JetBrains inspections

Mine correctness inspections that are absent from Ruff/Pylint/type checkers, especially indirect call/signature problems, override mismatches, shadowing/state hazards, data-flow errors, resource/lifecycle misuse, and framework-specific contract drift. Avoid cloning style rules that merely duplicate formatting policy.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### CWE correctness concepts

CWE is not only a security taxonomy. Useful correctness-oriented mining seeds include incorrect calculation, incorrect type conversion, excessive iteration, and improper handling/checking of unusual or exceptional conditions. Treat these as defect families; do not import a security severity merely because the taxonomy source is CWE.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
### IEEE 1044

Use anomaly-classification concepts as optional metadata for defect status/origin/severity. Do not force a standards label onto a finding when evidence is insufficient.

<!-- trace:exempt reason=repo-docs-move-no-behavior-change -->
## Promotion standard for a new shipped rule

A default BugHunt rule should have:

1. a named defect class and concrete failure mode;
2. positive, negative, and adversarial fixtures;
3. known overlap with existing analyzers documented;
4. a measured false-positive story;
5. stable machine output and a repair explanation;
6. promotion to blocking only when evidence justifies it.

The goal is not the largest rule count. The goal is independent coverage of real defect classes.
