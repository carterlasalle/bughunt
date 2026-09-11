<!-- trace:v1 id=DOC-CONTEXT type=document work=WORK-BUG-4ABH9VEY satisfies=REQ-BUG-KZG483AX -->
<!-- trace:exempt reason=repo-scaffolding-no-product-behavior -->
# Context

Domain vocabulary for BugHunt. Use these terms exactly.

| Term | Meaning |
| ---- | ------- |
| defense | One analyzer stage BugHunt runs (e.g. `ruff`, `mypy`, `semgrep`). |
| profile | A named defense set: `fast`, `pr`, `deep`, `all`/`full`, `skipmutmut`. |
| engine | A technology-specific analyzer layer activated only when repository evidence exists (see `TECHNOLOGY_ENGINES.md`). |
| finding | One normalized analyzer hit with severity, location, and rule id. |
| signal | Findings grouped by analyzer/rule for frequency triage. |
| blind spot | An applicable defense or engine that could not run; never reported as clean. |
| campaign | An auto-discovered or hand-written semantic check (differential, round-trip, metamorphic, fault-injection). |
| repair queue | The deterministic `queue.json` + `agent/` bundle another coding agent works through. |
| policy rule | A BugHunt-native AST rule shipped in `src/bughunt/policy_scan.py` (see `DEFAULT_RULES.md`). |
| seam | A contract boundary between components checked for drift (see `SEAM_CORRECTNESS.md`). |
