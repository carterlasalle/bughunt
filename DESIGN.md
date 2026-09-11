<!-- trace:v1 id=DOC-DESIGN type=document work=WORK-BUG-4ABH9VEY satisfies=REQ-BUG-KZG483AX -->
# Design

BugHunt's design lives in focused documents; this file maps them.

| Concern | Document |
| ------- | -------- |
| System spec and defense pipeline | `docs/V2_SPEC.md` |
| Correctness model (`STATIC → SEAMS → RUNTIME → …`) | `README.md`, `docs/SEAM_CORRECTNESS.md` |
| Bug taxonomy and detector roadmap | `docs/BUG_TAXONOMY.md` |
| Native policy rules | `docs/DEFAULT_RULES.md`, `docs/RULE_SOURCES.md` |
| Strict analyzer overlays | `docs/STRICT_CONFIGS.md` |
| Technology engines | `docs/TECHNOLOGY_ENGINES.md` |
| Auto-discovery and semantic campaigns | `docs/AUTO_DISCOVERY.md` |
| Complexity budgets | `docs/COMPLEXITY.md` |
| Deterministic simulation | `docs/DETERMINISTIC_SIMULATION.md` |
| Architecture decisions | `docs/adr/` |

New durable decisions go in `docs/adr/`. Do not duplicate content here;
link it.
