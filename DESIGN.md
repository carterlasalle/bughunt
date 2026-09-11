# Design

BugHunt's design lives in focused documents; this file maps them.

| Concern | Document |
| ------- | -------- |
| System spec and defense pipeline | `V2_SPEC.md` |
| Correctness model (`STATIC → SEAMS → RUNTIME → …`) | `README.md`, `SEAM_CORRECTNESS.md` |
| Bug taxonomy and detector roadmap | `BUG_TAXONOMY.md` |
| Native policy rules | `DEFAULT_RULES.md`, `RULE_SOURCES.md` |
| Strict analyzer overlays | `STRICT_CONFIGS.md` |
| Technology engines | `TECHNOLOGY_ENGINES.md` |
| Auto-discovery and semantic campaigns | `AUTO_DISCOVERY.md` |
| Complexity budgets | `COMPLEXITY.md` |
| Deterministic simulation | `DETERMINISTIC_SIMULATION.md` |
| Architecture decisions | `docs/adr/` |

New durable decisions go in `docs/adr/`. Do not duplicate content here;
link it.
