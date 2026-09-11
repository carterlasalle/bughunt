# BugHunt Semantic Auto-Discovery

BugHunt v0.4.0 treats auto-configuration as evidence-based program analysis, not filename guessing.

## Evidence tiers

- **High:** enough static/type/test evidence to create a deterministic runnable campaign automatically.
- **Medium:** useful candidate, but not automatically promoted when doing so could create false bug reports.
- **Low:** not emitted as an executable target.

## Automatically runnable target classes

1. Atheris parser/decoder/validator boundaries with one bytes/string-like input.
2. FastAPI ASGI apps and Flask WSGI apps with an explicit OpenAPI endpoint.
3. Local OpenAPI schemas whose server URL is unambiguously loopback-only.
4. Reference-vs-optimized differential pairs with matching typed signatures and no detected I/O.
5. Exact typed inverse/round-trip pairs (`encode/decode`, `serialize/deserialize`, etc.).
6. High-confidence idempotent/canonical transforms.
7. Repository-specific external-failure coverage campaigns.
8. Direct Pysa source/sink wrapper models.

## Generated assets

```text
.bughunt/generated/
├── targets.json
├── pysa-models.json
├── atheris/
├── schemathesis/
└── campaigns/
    ├── test_differential_*.py
    ├── test_roundtrip_*.py
    ├── test_idempotence_*.py
    ├── fault_boundaries.json
    └── check_fault_boundaries.py
```

High-confidence `custom-*` targets are mirrored into a managed `[[custom.checks]]` block in `bughunt.toml`. Re-running `configure --auto` replaces only that bounded block.

## Accuracy constraints

BugHunt refuses to auto-run remote API schemas, avoids differential/property generation for functions with detected external side effects, requires compatible type shapes for generated Hypothesis strategies, and does not invent application-specific recovery behavior for fault injection.

## v0.5 repository contracts

Auto-configuration also maintains correctness policy infrastructure:

- `.env.example` managed contract from statically detected environment variables;
- high-confidence export/import, backup/restore, encode/decode, serialize/deserialize, compress/decompress, and pack/unpack round-trip properties when annotations prove an `A -> B -> A` shape;
- fallback policy findings when a user-format-looking operation has no inverse or a known pair lacks round-trip coverage;
- repository fault-boundary coverage inventory;
- Pysa direct source/sink wrapper candidates;
- default architecture and complexity configuration.

Generated executable properties remain confidence-gated. A naming resemblance alone never creates a correctness assertion.
