# Seam and Contract Correctness

The highest-leverage correctness rule is: **do not erase a contract at a boundary if the program already knows it.**

Typical blind seams are JSON (`Any`), database rows/records, queues, subprocess protocols, files, sockets, RPC payloads, `**kwargs`, and untyped third-party APIs. Multiple static type checkers can all become blind at the same boundary.

## Detection layer

BugHunt's BHSEAM family checks key-set drift, kwargs forwarding, producer/consumer shape mismatch, schema/model drift, unvalidated HTTP JSON, missing recorded-payload corpora, and Pact mismatches. API/protobuf/model migration tools add history-aware contract checks.

## Prevention layer

Prefer a single source of truth that generates or validates both sides of the seam:

- typed configuration instead of stringly dictionaries;
- Pydantic strict models / `validate_call` or equivalent at external-data entry points;
- generated OpenAPI/protobuf clients and models;
- schema-derived fixtures;
- explicit response validation as well as request validation;
- migration/schema checks in CI;
- recorded real payloads (for example VCR.py cassettes) replayed against current parsers.

A drift detector is a backstop. A bug class made unrepresentable by a shared contract is stronger.

## Evidence-loss rules

BHEVID rules flag suspicious patterns that destroy knowledge and reconstruct it later, such as a known type widened to `Any`/`object` and then cast back. These are inspired by the same evidence-preservation principle as anti-slop, translated into Python semantics rather than mechanically porting TypeScript syntax.
