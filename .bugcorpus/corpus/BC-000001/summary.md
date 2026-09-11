<!-- trace:exempt reason=bugcorpus-case-record-no-product-behavior -->
# BC-000001 Unvalidated module name interpolated into python -c subprocess source

Symptom, root cause, and violated invariant are recorded in `bug.yaml`.

<!-- trace:exempt reason=bugcorpus-case-record-no-product-behavior -->
## Detector status (2026-09-11)

Rung 0: pytest regression tests are the detector
(`test_importtime_rejects_non_identifier_module_names`,
`test_python_importable_rejects_non_identifiers`).
A syntax-only rule cannot separate guarded from unguarded sinks; the
adequate engine is a BugHunt-native AST check (same-function
`isidentifier` guard detection on interpolated `-c`/`exec`/`eval`
payloads), queued as follow-up product work. `bugcorpus verify`: OK.
