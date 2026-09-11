# Repository BugHunt compliance

<!-- trace:v1 id=SPEC-BUG-COMPLY01 type=spec work=WORK-BUG-06107X2Q -->

## Requirements

### Skipmutmut scan is actionable-clean

<!-- trace:v1 id=REQ-BUG-5XJWASR4 type=requirement work=WORK-BUG-06107X2Q derived_from=SPEC-BUG-COMPLY01 -->

`bughunt skipmutmut` reports zero actionable findings on this repository.
Third-party and harness noise is excluded at the generator scope
(`_JS_TOOL_IGNORES`), TraceLayer marker lines are exempt centrally
(`canonicalize_findings`), empty-scope tools report SKIPPED, and every
remaining finding is fixed at its root cause with no suppressions,
baselines, or weakened defenses.

### TypeScript tool applicability

<!-- trace:v1 id=REQ-BUG-TSCSCOPE type=requirement work=WORK-BUG-06107X2Q derived_from=SPEC-BUG-COMPLY01 -->

`tsc` runs only when the repository has a root `tsconfig.json` (SKIPPED
with a reason otherwise: without a project, `tsc --noEmit` prints help
text that is not a finding). `knip` runs with a generated config carrying
`ignoreFiles` from the shared JS ignore list so harness entry points
dynamically loaded by their host are not reported unused.

### Pysa provider integrity

<!-- trace:v1 id=REQ-BUG-PYSAPROV type=requirement work=WORK-BUG-06107X2Q derived_from=SPEC-BUG-COMPLY01 -->

Pysa never reports ERROR for a missing type provider: the installer
verifies the `pyrefly` binary inside the isolated runtime (not just
`pyre --help`), the analyze subprocess runs with the runtime `bin`
directory on `PATH`, and a `Cannot locate a Pyrefly binary` banner maps
to SKIPPED with the repair stated.
