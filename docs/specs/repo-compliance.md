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
