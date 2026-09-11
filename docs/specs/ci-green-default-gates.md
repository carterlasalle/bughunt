# CI green on default gates

<!-- trace:v1 id=SPEC-BUG-CIGREEN01 type=spec work=WORK-BUG-JZ02ASSD -->

## Requirements

### Default gates pass

<!-- trace:v1 id=REQ-BUG-SY8DHSTC type=requirement work=WORK-BUG-JZ02ASSD derived_from=SPEC-BUG-CIGREEN01 -->

`ruff check`, `ruff format --check`, and `mypy` pass on `src` and `tests`
with the repository's default configuration. Pre-existing violations are
fixed at the source (narrowed exception types, precise container types,
bound executables, partial-bound parsers); intentional broad catches carry
narrowly-justified `noqa` suppressions per the repository's own policy.
The per-boundary markers added alongside this change record the sweep
itself; behavior preservation is evidenced by the unchanged test suite.
