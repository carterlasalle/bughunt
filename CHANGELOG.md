<!-- trace:v1 id=DOC-CHANGELOG type=document work=WORK-BUG-4ABH9VEY satisfies=REQ-BUG-KZG483AX -->
# Changelog

Follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.0] - 2026-09-14

Graph-evidence release: SCC/System IR and TraceLayer wired as real rings
(index/export cache, drift/invariant findings, verification/diagnostic
evidence); Transitive Verification (BHVERIFY001) and hollow-surface
(BHIMPL001) detectors over the System IR graph; protocol-correctness ring
(BHPRT001-004: assert-carried exceptions, async magic, yield-in-magic,
unguarded next) as DeepSource-PTC concept ports with provenance; recursive
`**kwargs` drift (BHSEAM002) extended one file-boundary outward via SCC
call edges with stale-cache and ambiguity guards; test suite at 87.5% line
and 80.0% branch coverage with two dead branches removed.

## [0.7.0] - 2026-09-13

Repository-governance release: accepted-debt ledger (`debt.toml`) with
snapshot/review so known debt stays visible without inflating health;
target-environment interpreter handling and isolated analyzer runtimes;
subprocess and import safety work including injection BugCase BC-000001;
repository-compliance spec with actionable-clean `skipmutmut`; naming-layer
unit rules BHUNIT001/002/003; calibrated strict-analyzer overlays with ADRs;
test suite at 85% line coverage; packaging provenance (`py.typed`, sdist
excludes, MANIFEST.in); fault-injection regression tests proving graceful
degradation; seam comparators repaired (chained-call JSON, dotted
serialization boundaries, validator inputs, soft-vs-hard reads).

## [0.6.0] - 2026-09-10

Runtime, seam, environment, and history correctness: branch coverage,
runtime Typeguard verification, randomized test order, timezone/locale/
interpreter matrices, concurrency checks, HypoFuzz, packaging verification,
public-API/version differentials, seam drift detection, and a
coverage-weighted risk map. Full notes in `docs/RELEASE_0.6.0.md`.
