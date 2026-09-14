<!-- trace:v1 id=DOC-CHANGELOG type=document work=WORK-BUG-4ABH9VEY satisfies=REQ-BUG-KZG483AX -->
# Changelog

Follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
