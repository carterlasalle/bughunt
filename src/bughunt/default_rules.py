# Copyright (c) 2026 Carter LaSalle
from __future__ import annotations

from dataclasses import dataclass


# trace:v1 id=impl.src-bughunt-default-rules.default-rule work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
@dataclass(frozen=True, slots=True)
class DefaultRule:
    code: str
    severity: str
    category: str
    summary: str
    overlap: str = ""


DEFAULT_RULES: tuple[DefaultRule, ...] = (
    DefaultRule(
        "BHCTRL001",
        "error",
        "control-flow",
        (
            "return/break/continue inside finally can suppress "
            "exceptions or override control flow"
        ),
        "Ruff B012 + ast-grep",
    ),
    DefaultRule(
        "BHCFG001",
        "warning",
        "configuration",
        "environment-driven project is missing .env.example",
    ),
    DefaultRule(
        "BHCFG002",
        "warning",
        "configuration",
        "environment variable used by code is missing from .env.example",
    ),
    DefaultRule(
        "BHCFG003",
        "error",
        "configuration/security",
        ".env.example appears to contain a real secret",
        "Semgrep secrets + Ruff security rules",
    ),
    DefaultRule(
        "BHCFG004",
        "note",
        "configuration",
        "module-level operational knob is hard-coded outside a configuration mechanism",
    ),
    DefaultRule(
        "BHCFG005",
        "note",
        "configuration",
        "operational keyword argument is hard-coded at a call site",
    ),
    DefaultRule(
        "BHPERS001",
        "warning",
        "architecture",
        "higher layer imports a persistence implementation directly",
    ),
    DefaultRule(
        "BHPERS002",
        "warning",
        "architecture",
        "higher-layer public signature exposes a persistence implementation type",
    ),
    DefaultRule(
        "BHARCH001",
        "warning",
        "architecture",
        (
            "source module imports an internal/private implementation "
            "module across a boundary"
        ),
    ),
    DefaultRule(
        "BHARCH002",
        "warning",
        "architecture",
        "source module imports a private implementation symbol across a boundary",
    ),
    DefaultRule(
        "BHTEST001",
        "warning",
        "test-quality",
        (
            "test imports a private implementation symbol instead "
            "of exercising a public contract"
        ),
    ),
    DefaultRule(
        "BHTEST002",
        "warning",
        "test-quality",
        "test asserts exact mock call sequence/internal call history",
    ),
    DefaultRule(
        "BHTEST003",
        "warning",
        "test-quality",
        "test asserts a huge literal/snapshot instead of semantic behavior",
    ),
    DefaultRule(
        "BHTEST004",
        "warning",
        "test-quality",
        "test heavily mocks collaborators and asserts orchestration detail",
    ),
    DefaultRule(
        "BHTEST005",
        "warning",
        "test-quality",
        "test compares generated/source-like output against a large exact string",
    ),
    DefaultRule(
        "BHRT001",
        "warning",
        "round-trip",
        "export/import or backup/restore pair lacks a detected round-trip test",
    ),
    DefaultRule(
        "BHRT002",
        "warning",
        "round-trip",
        (
            "export/import or backup/restore operation has no inverse "
            "operation alongside it"
        ),
    ),
    DefaultRule(
        "BHCX001",
        "warning/error",
        "complexity",
        "cyclomatic complexity exceeds the configured risk budget",
        "Ruff C901 + Lizard",
    ),
    DefaultRule(
        "BHCX002",
        "warning/error",
        "complexity",
        "function LOC exceeds the configured risk budget",
        "Lizard NLOC",
    ),
    DefaultRule(
        "BHCX003",
        "warning/error",
        "complexity",
        "file LOC exceeds the configured risk budget",
    ),
    DefaultRule(
        "BHCX004",
        "warning/error",
        "complexity",
        "ABC assignment/branch/condition magnitude exceeds the configured risk budget",
    ),
    DefaultRule(
        "BHCX005",
        "warning",
        "asset-budget",
        "individual JavaScript/CSS/WASM asset exceeds its configured size budget",
    ),
    DefaultRule(
        "BHCX006",
        "warning",
        "asset-budget",
        "built JavaScript/CSS/WASM bundle exceeds its configured size budget",
    ),
    DefaultRule(
        "BHCOV001",
        "warning/error",
        "coverage",
        "executable source lines are never exercised by tests",
        "coverage.py branch instrumentation",
    ),
    DefaultRule(
        "BHCOV002",
        "warning",
        "coverage",
        "control-flow branch edge is never exercised",
        "coverage.py branch instrumentation",
    ),
    DefaultRule(
        "BHSEAM001",
        "warning/error",
        "contract-drift",
        "dictionary keys written and consumed across a serialization seam drift apart",
    ),
    DefaultRule(
        "BHSEAM002",
        "error",
        "contract-drift",
        (
            "**kwargs forwarding chain can deliver keys the terminal "
            "signature does not accept"
        ),
    ),
    DefaultRule(
        "BHSEAM003",
        "warning",
        "contract-drift",
        "producer/consumer boundary type or parser contract appears inconsistent",
    ),
    DefaultRule(
        "BHSEAM004",
        "warning",
        "schema-drift",
        (
            "machine-readable schema and implementation contract "
            "need synchronization evidence"
        ),
    ),
    DefaultRule(
        "BHSEAM005",
        "warning",
        "runtime-validation",
        (
            "external HTTP JSON is consumed without explicit runtime "
            "model/schema validation"
        ),
        "Typeguard/Pydantic/OpenAPI validation can close the seam",
    ),
    DefaultRule(
        "BHSEAM006",
        "warning",
        "contract-drift",
        "external HTTP integration has no recorded-payload/cassette regression corpus",
    ),
    DefaultRule(
        "BHSEAM007",
        "error",
        "service-contract",
        "local provider does not satisfy a recorded consumer Pact contract",
    ),
    DefaultRule(
        "BHEVID001",
        "error",
        "evidence-preservation",
        "known static type is widened to Any/object/broad mapping and later cast back",
    ),
    DefaultRule(
        "BHEVID002",
        "warning",
        "evidence-preservation",
        (
            "chained casts reconstruct type evidence through assertions "
            "instead of preserving/narrowing it"
        ),
    ),
    DefaultRule(
        "BHEVID003",
        "warning",
        "performance",
        (
            "loop repeatedly copies a growing accumulator, risking "
            "accidental quadratic work"
        ),
    ),
    DefaultRule(
        "BHDB001",
        "warning",
        "database",
        "query-like database call occurs inside a loop; possible N+1/query explosion",
    ),
    DefaultRule(
        "BHTIME001",
        "warning",
        "environment-variation",
        "wall-clock logic exists without detected DST/leap/year-rollover tests",
    ),
    DefaultRule(
        "BHDIFF001",
        "warning",
        "behavior-compatibility",
        "public side-effect-free behavior changed against the local Git baseline",
    ),
    DefaultRule(
        "BHPERF001",
        "warning",
        "performance",
        "module import/startup time exceeds configured regression budget",
    ),
    DefaultRule(
        "BHDIS001",
        "warning",
        "type-disagreement",
        (
            "strict type engines disagree at the same source location; "
            "inspect erased/dynamic type evidence"
        ),
    ),
    DefaultRule(
        "BHPKG001",
        "error",
        "packaging",
        "package metadata/build/lock/install validation failed",
    ),
    DefaultRule(
        "BHPKG002",
        "error",
        "packaging",
        "installed wheel fails import smoke from an empty directory",
        "ast-grep repo-relative-resource (static half)",
    ),
    DefaultRule(
        "BHMISS001",
        "error",
        "data-invariants",
        "fillna(0)-imputed zero flows into a quantitative sink",
        "ast-grep fillna-zero (local tripwire)",
    ),
    DefaultRule(
        "BHDF001",
        "error",
        "data-invariants",
        "stale derived column read after a dependency was mutated",
    ),
    DefaultRule(
        "BHINT001",
        "error",
        "data-invariants",
        "half-open point selection feeds an adjacent-sample integrator",
    ),
    DefaultRule(
        "BHINT002",
        "error",
        "data-invariants",
        "trailing interval value used as a forward interval start",
    ),
    DefaultRule(
        "BHART001",
        "warning",
        "data-invariants",
        "cached artifact consumed before freshness is validated",
    ),
    DefaultRule(
        "BHART002",
        "error",
        "data-invariants",
        "artifact freshness contract omits build-time config dependencies",
    ),
    DefaultRule(
        "BHMETA001",
        "error",
        "data-invariants",
        "quantity result labeled complete/coverage-1.0 while data may be missing",
    ),
    DefaultRule(
        "BHMETA002",
        "warning",
        "contract-drift",
        "quantity propagated without its available quality metadata",
        "seam BHSEAM003 family",
    ),
    DefaultRule(
        "BHTIME002",
        "error",
        "data-invariants",
        "naive local wall clock labeled as UTC via utc=True",
    ),
    DefaultRule(
        "BHINV001",
        "error",
        "data-invariants",
        "two reject-predicates over one variable accept different sets",
    ),
    DefaultRule(
        "BHSEQ001",
        "error",
        "ast-grep",
        "unguarded first/last indexing of a fallible sequence",
    ),
    DefaultRule(
        "BHCTRL002",
        "warning",
        "ast-grep",
        "bare assert is removed under python -O; raise explicitly",
        "Ruff S101 overlaps",
    ),
    DefaultRule(
        "BHCFG006",
        "error",
        "semgrep",
        "denylist boolean parsing treats unexpected values as true",
    ),
    DefaultRule(
        "BHCONST001",
        "warning",
        "semgrep",
        "authority/version literal shape; hoist to one constant",
    ),
    DefaultRule(
        "BHEVID004",
        "warning",
        "semgrep",
        "hardcoded success claim after computed validation",
    ),
    DefaultRule(
        "bughunt.suppressed-exception",
        "warning",
        "semgrep",
        "contextlib.suppress silently discards the listed exceptions",
    ),
    DefaultRule(
        "BHCONST001",
        "warning",
        "semgrep",
        "authority/version literal shape duplicated; hoist to one constant",
    ),
    DefaultRule(
        "BHEVID004",
        "warning",
        "semgrep",
        "hardcoded success claim after computed validation",
    ),
    DefaultRule(
        "bughunt-swallowed-exception",
        "error",
        "ast-grep",
        "except block silently swallows an exception with pass",
        "CodeQL/Pylint/Ruff can overlap",
    ),
    DefaultRule(
        "bughunt-return-in-finally",
        "error",
        "ast-grep",
        "return/break/continue inside finally",
        "BHCTRL001 + Ruff B012",
    ),
    DefaultRule(
        "bughunt-swallowed-loop-error",
        "error",
        "ast-grep",
        "except handler silently discards the error with continue",
    ),
    DefaultRule(
        "bughunt-unused-auth-param",
        "error",
        "ast-grep",
        "auth-shaped parameter never appears in a digest/comparison body",
        "BC-000022 proof-preimage family",
    ),
    DefaultRule(
        "bughunt.cached-generator",
        "error",
        "semgrep",
        "cached generator can return an already-consumed iterator",
        "Semgrep correctness concept; low overlap",
    ),
    DefaultRule(
        "bughunt.unconsumed-threadpool-map",
        "error",
        "semgrep",
        (
            "ThreadPoolExecutor.map result is never consumed so "
            "worker exceptions can be lost"
        ),
    ),
    DefaultRule(
        "bughunt.dict-delete-during-iteration",
        "error",
        "semgrep",
        "dictionary entries deleted while iterating the same dictionary",
    ),
    DefaultRule(
        "bughunt.list-mutation-during-iteration",
        "warning",
        "semgrep",
        "list is structurally mutated while it is being iterated",
    ),
    DefaultRule(
        "bughunt.sync-sleep-in-async",
        "error",
        "semgrep",
        "blocking time.sleep call inside async code",
    ),
    DefaultRule(
        "bughunt.file-rebound-before-close",
        "error",
        "semgrep",
        "file handle is overwritten before the previous file is closed",
        "CodeQL file-not-closed may overlap",
    ),
    DefaultRule(
        "bughunt.named-tempfile-name-before-flush",
        "error",
        "semgrep",
        "temporary-file path consumed after writes but before flush/close",
    ),
    DefaultRule(
        "bughunt.assertion-free-test",
        "error",
        "semgrep",
        "test contains no assertion and passes silently",
    ),
    DefaultRule(
        "bughunt.ignored-warnings-filter",
        "warning",
        "semgrep",
        "warnings filter discards warnings instead of surfacing them",
    ),
    DefaultRule(
        "bughunt.suppressed-exception",
        "warning",
        "semgrep",
        "contextlib.suppress silently discards the listed exceptions",
    ),
)
