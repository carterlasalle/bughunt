# Copyright (c) 2026 Carter LaSalle
"""Doctor capability and coverage table builders."""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING

from rich.markup import escape
from rich.table import Table

from .discovery import load_generated_targets
from .probes import (
    generated_config,
    pact_json_files,
    python_module_available,
)
from .technology import (
    TechnologyInventory,
)

if TYPE_CHECKING:
    from .cli import Config


# trace:v1 id=impl.src-bughunt-doctor-tables.doctor-capability-rows work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def doctor_capability_rows(
    _cfg: Config, technology: TechnologyInventory, capability_table: Table
) -> None:
    """Capability rows appended to the capability table."""
    for cap in technology.capabilities.values():
        evidence = cap.evidence
        detail = ", ".join(evidence[:4])
        if len(evidence) > 4:
            detail += f" (+{len(evidence) - 4} more)"
        capability_table.add_row(
            cap.id,
            "[green]DETECTED[/]" if cap.detected else "[dim cyan]N/A[/]",
            escape(detail or cap.detail),
        )
    if technology.git_baseline:
        capability_table.caption = (
            f"Local Git compatibility baseline: {technology.git_baseline[:12]}"
        )


# trace:v1 id=impl.src-bughunt-doctor-tables.doctor-coverage-rows work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def doctor_coverage_rows(
    cfg: Config, technology: TechnologyInventory, coverage: Table
) -> None:
    """Coverage rows appended to the coverage table."""
    has_python = technology.has("python")
    generated = load_generated_targets(cfg.root)

    atheris_targets = [t for t in generated if t.kind == "atheris" and t.runnable]

    schema_targets = [t for t in generated if t.kind == "schemathesis" and t.runnable]

    schema_candidates = [t for t in generated if t.kind == "schemathesis-candidate"]

    explicit_atheris = cfg.raw_list("atheris", "targets")

    explicit_schema = cfg.raw_list("schemathesis", "targets")

    a_count = len(atheris_targets) + len(explicit_atheris)

    coverage.add_row(
        "Atheris fuzz targets",
        "[green]READY[/]" if a_count else "[yellow]TARGET NEEDED[/]",
        f"{a_count} runnable target(s)"
        if a_count
        else (
            "run `uv run bughunt configure --auto`; only safe one-input "
            "parser/decoder targets are generated"
        ),
    )

    s_count = len(schema_targets) + len(explicit_schema)

    schema_detail = (
        f"{s_count} runnable target(s)"
        if s_count
        else (
            "run `uv run bughunt configure --auto`; FastAPI apps "
            "can be fuzzed in-process"
        )
    )

    if not s_count and schema_candidates:
        schema_detail += (
            f"; {len(schema_candidates)} OpenAPI candidate(s) need a local base URL"
        )

    coverage.add_row(
        "Schemathesis API targets",
        "[green]READY[/]" if s_count else "[yellow]TARGET NEEDED[/]",
        schema_detail,
    )

    pysa_base = (cfg.root / ".pyre_configuration").exists() and (
        cfg.root / ".bughunt" / "configs" / "pysa" / "taint.config"
    ).exists()

    pysa_models = cfg.root / ".bughunt" / "configs" / "pysa" / "bughunt.pysa"

    semantic_lines = 0

    if pysa_models.exists():
        semantic_lines = sum(
            1
            for line in pysa_models.read_text(errors="replace").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )

    coverage.add_row(
        "Pysa taint framework",
        "[green]CONFIGURED[/]" if pysa_base else "[yellow]CONFIG NEEDED[/]",
        (
            f"base taint config ready; {semantic_lines} project semantic model line(s)"
            if pysa_base
            else "run `uv run bughunt configure --auto`"
        ),
    )

    sgconfig = generated_config(cfg.root, "sgconfig.yml")

    if not sgconfig:
        sgconfig = next(
            (
                cfg.root / p
                for p in ("sgconfig.yml", "sgconfig.yaml")
                if (cfg.root / p).exists()
            ),
            None,
        )

    coverage.add_row(
        "ast-grep project rules",
        "[green]CONFIGURED[/]" if sgconfig else "[yellow]CONFIG NEEDED[/]",
        str(sgconfig.relative_to(cfg.root))
        if sgconfig
        else "run `uv run bughunt configure --auto`",
    )

    custom_targets = [
        target
        for target in generated
        if target.kind.startswith("custom-") and target.runnable
    ]

    custom_counts = Counter(
        target.kind.removeprefix("custom-") for target in custom_targets
    )

    for category, label in (
        ("differential", "Differential oracles"),
        ("roundtrip", "Round-trip properties"),
        ("idempotence", "Metamorphic/idempotence properties"),
        ("fault-coverage", "Fault-injection boundary coverage"),
    ):
        count = custom_counts.get(category, 0)

        coverage.add_row(
            label,
            "[green]READY[/]" if count else "[dim]NONE INFERRED[/]",
            f"{count} high-confidence generated campaign(s)"
            if count
            else (
                "auto-configure found no high-confidence repository "
                "evidence for this campaign class"
            ),
        )

    configured_custom = cfg.raw_list("custom", "checks")

    coverage.add_row(
        "custom.checks managed entries",
        "[green]CONFIGURED[/]",
        (
            f"{len(configured_custom)} total custom check(s) loaded; generated "
            "high-confidence campaigns are persisted to bughunt.toml"
        ),
    )

    env_contract = cfg.root / ".bughunt" / "generated" / "env-contract.json"

    env_example = cfg.root / ".env.example"

    coverage.add_row(
        "Environment contract / .env.example",
        "[green]CONFIGURED[/]" if env_contract.exists() else "[dim]N/A[/]",
        (
            "static env inventory + managed .env.example generated"
            if env_contract.exists() and env_example.exists()
            else "no static environment-variable use inferred"
        ),
    )

    policy_roundtrip = [
        t for t in generated if t.kind == "custom-roundtrip" and t.runnable
    ]

    coverage.add_row(
        "Export/import round-trip enforcement",
        "[green]READY[/]" if policy_roundtrip else "[cyan]POLICY[/]",
        (
            f"{len(policy_roundtrip)} executable round-trip property campaign(s); "
            "policy scan also flags untested export/import and backup/restore pairs"
            if policy_roundtrip
            else (
                "policy scan flags supported export/import or backup/restore "
                "pairs lacking round-trip coverage"
            )
        ),
    )

    coverage.add_row(
        "Branch/line execution coverage",
        "[green]CONFIGURED[/]"
        if generated_config(cfg.root, "coverage.ini")
        else "[yellow]CONFIG NEEDED[/]",
        (
            "coverage.py branch instrumentation; uncovered lines/edges "
            "become BHCOV findings and feed the risk map"
        ),
    )

    coverage.add_row(
        "Runtime annotation verification",
        "[green]READY[/]"
        if has_python and python_module_available("typeguard")
        else ("[cyan]N/A[/]" if not has_python else "[yellow]MISSING[/]"),
        (
            "Typeguard pytest pass checks annotation truth where "
            "dynamic/untyped values enter"
        ),
    )

    coverage.add_row(
        "Environment/order/interpreter variation",
        "[green]CONFIGURED[/]"
        if (cfg.root / ".bughunt" / "generated" / "noxfile.py").exists()
        else "[yellow]CONFIG NEEDED[/]",
        (
            "fixed + random hash/order seeds, hostile TZ/locale "
            "passes, Nox 3.11-3.14 + free-threaded candidate"
        ),
    )

    coverage.add_row(
        "Seam/contract drift",
        "[green]ACTIVE[/]" if has_python else "[cyan]N/A[/]",
        (
            "dict-key drift, **kwargs chains, schema/model drift, "
            "external response validation, N+1 and recorded-payload "
            "coverage"
        ),
    )

    coverage.add_row(
        "Packaging/install correctness",
        "[green]ACTIVE[/]" if has_python else "[cyan]N/A[/]",
        (
            "validate-pyproject + uv lock/pip check + manifest "
            "+ build/twine where applicable"
        ),
    )

    pact_files = pact_json_files(cfg.root, technology.files.get("pact", []))

    pact_asgi = [
        t
        for t in generated
        if t.kind == "schemathesis" and (t.metadata or {}).get("transport") == "asgi"
    ]

    if technology.has("pact"):
        pact_ready = (
            bool(pact_files)
            and len(pact_asgi) == 1
            and python_module_available("pact")
            and python_module_available("uvicorn")
        )

        coverage.add_row(
            "Consumer/provider contract verification",
            "[green]READY[/]" if pact_ready else "[yellow]TARGET NEEDED[/]",
            (
                f"{len(pact_files)} Pact file(s) + one local ASGI provider; "
                "deep/all can verify locally"
                if pact_ready
                else (
                    "Pact detected, but automatic verification "
                    "requires concrete local Pact JSON plus exactly "
                    "one high-confidence local provider; remote "
                    "deployed providers are never auto-targeted"
                )
            ),
        )

    else:
        coverage.add_row(
            "Consumer/provider contract verification",
            "[dim cyan]N/A[/]",
            "no Pact contract capability detected",
        )

    coverage.add_row(
        "Cross-tool disagreement",
        "[green]ACTIVE[/]" if has_python else "[cyan]N/A[/]",
        (
            "BHDIS001 turns disagreement among strict type engines "
            "into first-class evidence instead of silently choosing "
            "one checker"
        ),
    )

    coverage.add_row(
        "Non-destructive deduplication",
        "[green]ACTIVE[/]",
        (
            "raw findings are preserved; reports also group "
            "same-location/same-defect-class evidence into logical issue "
            "clusters for agent repair"
        ),
    )

    coverage.add_row(
        "Recorded payload regression",
        "[green]POLICY[/]" if has_python else "[cyan]N/A[/]",
        (
            "BHSEAM006 requires HTTP integrations to have cassette/fixture "
            "payload evidence; VCR.py is optional, equivalent recorded "
            "fixtures count"
        ),
    )

    coverage.add_row(
        "Deterministic simulation",
        "[cyan]V2 ADAPTER[/]",
        (
            "clock/scheduler/network/RNG replay requires a project-specific "
            "simulation adapter; V2_SPEC.md defines seeded replay "
            "and promotion requirements rather than fabricating "
            "one"
        ),
    )

    coverage.add_row(
        "Bug Corpus learning/detectors",
        "[cyan]V2[/]",
        "specified in V2_SPEC.md; no external `bugcorpus` executable is required",
    )
