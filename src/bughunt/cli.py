# Copyright (c) 2026 Carter LaSalle
from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import re
import secrets as secrets
import signal
import sys
import threading
import time
from collections.abc import Sequence
from functools import partial as partial
from typing import Any

from rich import box
from rich.live import Live
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from bughunt.default_rules import DEFAULT_RULES

from . import __version__
from .configurator import JS_TOOL_IGNORES as JS_TOOL_IGNORES
from .configurator import configure_all, configure_custom_checks
from .models import Result as Result, Status as Status
from .models import Check as Check, DebtEntry as DebtEntry, Finding as Finding
from .reporting import (
    agent_queue as agent_queue,
    autofix_summary as autofix_summary,
    canonicalize_findings as canonicalize_findings,
    correlated_issue_groups as correlated_issue_groups,
    coverage_summary_from_results as coverage_summary_from_results,
    hotspot_files as hotspot_files,
    logical_issue_groups as logical_issue_groups,
    odc_class as odc_class,
    overall_score as overall_score,
    render_terminal as render_terminal,
    result_to_dict as result_to_dict,
    risk_map as risk_map,
    signal_groups as signal_groups,
    status_style as status_style,
    type_disagreement_result as type_disagreement_result,
    write_reports as write_reports,
)
from .debt import (
    debt_report as debt_report,
    debt_review as debt_review,
    debt_snapshot as debt_snapshot,
    load_debt_ledger as load_debt_ledger,
    mark_accepted as mark_accepted,
)
from .config import (
    CACHE_DIR as CACHE_DIR,
    Config as Config,
    deep_merge as deep_merge,
    default_config_raw as default_config_raw,
    load_config as load_config,
)
from .argparse_cli import build_parser
from . import runners as runners
from .runners import (
    LiveRunState as LiveRunState,
    LIVE_PROCS as LIVE_PROCS,
    STOP_REQUESTED as STOP_REQUESTED,
    stop_requested as stop_requested,
    handle_sigint as handle_sigint,
    interrupted_result as interrupted_result,
    reconcile_pysa_provider as reconcile_pysa_provider,
    run_codeql as run_codeql,
    run_mutmut as run_mutmut,
    run_parallel as run_parallel,
    run_process as run_process,
    run_pysa as run_pysa,
    reset_tool_dir as reset_tool_dir,
)
from .checkctx import CheckBuildCx
from .doctor_engines import doctor_engine_rows, doctor_guarded_rows
from .doctor_tables import doctor_capability_rows, doctor_coverage_rows
from .checks_python import build_python_checks
from .checks_quality import build_quality_checks
from .checks_structural import build_structural_checks
from .checks_runtime import build_runtime_checks
from .checks_matrices import build_matrix_checks
from .checks_native_a import build_native_a_checks
from .checks_native_b import build_native_b_checks
from .probes import optional_cmd as optional_cmd
from .probes import publishable_package_json as publishable_package_json
from .probes import pylint_disables as pylint_disables
from .probes import _supports_flag as _supports_flag
from .probes import analysis_scope as analysis_scope
from .probes import ast_grep_executable as ast_grep_executable
from .probes import atheris_available as atheris_available
from .probes import executable as executable
from .probes import existing_paths as existing_paths
from .probes import generated_config as generated_config
from .probes import import_linter_configured as import_linter_configured
from .probes import local_schema_pairs as local_schema_pairs
from .probes import pact_json_files as pact_json_files
from .probes import python_module_available as python_module_available
from .probes import python_package_names as python_package_names
from .probes import pysa_executable as pysa_executable
from .parsers import ESLINT_EMPTY_SCOPE as ESLINT_EMPTY_SCOPE
from .parsers import OXLINT_EMPTY_SCOPE as OXLINT_EMPTY_SCOPE
from .parsers import parse_actionlint as parse_actionlint
from .parsers import parse_ast_grep as parse_ast_grep
from .parsers import parse_bandit as parse_bandit
from .parsers import parse_basedpyright as parse_basedpyright
from .parsers import parse_buf_json_lines as parse_buf_json_lines
from .parsers import parse_bughunt_helper as parse_bughunt_helper
from .parsers import parse_clippy as parse_clippy
from .parsers import parse_complexipy as parse_complexipy
from .parsers import parse_cppcheck as parse_cppcheck
from .parsers import parse_deal as parse_deal
from .parsers import parse_deptry as parse_deptry
from .parsers import parse_eslint as parse_eslint
from .parsers import parse_golangci as parse_golangci
from .parsers import parse_hadolint as parse_hadolint
from .parsers import parse_json_list as parse_json_list
from .parsers import parse_lizard as parse_lizard
from .parsers import parse_oxlint as parse_oxlint
from .parsers import parse_phpstan as parse_phpstan
from .parsers import parse_pylint as parse_pylint
from .parsers import parse_pyrefly as parse_pyrefly
from .parsers import parse_radon_mi as parse_radon_mi
from .parsers import parse_ruff as parse_ruff
from .parsers import parse_sarif as parse_sarif
from .parsers import parse_semgrep as parse_semgrep
from .parsers import parse_shellcheck as parse_shellcheck
from .parsers import parse_sqlfluff as parse_sqlfluff
from .parsers import parse_squawk as parse_squawk
from .parsers import parse_tflint as parse_tflint
from .parsers import text_findings as text_findings
from .discovery import discover_all, load_generated_targets
from .installers import install_all
from .technology import (
    ENGINE_CAPABILITY,
    ENGINE_CATEGORY,
    discover_technologies,
    git_path_exists as git_path_exists,
    load_technology_inventory,
    project_executable as project_executable,
    target_executable,
    target_has_module,
    target_python,
    TECH_DEEP_TOOLS as TECH_DEEP_TOOLS,
    TECH_PR_TOOLS as TECH_PR_TOOLS,
)
from .ui import console as console

# These defenses operate specifically on Python source or Python's runtime/test
# ecosystem. They are N/A in repositories where no first-party Python capability
# exists; N/A never lowers defense health. Lizard and Semgrep are intentionally
# excluded because they can analyze multiple languages, while Schemathesis can
# exercise an OpenAPI contract independently of the implementation language.


# trace:v1 id=impl.src-bughunt-cli.build-checks work=WORK-BUG-4ABH9VEY satisfies=REQ-BUG-KZG483AX implements=PLAN-BUG-560GXA79
def build_checks(
    cfg: Config,
    profile: str,
    *,
    excluded: set[str] | None = None,
) -> tuple[list[Check], list[Result]]:
    root = cfg.root
    timeout = cfg.timeout(profile)
    profile_tools = cfg.tools(profile)
    excluded = set(excluded or ())
    wanted = [name for name in profile_tools if name not in excluded]
    py = analysis_scope(root, cfg.python_paths)
    src = analysis_scope(root, cfg.source_paths)
    tests = analysis_scope(root, cfg.test_paths)
    config_dir = root / ".bughunt" / "configs"
    checks: list[Check] = []
    skipped: list[Result] = []
    generated_targets = load_generated_targets(root)
    technology = load_technology_inventory(root)
    category_by_tool = {
        "codeql": "whole-program",
        "pysa": "taint",
        "mutmut": "mutation",
        "semgrep": "semantic-static",
        "ast-grep": "structural",
        "bandit": "security",
        "atheris": "coverage-fuzz",
        "schemathesis": "api-fuzz",
        "bugcorpus": "historical/custom-static",
        **ENGINE_CATEGORY,
    }
    target_py = target_python(root)
    pytest = target_executable(root, "pytest")
    hypothesis_plugin = generated_config(root, "hypothesis_plugin.py")
    repro_seed = cfg.raw_int("tests", "repro_seed", 1)
    test_timeout = cfg.raw_int("tests", "timeout_seconds", 300)
    pytest_env = {"HYPOTHESIS_PROFILE": "bughunt", "PYTHONHASHSEED": str(repro_seed)}
    pytest_cmd = (
        [
            pytest,
            "-q",
            "--tb=short",
            "--strict-config",
            "--strict-markers",
            "-o",
            "xfail_strict=true",
        ]
        if pytest
        else None
    )
    if pytest_cmd and target_has_module(target_py, "pytest_timeout"):
        pytest_cmd += ["--timeout", str(test_timeout)]
    if pytest_cmd and profile in {"deep", "all"}:
        # Resource/deprecation/runtime warnings are often latent bugs. Developer
        # mode also enables faulthandler and extra CPython runtime checks.
        pytest_cmd += ["-W", "error"]
        pytest_env["PYTHONDEVMODE"] = "1"
        pytest_env["PYTHONASYNCIODEBUG"] = "1"
    if pytest_cmd and hypothesis_plugin and target_has_module(target_py, "hypothesis"):
        pytest_cmd += ["-p", "hypothesis_plugin"]
        pytest_env["PYTHONPATH"] = (
            str(hypothesis_plugin.parent)
            + os.pathsep
            + os.environ.get("PYTHONPATH", "")
        )
    if pytest_cmd:
        pytest_cmd += tests
    cx = CheckBuildCx(
        cfg=cfg,
        profile=profile,
        root=root,
        timeout=timeout,
        wanted=wanted,
        excluded=excluded,
        py=py,
        src=src,
        tests=tests,
        config_dir=config_dir,
        checks=checks,
        skipped=skipped,
        generated_targets=generated_targets,
        technology=technology,
        category_by_tool=category_by_tool,
        target_py=target_py,
        pytest=pytest,
        hypothesis_plugin=hypothesis_plugin,
        repro_seed=repro_seed,
        test_timeout=test_timeout,
        pytest_env=pytest_env,
        pytest_cmd=pytest_cmd,
    )
    if not cx.technology.has("python"):
        for name, category in (
            ("codeql", "whole-program"),
            ("pysa", "taint"),
            ("mutmut", "mutation"),
        ):
            if name in cx.wanted:
                cx.skipped.append(
                    Result(
                        name,
                        category,
                        Status.NA,
                        note=(
                            "not applicable: no first-party Python capability detected"
                        ),
                    ),
                )
    cx.skipped.extend(
        Result(
            name=name,
            category=category_by_tool.get(name, "excluded"),
            status=Status.SKIPPED,
            note="explicitly skipped by user",
        )
        for name in sorted(cx.excluded & set(profile_tools))
    )
    build_python_checks(cx)
    build_quality_checks(cx)
    build_structural_checks(cx)
    build_runtime_checks(cx)
    build_matrix_checks(cx)
    build_native_a_checks(cx)
    build_native_b_checks(cx)
    return cx.checks, cx.skipped


# Banner pyre prints when it cannot locate its Pyrefly type-provider binary.
# A missing provider means the defense cannot execute; the runner maps it to
# SKIPPED with the repair stated instead of reporting an analysis ERROR.


_TRACE_MARKER_LINE = re.compile(r"^\s*(?:#\s*|<!--\s*)trace:(?:v1|exempt)\b")


# trace:v1 id=impl.src-bughunt-cli.show-default-rules work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def show_default_rules() -> int:
    table = Table(
        title=f"BugHunt Default Rule Pack — {len(DEFAULT_RULES)} rules",
        box=box.ROUNDED,
        expand=True,
    )
    table.add_column("CODE", style="cyan", no_wrap=True)
    table.add_column("SEVERITY", width=14)
    table.add_column("CLASS", width=22)
    table.add_column("RULE", ratio=3)
    table.add_column("REDUNDANCY", ratio=2)
    for rule in DEFAULT_RULES:
        style = (
            "red"
            if "error" in rule.severity
            else ("yellow" if "warning" in rule.severity else "dim")
        )
        table.add_row(
            rule.code,
            f"[{style}]{rule.severity}[/]",
            rule.category,
            rule.summary,
            rule.overlap or "—",
        )
    console.print(table)
    console.print(
        (
            "[dim]These are BugHunt-native defaults. Ruff ALL, "
            "type checkers, Pylint extensions, Semgrep packs, CodeQL, "
            "and other analyzers add their own rule sets on top.[/]"
        ),
    )
    return 0


# trace:v1 id=impl.src-bughunt-cli.doctor work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def doctor(cfg: Config) -> int:
    technology = discover_technologies(cfg.root, persist=True)

    rows = doctor_engine_rows(cfg, technology)
    engines = Table(title="BugHunt Engines", box=box.ROUNDED, expand=True)
    engines.add_column("ENGINE", min_width=24)
    engines.add_column("STATUS", width=13)
    engines.add_column("EXECUTABLE / MODULE", ratio=2)
    styles = {
        "READY": "green",
        "MISSING": "red",
        "BROKEN": "red",
        "DEGRADED": "yellow",
        "N/A": "cyan",
    }
    for label, state, detail in rows:
        engines.add_row(
            label,
            f"[{styles.get(state, 'yellow')}]{state}[/]",
            escape(detail),
        )
    console.print(engines)

    guarded = Table(
        title="Guarded / Advisory Correctness Helpers",
        box=box.ROUNDED,
        expand=True,
    )
    guarded.add_column("HELPER", min_width=26)
    guarded.add_column("STATE", width=13)
    guarded.add_column("ROLE / WHY GUARDED", ratio=3)

    doctor_guarded_rows(cfg, technology, guarded)
    console.print(guarded)

    capability_table = Table(
        title="Repository Capabilities",
        box=box.ROUNDED,
        expand=True,
    )
    capability_table.add_column("CAPABILITY", min_width=24)
    capability_table.add_column("STATE", width=12)
    capability_table.add_column("EVIDENCE", ratio=3)
    doctor_capability_rows(cfg, technology, capability_table)
    console.print(capability_table)

    manifest_path = cfg.root / ".bughunt" / "configs" / "manifest.json"
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text())
            configured = Table(
                title="Strict Analyzer Configuration",
                box=box.ROUNDED,
                expand=True,
            )
            configured.add_column("STATE", width=11)
            configured.add_column("TOOL", min_width=20)
            configured.add_column("CONFIG", min_width=25)
            configured.add_column("DETAIL", ratio=2)
            for item in manifest.get("artifacts", []):
                state = str(item.get("state", "UNKNOWN"))
                style = "green" if state in {"READY", "EXISTING", "AUTO"} else "yellow"
                configured.add_row(
                    f"[{style}]{state}[/]",
                    str(item.get("name", "?")),
                    str(item.get("path") or "—"),
                    str(item.get("detail") or ""),
                )
            console.print(configured)
        except (OSError, json.JSONDecodeError, TypeError):
            console.print(
                (
                    "[yellow]Strict config manifest is unreadable; "
                    "run `uv run bughunt configure --auto`.[/]"
                ),
            )
    else:
        console.print(
            (
                "[yellow]Strict analyzer overlays are not generated "
                "yet. Run `uv run bughunt configure --auto`.[/]"
            ),
        )

    coverage = Table(title="Repository-Specific Coverage", box=box.ROUNDED, expand=True)
    coverage.add_column("DEFENSE", min_width=34)
    coverage.add_column("CONFIG", width=18)
    coverage.add_column("DETAIL", ratio=2)
    doctor_coverage_rows(cfg, technology, coverage)
    console.print(coverage)
    return 0


# trace:v1 id=impl.src-bughunt-cli.auto-configure work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def auto_configure(cfg: Config, *, quiet: bool = False) -> list[Any]:
    autod = cfg.raw.get("autodiscovery", {})
    schemathesis_examples = max(1000, int(autod.get("schemathesis_max_examples", 1000)))
    artifacts = configure_all(
        cfg.root,
        cfg.python_paths,
        cfg.source_paths,
        cfg.test_paths,
        schemathesis_examples=schemathesis_examples,
    )
    targets = discover_all(
        cfg.root,
        cfg.source_paths,
        atheris_runs=max(500_000, int(autod.get("atheris_runs", 500_000))),
        schemathesis_examples=schemathesis_examples,
    )
    custom_artifact = configure_custom_checks(cfg.root, targets)
    artifacts.append(custom_artifact)
    pysa_evidence = cfg.root / ".bughunt" / "generated" / "pysa-models.json"
    pysa_count = 0
    if pysa_evidence.exists():
        try:
            pysa_count = len(json.loads(pysa_evidence.read_text()).get("models", []))
        except (OSError, json.JSONDecodeError, TypeError):
            pysa_count = 0
    artifacts.append(
        type(custom_artifact)(
            "Pysa inferred semantic models",
            ".bughunt/configs/pysa/bughunt.pysa",
            "READY",
            (
                f"{pysa_count} high-confidence direct source/sink wrapper model(s) "
                "inferred; evidence in .bughunt/generated/pysa-models.json"
            ),
        ),
    )
    generated_checks = [
        {
            "name": target.name,
            "category": target.kind.removeprefix("custom-"),
            "profile": "deep",
            "command": list(target.command),
            "timeout": int((target.metadata or {}).get("timeout", 3600)),
            "generated": True,
            "confidence": target.confidence,
        }
        for target in targets
        if target.kind.startswith("custom-")
        and target.runnable
        and target.command
        and target.confidence == "high"
    ]
    existing_checks = [
        x for x in cfg.raw.get("custom", {}).get("checks", []) if not x.get("generated")
    ]
    cfg.raw.setdefault("custom", {})["checks"] = [*existing_checks, *generated_checks]
    manifest_path = cfg.root / ".bughunt" / "configs" / "manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    _ = manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 3,
                "artifacts": [dataclasses.asdict(item) for item in artifacts],
            },
            indent=2,
        )
        + "\n",
    )
    if not quiet:
        ctable = Table(
            title="Strict Analyzer Configuration",
            box=box.ROUNDED,
            expand=True,
        )
        ctable.add_column("STATE", width=11)
        ctable.add_column("TOOL", min_width=18)
        ctable.add_column("CONFIG", min_width=24)
        ctable.add_column("DETAIL", ratio=2)
        for item in artifacts:
            style = "green" if item.state in {"READY", "EXISTING", "AUTO"} else "yellow"
            ctable.add_row(
                f"[{style}]{item.state}[/]",
                item.name,
                item.path or "—",
                item.detail,
            )
        console.print(ctable)

        inventory = discover_technologies(cfg.root, persist=True)
        cap_table = Table(
            title="Repository Capability Auto-selection",
            box=box.ROUNDED,
            expand=True,
        )
        cap_table.add_column("CAPABILITY", min_width=24)
        cap_table.add_column("STATE", width=12)
        cap_table.add_column("APPLICABLE ENGINES", ratio=2)
        cap_table.add_column("EVIDENCE", ratio=3)
        for capability in inventory.capabilities.values():
            engines = [
                name for name, cap in ENGINE_CAPABILITY.items() if cap == capability.id
            ]
            evidence = ", ".join(capability.evidence[:3])
            if len(capability.evidence) > 3:
                evidence += f" (+{len(capability.evidence) - 3} more)"
            cap_table.add_row(
                capability.id,
                "[green]DETECTED[/]" if capability.detected else "[dim cyan]N/A[/]",
                ", ".join(engines) or "—",
                escape(evidence or capability.detail),
            )
        console.print(cap_table)

        table = Table(
            title="Auto-discovered Targets & Campaigns",
            box=box.ROUNDED,
            expand=True,
        )
        table.add_column("STATE", width=11)
        table.add_column("ENGINE", width=18)
        table.add_column("TARGET", min_width=28)
        table.add_column("CONF", width=8)
        table.add_column("WHY", ratio=2)
        for target in targets:
            state = "[green]READY[/]" if target.runnable else "[yellow]REVIEW[/]"
            engine = (
                "schemathesis"
                if target.kind.startswith("schemathesis")
                else target.kind.removeprefix("custom-")
            )
            table.add_row(state, engine, target.name, target.confidence, target.reason)
        if not targets:
            table.add_row(
                "[dim]NONE[/]",
                "—",
                "—",
                "—",
                "No high-confidence fuzz/API/semantic targets discovered",
            )
        console.print(table)
        console.print(
            f"[dim]Registry: {cfg.root / '.bughunt' / 'generated' / 'targets.json'}[/]",
        )
    return targets


# trace:v1 id=impl.src-bughunt-cli.run-all work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
async def run_all(
    cfg: Config,
    profile: str,
    *,
    auto_discover: bool = True,
    excluded: set[str] | None = None,
) -> tuple[list[Result], float]:
    runners.STOP_REQUESTED = False
    started = time.perf_counter()
    raw_limit = int(cfg.raw.get("execution", {}).get("raw_output_limit_kb", 512)) * 1024
    if auto_discover and cfg.raw.get("autodiscovery", {}).get("enabled", True):
        _ = auto_configure(cfg, quiet=True)

    excluded = set(excluded or ())
    checks, skipped = build_checks(cfg, profile, excluded=excluded)
    effective_tools = set(cfg.tools(profile)) - excluded
    if not load_technology_inventory(cfg.root).has("python"):
        effective_tools -= {"codeql", "pysa", "mutmut"}
    # Count logical defenses, not internal CodeQL database/mutmut-results phases.
    special_names = [
        name for name in ("codeql", "pysa", "mutmut") if name in effective_tools
    ]
    progress = LiveRunState(total=len(checks) + len(skipped) + len(special_names))
    for item in skipped:
        progress.finish(item)

    stop_refresh = asyncio.Event()

    # trace:v1 id=impl.src-bughunt-cli-run-all.refresher work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
    async def refresher(live: Live) -> None:
        last_heartbeat = time.perf_counter()
        while not stop_refresh.is_set():
            live.update(progress.render(), refresh=True)
            now = time.perf_counter()
            if now - last_heartbeat >= 60:
                last_heartbeat = now
                stuck = sorted(
                    (name, now - float(e["started"]), now - float(e["last_activity"]))
                    for name, e in progress.running.items()
                )
                print(
                    f"[bughunt heartbeat] {now - progress.started_at:.0f}s elapsed, "
                    f"{len(progress.completed)} done, {len(stuck)} running: "
                    + ", ".join(f"{n}({int(a)}s)" for n, a, _ in stuck[:12]),
                    file=sys.stderr,
                    flush=True,
                )
            try:
                await asyncio.wait_for(stop_refresh.wait(), timeout=0.5)
            except TimeoutError:
                # Shutdown race; the loop is already stopping
                pass

    results: list[Result] = []
    with Live(
        progress.render(),
        console=console,
        refresh_per_second=4,
        transient=False,
    ) as live:
        # Signals are delivered to the main thread only; installing a handler
        # off the main thread raises ValueError and could never fire there.
        main_thread = threading.current_thread() is threading.main_thread()
        previous_handler = signal.getsignal(signal.SIGINT)
        if main_thread:
            signal.signal(signal.SIGINT, handle_sigint)
        refresh_task = asyncio.create_task(refresher(live))
        try:
            normal = await run_parallel(checks, cfg.max_parallel, raw_limit, progress)
            special = []
            for runner, logical_name in (
                (run_codeql, "codeql"),
                (run_pysa, "pysa"),
                (run_mutmut, "mutmut"),
            ):
                if logical_name not in effective_tools:
                    continue
                if runners.stop_requested():
                    categories = {
                        "codeql": "whole-program",
                        "pysa": "taint",
                        "mutmut": "mutation",
                    }
                    result = interrupted_result(
                        logical_name, categories.get(logical_name, logical_name)
                    )
                    progress.finish(result)
                    special.append(result)
                    continue
                result = await runner(cfg, profile, raw_limit, progress)
                # Internal subprocesses never count as finished defenses. Record
                # exactly one logical result here, regardless of how many phases ran.
                _ = progress.running.pop("codeql-db", None)
                _ = progress.running.pop("mutmut-results", None)
                progress.finish(result)
                special.append(result)
            results = normal + skipped
            for r in special:
                if r.note == "not in profile":
                    continue
                results.append(r)
        finally:
            stop_refresh.set()
            await refresh_task
            live.update(progress.render(), refresh=True)
            if main_thread:
                signal.signal(signal.SIGINT, previous_handler)

    canonicalize_findings(cfg.root, results)
    mark_accepted(results, load_debt_ledger(cfg.root))
    if "type-disagreement" in effective_tools:
        disagreement = type_disagreement_result(results)
        if disagreement is not None:
            results = [r for r in results if r.name != "type-disagreement"] + [
                disagreement,
            ]
    by_name = {result.name: result for result in results}
    reconcile_pysa_provider(by_name)
    return results, time.perf_counter() - started


def exit_code_for(cfg: Config, results: list[Result]) -> int:
    policy = str(cfg.raw.get("execution", {}).get("fail_on", "findings"))
    if policy == "never":
        return 0
    if any(r.status == Status.ERROR for r in results):
        return 2
    if policy == "findings" and any(r.status == Status.FINDINGS for r in results):
        return 1
    return 0


# trace:v1 id=impl.src-bughunt-cli.main work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def main(argv: Sequence[str] | None = None) -> int:
    print(f"bughunt v{__version__}", file=sys.stderr)
    parser = build_parser()
    args = parser.parse_args(argv)
    root = args.root.resolve()
    cfg = load_config(root, args.config)

    if args.command == "rules":
        return show_default_rules()

    if args.command == "doctor":
        return doctor(cfg)
    if args.command == "debt":
        if args.debt_command == "snapshot":
            return debt_snapshot(
                root,
                list(args.signal or []),
                str(args.reason or ""),
                list(args.path or []),
            )
        return debt_review(root)

    if args.command == "configure":
        _ = auto_configure(cfg)
        return 0

    if args.command == "install":
        selected = ", ".join(args.only) if args.only else "full analysis stack"
        console.print(
            Panel.fit(
                f"[bold bright_cyan]Installing BugHunt: {escape(selected)} with uv[/]",
                border_style="bright_cyan",
            ),
        )
        results = install_all(
            root,
            dry_run=args.dry_run,
            emit=lambda line: console.print(f"[dim]{line}[/]"),
            only=set(args.only) if args.only else None,
        )
        table = Table(title="Installation", box=box.ROUNDED, expand=True)
        table.add_column("STATUS", width=12)
        table.add_column("COMPONENT", min_width=24)
        table.add_column("DETAIL", ratio=2)
        for item in results:
            style = (
                "green"
                if item.status == "PASS"
                else ("yellow" if item.status in {"SKIPPED", "DRY-RUN"} else "red")
            )
            table.add_row(f"[{style}]{item.status}[/]", item.name, item.note)
        console.print(table)
        return 1 if any(item.status == "ERROR" for item in results) else 0

    alias_profiles = {"quick": "fast", "pr": "pr", "deep": "deep"}
    if args.command in {"all", "full", "skipmutmut"}:
        profile = "all"
    elif args.command == "run":
        profile = (
            getattr(args, "profile_positional", None)
            or getattr(args, "profile", None)
            or "pr"
        )
    else:
        profile = alias_profiles.get(args.command, "pr")
    excluded = set(cfg.skip) | set(getattr(args, "skip", []) or [])
    if bool(getattr(args, "skip_mutmut", False)) or args.command == "skipmutmut":
        excluded.add("mutmut")
    known_defenses = (
        set(cfg.tools(profile))
        | set(TECH_DEEP_TOOLS)
        | {
            "mutmut",
            "codeql",
            "pysa",
            "atheris",
            "schemathesis",
            "semgrep",
            "ast-grep",
            "bandit",
            "bugcorpus",
            "custom",
            "pylint-tests",
        }
    )
    unknown_skips = sorted(excluded - known_defenses)
    if unknown_skips:
        parser.error(
            "unknown defense(s) for --skip / execution.skip: "
            + ", ".join(unknown_skips),
        )

    if args.command in {"all", "full", "skipmutmut"} and args.install_missing:
        suffix = " (mutmut skipped)" if "mutmut" in excluded else ""
        inventory = discover_technologies(root, persist=True)
        detected = sum(1 for item in inventory.capabilities.values() if item.detected)
        console.print(
            (
                f"[bold]Detected {detected} repository capability class(es); "
                f"installing only applicable analysis engines{suffix}...[/]"
            ),
        )
        try:
            if excluded:
                install_results = install_all(
                    root,
                    dry_run=False,
                    emit=lambda line: console.print(f"[dim]{line}[/]"),
                    exclude=excluded,
                )
            else:
                install_results = install_all(
                    root,
                    dry_run=False,
                    emit=lambda line: console.print(f"[dim]{line}[/]"),
                )
        except KeyboardInterrupt:
            console.print(
                "[yellow]Installation interrupted — aborting before "
                "the scan starts. Re-run to continue.[/]"
            )
            return 130
        if any(x.status == "ERROR" for x in install_results):
            console.print(
                (
                    "[yellow]Some installers failed; continuing "
                    "so the final report records the remaining "
                    "blind spots.[/]"
                ),
            )
        # Reload config/environment view after uv modified the project.
        cfg = load_config(root, args.config)

    no_auto = bool(getattr(args, "no_auto_config", False))
    if not no_auto:
        _ = auto_configure(cfg, quiet=True)

    profile_display = profile + (
        " - " + ", ".join(f"no {name}" for name in sorted(excluded)) if excluded else ""
    )
    console.print(
        Panel.fit(
            (
                f"[bold bright_cyan]Scanning[/] [bold]{root.name}[/] with "
                f"[bold bright_magenta]{profile_display}[/] defenses"
            ),
            border_style="bright_cyan",
        ),
    )
    if excluded:
        scan_results, elapsed = asyncio.run(
            run_all(cfg, profile, auto_discover=False, excluded=excluded),
        )
    else:
        scan_results, elapsed = asyncio.run(run_all(cfg, profile, auto_discover=False))
    md, js = write_reports(cfg, scan_results, profile, elapsed)
    render_terminal(scan_results, profile, elapsed, md, js)
    if runners.stop_requested():
        console.print("[yellow]Scan interrupted — partial report written above.[/]")
        return 130
    return exit_code_for(cfg, scan_results)


if __name__ == "__main__":
    raise SystemExit(main())
