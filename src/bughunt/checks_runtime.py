# Copyright (c) 2026 Carter LaSalle
"""Runtime test, coverage, and fuzz check builders."""

from __future__ import annotations

import os
import secrets
import subprocess
import sys
from functools import partial
from .checkctx import CheckBuildCx
from .probes import generated_config, python_package_names
from .technology import target_executable, target_has_module
from .parsers import parse_bughunt_helper, text_findings
from .models import Check, Result, Status


# trace:v1 id=impl.src-bughunt-checks-runtime.-build-runtime-checks work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def build_runtime_checks(cx: CheckBuildCx) -> None:
    if cx.technology.has("python"):
        if "coverage" in cx.wanted:
            cov_python = (
                cx.target_py
                if target_has_module(cx.target_py, "bughunt")
                else sys.executable
            )
            if target_has_module(cov_python, "coverage") and cx.pytest:
                cx.add(
                    "coverage",
                    "coverage/branches",
                    [
                        cov_python,
                        "-m",
                        "bughunt.coverage_runner",
                        str(cx.root),
                        *cx.tests,
                    ],
                    lambda o, e, c: parse_bughunt_helper("coverage", o, e, c),
                    findings_exit_codes={1},
                )
            else:
                cx.add(
                    "coverage",
                    "coverage/branches",
                    None,
                    reason="coverage.py/pytest not installed",
                )

        if "seam" in cx.wanted:
            cx.add(
                "seam",
                "contract-drift",
                [
                    sys.executable,
                    "-m",
                    "bughunt.seam_scan",
                    str(cx.root),
                    ",".join(cx.cfg.source_paths),
                    ",".join(cx.cfg.test_paths),
                ],
                lambda o, e, c: parse_bughunt_helper("seam", o, e, c),
                findings_exit_codes={1},
            )

        if "evidence" in cx.wanted:
            cx.add(
                "evidence",
                "evidence-preservation",
                [
                    sys.executable,
                    "-m",
                    "bughunt.evidence_scan",
                    str(cx.root),
                    *cx.cfg.source_paths,
                ],
                lambda o, e, c: parse_bughunt_helper("evidence", o, e, c),
                findings_exit_codes={1},
            )

        if "semantic" in cx.wanted:
            cx.add(
                "semantic",
                "semantic-contracts",
                [
                    sys.executable,
                    "-m",
                    "bughunt.semantic_scan",
                    str(cx.root),
                    ",".join(cx.cfg.source_paths),
                ],
                lambda o, e, c: parse_bughunt_helper("semantic", o, e, c),
                findings_exit_codes={1},
            )

        if "packaging" in cx.wanted:
            cx.add(
                "packaging",
                "package-correctness",
                [sys.executable, "-m", "bughunt.package_checks", str(cx.root)],
                lambda o, e, c: parse_bughunt_helper("packaging", o, e, c),
                findings_exit_codes={1},
            )

        if "runtime-types" in cx.wanted:
            packages = python_package_names(cx.root, cx.cfg.source_paths)
            tg_cmd = None
            if cx.pytest and target_has_module(cx.target_py, "typeguard") and packages:
                tg_cmd = [
                    cx.pytest,
                    "-q",
                    "--tb=short",
                    f"--typeguard-packages={','.join(packages)}",
                    *cx.tests,
                ]
                if target_has_module(cx.target_py, "pytest_timeout"):
                    tg_cmd += ["--timeout", str(cx.test_timeout)]
            cx.add(
                "runtime-types",
                "runtime-type-contracts",
                tg_cmd,
                reason=(
                    "no importable package roots for Typeguard"
                    if not packages
                    else "typeguard/pytest not installed"
                ),
                env={"PYTHONHASHSEED": str(cx.repro_seed)},
            )

        if "doctest" in cx.wanted:
            doctest_cmd = (
                [cx.pytest, "-q", "--tb=short", "--doctest-modules", *cx.src]
                if cx.pytest
                else None
            )
            cx.add(
                "doctest",
                "executable-docs",
                doctest_cmd,
                reason="pytest not installed",
                skip_exit_codes={5},
            )

        if "pydoclint" in cx.wanted:
            pd = target_executable(cx.root, "pydoclint")
            cx.add(
                "pydoclint",
                "doc-contracts",
                [pd, *cx.src] if pd else None,
                reason="pydoclint not installed",
                findings_exit_codes={1},
            )

        if "refurb" in cx.wanted:
            rb = target_executable(cx.root, "refurb")
            cx.add(
                "refurb",
                "correctness-modernization",
                [rb, *cx.src] if rb else None,
                reason="refurb not installed",
                findings_exit_codes={1},
            )

        if "pytest-random" in cx.wanted:
            seed = secrets.randbelow(2**31 - 2) + 1
            cmd = (
                [cx.pytest, "-q", "--tb=short", f"--randomly-seed={seed}", *cx.tests]
                if cx.pytest and target_has_module(cx.target_py, "pytest_randomly")
                else None
            )
            cx.add(
                "pytest-random",
                "determinism/order",
                cmd,
                reason="pytest-randomly not installed",
                env={"PYTHONHASHSEED": str(seed), "PYTHONASYNCIODEBUG": "1"},
                findings_exit_codes={1},
            )

        if "pytest-no-network" in cx.wanted:
            cmd = (
                [
                    cx.pytest,
                    "-q",
                    "--tb=short",
                    "--disable-socket",
                    "--allow-unix-socket",
                    *cx.tests,
                ]
                if cx.pytest and target_has_module(cx.target_py, "pytest_socket")
                else None
            )
            cx.add(
                "pytest-no-network",
                "hidden-io",
                cmd,
                reason="pytest-socket not installed",
                env={"PYTHONHASHSEED": str(cx.repro_seed)},
                findings_exit_codes={1},
            )

        if "pytest-xdist" in cx.wanted:
            cmd = (
                [
                    cx.pytest,
                    "-q",
                    "--tb=short",
                    "-n",
                    "auto",
                    "--dist",
                    "loadfile",
                    *cx.tests,
                ]
                if cx.pytest and target_has_module(cx.target_py, "xdist")
                else None
            )
            cx.add(
                "pytest-xdist",
                "cross-test-state",
                cmd,
                reason="pytest-xdist not installed",
                env={"PYTHONHASHSEED": str(cx.repro_seed)},
                findings_exit_codes={1},
            )

        if "pytest-async-blocking" in cx.wanted:
            blocker = generated_config(cx.root, "blockbuster_plugin.py")
            cmd = (
                [cx.pytest, "-q", "--tb=short", "-p", "blockbuster_plugin", *cx.tests]
                if cx.pytest
                and blocker
                and target_has_module(cx.target_py, "blockbuster")
                else None
            )
            env = {"PYTHONASYNCIODEBUG": "1", "PYTHONHASHSEED": str(cx.repro_seed)}
            if blocker:
                env["PYTHONPATH"] = (
                    str(blocker.parent) + os.pathsep + os.environ.get("PYTHONPATH", "")
                )
            cx.add(
                "pytest-async-blocking",
                "async-runtime",
                cmd,
                reason="Blockbuster plugin not configured/installed",
                env=env,
                findings_exit_codes={1},
            )

        if "pytest-parallel" in cx.wanted:
            cmd = (
                [
                    cx.pytest,
                    "-q",
                    "--tb=short",
                    "--parallel-threads=auto",
                    "--iterations=3",
                    *cx.tests,
                ]
                if cx.pytest and target_has_module(cx.target_py, "pytest_run_parallel")
                else None
            )
            cx.add(
                "pytest-parallel",
                "thread-safety",
                cmd,
                reason="pytest-run-parallel not installed",
                env={"PYTHONASYNCIODEBUG": "1", "PYTHONHASHSEED": str(cx.repro_seed)},
                findings_exit_codes={1},
            )

        if "hypofuzz" in cx.wanted:
            hypothesis_cli = target_executable(cx.root, "hypothesis")
            budget = int(
                cx.cfg.raw_section("hypofuzz").get(
                    f"{cx.profile}_seconds",
                    300 if cx.profile == "all" else 120,
                ),
            )
            workers = int(cx.cfg.raw.get("hypofuzz", {}).get("workers", 2))
            cmd = (
                [
                    hypothesis_cli,
                    "fuzz",
                    "--no-dashboard",
                    "-n",
                    str(workers),
                    "--",
                    *cx.tests,
                ]
                if hypothesis_cli
                else None
            )
            cx.add(
                "hypofuzz",
                "coverage-guided-property-fuzz",
                cmd,
                reason="HypoFuzz/Hypothesis CLI not installed",
                check_timeout=budget,
                timeout_is_success=True,
                env={"PYTHONHASHSEED": str(cx.repro_seed)},
                # Fuzzing is generation: it needs Hypothesis randomized. The
                # "ci" settings profile (auto-loaded whenever these vars exist;
                # see hypothesis/_settings.py _CI_VARS) sets derandomize=True,
                # which makes HypoFuzz skip every target and exit 5.
                env_scrub=("CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI"),
                skip_exit_codes={5},
            )

        if "griffe" in cx.wanted:
            griffe = target_executable(cx.root, "griffe")
            baseline = cx.technology.git_baseline
            packages = python_package_names(cx.root, cx.cfg.source_paths)
            if griffe and baseline and packages:
                # One aggregate command keeps the defense readable; Griffe accepts
                # repeated packages.
                cmd = [griffe, "check", *packages, "--against", baseline]
                for sp in cx.cfg.source_paths:
                    cmd += ["--search", sp]
                cx.add(
                    "griffe",
                    "python-api-compatibility",
                    cmd,
                    reason="griffe unavailable",
                    findings_exit_codes={1},
                )
            else:
                reason = (
                    "no local Git baseline/public package found"
                    if griffe
                    else "griffe not installed"
                )
                cx.add("griffe", "python-api-compatibility", None, reason=reason)

        if "importtime" in cx.wanted:
            packages = python_package_names(cx.root, cx.cfg.source_paths)
            threshold = int(
                cx.cfg.raw.get("performance", {}).get("import_ms_warn", 1000)
            )
            cx.add(
                "importtime",
                "startup-performance",
                [
                    sys.executable,
                    "-m",
                    "bughunt.importtime_runner",
                    str(threshold),
                    *packages,
                ]
                if packages
                else None,
                lambda o, e, c: parse_bughunt_helper("importtime", o, e, c),
                reason="no importable package root",
                findings_exit_codes={1},
            )

        if "python-matrix" in cx.wanted:
            nox = target_executable(cx.root, "nox")
            noxfile = cx.root / ".bughunt" / "generated" / "noxfile.py"
            cx.add(
                "python-matrix",
                "interpreter-compatibility",
                [nox, "-f", str(noxfile), "--download-python", "auto"]
                if nox and noxfile.exists()
                else None,
                reason="Nox matrix not configured/installed",
                check_timeout=cx.cfg.timeout("all"),
                findings_exit_codes={1},
            )

        if "timezone-matrix" in cx.wanted:
            # Two hostile timezone passes; locale variation is only added when a
            # matching locale exists.
            for tz in ("UTC", "Pacific/Kiritimati"):
                name = f"timezone-matrix:{tz}"
                cx.checks.append(
                    Check(
                        name,
                        "environment-variation",
                        [cx.pytest, "-q", "--tb=short", *cx.tests],
                        partial(text_findings, name),
                        cx.timeout,
                        cx.root,
                        env={
                            "TZ": tz,
                            "PYTHONHASHSEED": str(cx.repro_seed),
                            "PYTHONASYNCIODEBUG": "1",
                        },
                        findings_exit_codes={1},
                    ),
                ) if cx.pytest else None
            # macOS commonly exposes Turkish as tr_TR.UTF-8/tr_TR.UTF-8-like names;
            # only run it if installed.
            try:
                locale_lines = subprocess.run(
                    ["locale", "-a"],  # noqa: S607 - executable resolved via project env/PATH by design, E501
                    capture_output=True,
                    text=True,
                    timeout=3,
                    check=False,
                ).stdout.splitlines()
            except (OSError, subprocess.SubprocessError):
                locale_lines = []
            turkish = next(
                (
                    x.strip()
                    for x in locale_lines
                    if x.strip().lower() in {"tr_tr.utf-8", "tr_tr.utf8", "tr_tr"}
                ),
                None,
            )
            if turkish and cx.pytest:
                name = "locale-matrix:tr_TR"
                cx.checks.append(
                    Check(
                        name,
                        "environment-variation",
                        [cx.pytest, "-q", "--tb=short", *cx.tests],
                        partial(text_findings, name),
                        cx.timeout,
                        cx.root,
                        env={
                            "LC_ALL": turkish,
                            "LANG": turkish,
                            "PYTHONHASHSEED": str(cx.repro_seed),
                        },
                        findings_exit_codes={1},
                    ),
                )

        if "memray" in cx.wanted:
            cmd = (
                [
                    cx.pytest,
                    "-q",
                    "--tb=short",
                    "--memray",
                    "--fail-on-increase",
                    *cx.tests,
                ]
                if cx.pytest and target_has_module(cx.target_py, "pytest_memray")
                else None
            )
            cx.add(
                "memray",
                "memory-runtime",
                cmd,
                reason="pytest-memray not installed",
                check_timeout=cx.cfg.timeout(cx.profile),
                findings_exit_codes={1},
            )

        if "benchmark" in cx.wanted:
            if (
                cx.technology.has("benchmark-tests")
                and cx.pytest
                and target_has_module(cx.target_py, "pytest_benchmark")
            ):
                cmd = [cx.pytest, "-q", "--benchmark-only", "--benchmark-autosave"]
                # xdist auto-activates --benchmark-disable, which conflicts
                # with --benchmark-only; benchmarks also need serial timing.
                cmd += ["-p", "no:xdist"]
                if (cx.root / ".benchmarks").exists():
                    regression = int(
                        cx.cfg.raw.get("performance", {}).get(
                            "benchmark_regression_percent",
                            10,
                        ),
                    )
                    cmd += [
                        "--benchmark-compare",
                        f"--benchmark-compare-fail=mean:{regression}%",
                    ]
                cmd += cx.tests
                cx.add(
                    "benchmark",
                    "performance-regression",
                    cmd,
                    findings_exit_codes={1},
                    skip_exit_codes={5},
                )
            else:
                cx.skipped.append(
                    Result(
                        "benchmark",
                        "performance-regression",
                        Status.NA
                        if not cx.technology.has("benchmark-tests")
                        else Status.SKIPPED,
                        note="no pytest-benchmark tests detected"
                        if not cx.technology.has("benchmark-tests")
                        else "pytest-benchmark not installed",
                    ),
                )

        if "pyanalyze" in cx.wanted:
            pa = target_executable(cx.root, "pyanalyze")
            allowed = bool(
                cx.cfg.raw.get("execution_imports", {}).get(
                    "allow_importing_analyzers",
                    False,
                ),
            )
            cx.add(
                "pyanalyze",
                "runtime-informed-static",
                [pa, *cx.src] if pa and allowed else None,
                reason=(
                    (
                        "installed but disabled: pyanalyze imports "
                        "modules; set execution_imports.allow_importing_analyzers=true "
                        "only in a sandbox"
                    )
                    if pa
                    else "pyanalyze not installed"
                ),
                findings_exit_codes={1},
            )

        # These are intentionally represented even when auto-execution would be unsafe.
        if "version-diff" in cx.wanted:
            baseline = cx.technology.git_baseline
            cx.add(
                "version-diff",
                "behavior-compatibility",
                [
                    sys.executable,
                    "-m",
                    "bughunt.version_diff_runner",
                    str(cx.root),
                    baseline,
                    *cx.cfg.source_paths,
                ]
                if baseline
                else None,
                lambda o, e, c: parse_bughunt_helper("version-diff", o, e, c),
                reason="no local Git baseline for behavioral differential",
                findings_exit_codes={1},
            )
        if "ghostwriter" in cx.wanted:
            cx.skipped.append(
                Result(
                    "ghostwriter",
                    "test-generation",
                    Status.NA,
                    note=(
                        "GUARDED: Hypothesis ghostwriter generates "
                        "candidate tests and may import project "
                        "callables; BugHunt property discovery "
                        "runs automatically, while ghostwriter "
                        "remains an explicit review/generation "
                        "helper"
                    ),
                ),
            )
        if "pynguin" in cx.wanted:
            cx.skipped.append(
                Result(
                    "pynguin",
                    "search-based-test-generation",
                    Status.NA,
                    note=(
                        "GUARDED: Pynguin executes modules under "
                        "test; only run in a throwaway or OS-sandboxed "
                        "environment, so this candidate does not "
                        "reduce correctness health"
                    ),
                ),
            )
