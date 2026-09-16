# Copyright (c) 2026 Carter LaSalle
"""Structural and semantic static check builders."""

from __future__ import annotations

import os
import sys
from .checkctx import CheckBuildCx
from .probes import (
    _optional_cmd,
    _supports_flag,
    ast_grep_executable,
    generated_config,
    import_linter_configured,
    python_module_available,
)
from .technology import target_executable
from .parsers import (
    parse_ast_grep,
    parse_deal,
    parse_deptry,
    parse_semgrep,
    text_findings,
)
from .models import Check, Result, Status


# trace:v1 id=impl.src-bughunt-checks-structural.-build-structural-checks work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _build_structural_checks(cx: CheckBuildCx) -> None:
    deptry_cmd = _optional_cmd(
        target_executable(cx.root, "deptry"),
        [
            *cx.src,
            "--extend-exclude",
            r"(^|/)(.bughunt|build|dist|mutants|node_modules)(/|$)",
            "--experimental-namespace-package",
            "--no-ansi",
        ],
    )
    cx.add(
        "deptry",
        "dependencies",
        deptry_cmd,
        parse_deptry,
        reason="deptry not installed",
    )
    import_linter = target_executable(cx.root, "lint-imports", "import-linter")
    generated_import_cfg = generated_config(cx.root, "importlinter.toml")
    lint_flags = (
        ["--no-logo", "--show-timings"]
        if import_linter and _supports_flag(import_linter, "--no-logo", cx.root)
        else ["--show-timings"]
    )
    if import_linter and generated_import_cfg:
        cx.add(
            "import-linter",
            "architecture",
            [
                import_linter,
                "--config",
                str(generated_import_cfg),
                *lint_flags,
            ],
            reason="import-linter not installed",
        )
    elif import_linter and import_linter_configured(cx.root):
        cx.add(
            "import-linter",
            "architecture",
            [import_linter, *lint_flags],
            reason="import-linter not installed",
        )
    else:
        cx.add(
            "import-linter",
            "architecture",
            None,
            reason=(
                "import-linter not installed"
                if not import_linter
                else "no safe import contract could be inferred; run configure --auto"
            ),
        )
    sg = ast_grep_executable(cx.root)
    sgconfig = generated_config(cx.root, "sgconfig.yml")
    if not sgconfig:
        sgconfig = next(
            (
                cx.root / p
                for p in ("sgconfig.yml", "sgconfig.yaml")
                if (cx.root / p).exists()
            ),
            None,
        )
    sg_cmd = (
        [sg, "scan", "--json=compact", "--config", str(sgconfig), *cx.py]
        if sg and sgconfig
        else None
    )
    cx.add(
        "ast-grep",
        "structural",
        sg_cmd,
        parse_ast_grep,
        reason="ast-grep missing or no generated/project sgconfig.yml",
    )
    semgrep = target_executable(cx.root, "semgrep")
    semgrep_settings = cx.cfg.raw.get("semgrep", {})
    requested_semgrep = list(semgrep_settings.get("configs", []))
    semgrep_cfgs = [
        "p/default" if str(x) == "auto" else str(x) for x in requested_semgrep
    ]
    if "p/default" not in semgrep_cfgs:
        semgrep_cfgs.append("p/default")
    if bool(semgrep_settings.get("include_security", False)):
        semgrep_cfgs.extend(
            str(x)
            for x in semgrep_settings.get(
                "security_configs",
                ["p/security-audit", "p/secrets"],
            )
        )
    local_semgrep = cx.config_dir / "semgrep" / "rules"
    if local_semgrep.exists() and any(
        path.suffix in {".yml", ".yaml"} for path in local_semgrep.rglob("*")
    ):
        semgrep_cfgs.append(str(local_semgrep))
    semgrep_cmd = (
        [semgrep, "scan", "--json", "--metrics=off", "--disable-version-check"]
        if semgrep
        else []
    )
    if semgrep_cmd:
        semgrep_cmd.append(
            "--pro" if os.environ.get("SEMGREP_APP_TOKEN") else "--oss-only",
        )
    for c in dict.fromkeys(semgrep_cfgs):
        semgrep_cmd.extend(["--config", c])
    semgrep_cmd.extend(cx.py)
    cx.add(
        "semgrep",
        "semantic-static",
        semgrep_cmd if semgrep else None,
        parse_semgrep,
        reason="semgrep not installed",
    )
    deal_ready = python_module_available("deal")
    cx.add(
        "deal",
        "contracts",
        [sys.executable, "-m", "deal", "lint", *cx.src, "--json"]
        if deal_ready
        else None,
        parse_deal,
        reason="deal Python module not installed",
        findings_exit_codes=set(range(1, 256)),
    )
    crosshair = target_executable(cx.root, "crosshair")
    crosshair_cmd = None
    if crosshair:
        per_path = (
            "8" if cx.profile == "all" else ("5" if cx.profile == "deep" else "3")
        )
        per_condition = (
            "180" if cx.profile == "all" else ("90" if cx.profile == "deep" else "45")
        )
        iterations = (
            "1000"
            if cx.profile == "all"
            else ("300" if cx.profile == "deep" else "100")
        )
        crosshair_cmd = [
            crosshair,
            "check",
            "--analysis_kind=asserts,PEP316,deal,icontract",
            "--max_uninteresting_iterations",
            iterations,
            "--per_path_timeout",
            per_path,
            "--per_condition_timeout",
            per_condition,
            *cx.src,
        ]
    cx.add(
        "crosshair",
        "symbolic",
        crosshair_cmd,
        reason="crosshair not installed",
        findings_exit_codes={1},
    )
    if "pytest" in cx.wanted:
        if not cx.technology.has("python"):
            cx.skipped.append(
                Result(
                    "pytest",
                    "tests/property/state",
                    Status.NA,
                    note="not applicable: no first-party Python capability detected",
                ),
            )
        elif cx.pytest_cmd:
            cx.checks.append(
                Check(
                    "pytest",
                    "tests/property/state",
                    cx.pytest_cmd,
                    lambda o, e, c: text_findings("pytest", o, e, c),
                    cx.timeout,
                    cx.root,
                    env=cx.pytest_env,
                    findings_exit_codes={1},
                ),
            )
        else:
            cx.skipped.append(
                Result(
                    "pytest",
                    "tests/property/state",
                    Status.SKIPPED,
                    note="pytest not installed",
                ),
            )
