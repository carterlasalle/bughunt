# Copyright (c) 2026 Carter LaSalle
"""Policy, complexity, and dependency check builders."""

from __future__ import annotations

import sys
from .checkctx import CheckBuildCx
from .probes import optional_cmd, generated_config
from .technology import target_executable
from .parsers import (
    parse_bandit,
    parse_complexipy,
    parse_json_list,
    parse_lizard,
    parse_radon_mi,
)


# trace:v1 id=impl.src-bughunt-checks-quality.-build-quality-checks work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def build_quality_checks(cx: CheckBuildCx) -> None:
    policy_cmd = [sys.executable, "-m", "bughunt.policy_scan", "--root", str(cx.root)]
    for path in cx.src:
        policy_cmd += ["--source", path]
    for path in cx.tests:
        policy_cmd += ["--test", path]
    cx.add(
        "policy",
        "repository-policy",
        policy_cmd,
        lambda o, e, c: parse_json_list("policy", o, e, c),
        findings_exit_codes={1},
    )
    metrics_cmd = [sys.executable, "-m", "bughunt.metrics_scan", "--root", str(cx.root)]
    for path in cx.src:
        metrics_cmd += ["--source", path]
    cx.add(
        "complexity",
        "complexity-budgets",
        metrics_cmd,
        lambda o, e, c: parse_json_list("complexity", o, e, c),
        findings_exit_codes={1},
    )
    complexipy = target_executable(cx.root, "complexipy")
    complexipy_cmd = (
        [
            complexipy,
            *cx.src,
            "--plain",
            "--failed",
            "--check-script",
            "--no-ignore",
            "--report-ignored",
            "--max-complexity-allowed",
            str(cx.cfg.complexity_limit("cognitive_max", 10)),
        ]
        if complexipy
        else None
    )
    cx.add(
        "complexipy",
        "cognitive-complexity",
        complexipy_cmd,
        parse_complexipy,
        reason="complexipy not installed",
        findings_exit_codes={1},
    )
    radon = target_executable(cx.root, "radon")
    radon_cmd = [radon, "mi", "-j", "-s", *cx.src] if radon else None
    cx.add(
        "radon",
        "maintainability",
        radon_cmd,
        parse_radon_mi,
        reason="radon not installed",
        findings_exit_codes=set(),
    )
    lizard = target_executable(cx.root, "lizard")
    lizard_cmd = (
        [
            lizard,
            "-w",
            "-C",
            str(cx.cfg.complexity_limit("cyclomatic_warn", 10)),
            "-L",
            str(cx.cfg.complexity_limit("function_loc_warn", 80)),
            "-a",
            "8",
            "-t",
            str(max(1, cx.cfg.max_parallel)),
            *cx.src,
        ]
        if lizard
        else None
    )
    cx.add(
        "lizard",
        "cross-language-complexity",
        lizard_cmd,
        parse_lizard,
        reason="lizard not installed",
        findings_exit_codes={1},
    )
    vulture_confidence = (
        "0" if cx.profile in {"deep", "all"} else ("60" if cx.profile == "pr" else "80")
    )
    # `caption` is rich's Table attribute (set, never read back); MAX_REVISITS
    # is a tripwire constant; dataclass fields look unused to vulture;
    # http.server calls do_GET/log_message via the framework, not our code.
    vulture_ignored = (
        "visit_[A-Z]*,caption,MAX_REVISITS,python_type,numeric_range,do_GET,log_message"
    )
    cx.add(
        "vulture",
        "dead-code",
        optional_cmd(
            target_executable(cx.root, "vulture"),
            [
                *cx.py,
                "--min-confidence",
                vulture_confidence,
                "--ignore-names",
                vulture_ignored,
            ],
        ),
        findings_exit_codes={3},
    )
    bandit_cfg = generated_config(cx.root, "bandit.yaml")
    bandit_cmd = optional_cmd(
        target_executable(cx.root, "bandit"), ["-r", *cx.src, "-f", "json", "-q"]
    )
    if bandit_cmd and bandit_cfg:
        bandit_cmd += ["-c", str(bandit_cfg)]
    cx.add(
        "bandit", "security", bandit_cmd, parse_bandit, reason="bandit not installed"
    )
