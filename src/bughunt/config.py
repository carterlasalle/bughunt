# Copyright (c) 2026 Carter LaSalle
"""Application configuration: constants, floors, and loading."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .discovery import infer_source_paths, infer_test_paths
from .technology import TECH_DEEP_TOOLS, TECH_PR_TOOLS

CONFIG_NAME = "bughunt.toml"
REPORT_DIR = ".bughunt/reports"
CACHE_DIR = ".bughunt/cache"


# Correctness floors are augmented at runtime so an old bughunt.toml cannot
# silently omit a defense introduced by a newer BugHunt release.
PR_CORRECTNESS_FLOOR = [
    "coverage",
    "seam",
    "semantic",
    "evidence",
    "packaging",
    "bugcorpus",
    "system-ir",
    "tracelayer",
    "verify-gaps",
    "protocol",
    "runtime-types",
    "doctest",
    "pydoclint",
    "refurb",
]
DEEP_CORRECTNESS_FLOOR = [
    *PR_CORRECTNESS_FLOOR,
    "pytest-random",
    "pytest-no-network",
    "pytest-xdist",
    "pytest-async-blocking",
    "hypofuzz",
    "griffe",
    "importtime",
    "type-disagreement",
]
ALL_CORRECTNESS_FLOOR = [
    *DEEP_CORRECTNESS_FLOOR,
    "pytest-parallel",
    "python-matrix",
    "timezone-matrix",
    "memray",
    "benchmark",
    "pyanalyze",
    "version-diff",
    "ghostwriter",
    "pynguin",
]


# trace:v1 id=impl.src-bughunt-cli.config work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
@dataclass(slots=True)
class Config:
    root: Path
    raw: dict[str, Any]

    # trace:v1 id=impl.src-bughunt-cli.project work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    @property
    def project(self) -> dict[str, Any]:
        project = self.raw.get("project", {})
        return project if isinstance(project, dict) else {}

    # trace:v1 id=impl.src-bughunt-config.max-parallel work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    @property
    def max_parallel(self) -> int:
        return int(self.raw.get("execution", {}).get("max_parallel", 6))

    # trace:v1 id=impl.src-bughunt-cli.config-skip work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    @property
    def skip(self) -> list[str]:
        """Defenses the repo opts out of, merged with `--skip`."""
        skipped = self.raw.get("execution", {}).get("skip", [])
        return [str(x) for x in skipped] if isinstance(skipped, list) else []

    # trace:v1 id=impl.src-bughunt-config.complexity-limit work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    def complexity_limit(self, key: str, default: int) -> int:
        """One complexity budget as int; non-dict/non-int config degrades to default."""
        section = self.raw.get("complexity", {})
        if not isinstance(section, dict):
            return default
        value = section.get(key, default)
        return value if isinstance(value, int) else default

    # trace:v1 id=impl.src-bughunt-config.timeout work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    def timeout(self, profile: str) -> int:
        timeouts = self.raw.get("timeouts", {})
        fallback = timeouts.get("deep", 900) if profile == "all" else 900
        return int(timeouts.get(profile, fallback))

    # trace:v1 id=impl.src-bughunt-cli-config.tools work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
    def tools(self, profile: str) -> list[str]:
        profiles = self.raw.get("profiles", {})
        configured: list[str] = [
            str(t) for t in profiles.get(profile, {}).get("tools", [])
        ]
        if not configured and profile == "all":
            # Backward compatibility with pre-`all` configs: maximal mode is the
            # union of every configured profile, preserving first-seen order.
            for data in profiles.values():
                for tool in data.get("tools", []):
                    name = str(tool)
                    if name not in configured:
                        configured.append(name)
        technology = (
            TECH_PR_TOOLS
            if profile == "pr"
            else (TECH_DEEP_TOOLS if profile in {"deep", "all"} else [])
        )
        floor = (
            PR_CORRECTNESS_FLOOR
            if profile == "pr"
            else (
                DEEP_CORRECTNESS_FLOOR
                if profile == "deep"
                else (ALL_CORRECTNESS_FLOOR if profile == "all" else [])
            )
        )
        for tool in floor:
            if tool not in configured:
                configured.append(tool)
        # Technology engines are a BugHunt correctness floor. Old project configs
        # cannot silently opt out merely because they predate the capability layer.
        for tool in technology:
            if tool not in configured:
                configured.append(tool)
        return configured

    # trace:v1 id=impl.src-bughunt-config.source-paths work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    @property
    def source_paths(self) -> list[str]:
        configured = list(self.project.get("source_paths", ["src"]))
        if configured and any((self.root / path).exists() for path in configured):
            return configured
        return infer_source_paths(self.root)

    # trace:v1 id=impl.src-bughunt-config.test-paths work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    @property
    def test_paths(self) -> list[str]:
        configured = list(self.project.get("test_paths", ["tests"]))
        if configured and any((self.root / path).exists() for path in configured):
            return configured
        return infer_test_paths(self.root)

    # trace:v1 id=impl.src-bughunt-cli-config.python-paths work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
    @property
    def python_paths(self) -> list[str]:
        configured = [
            path
            for path in self.project.get("python_paths", [])
            if (self.root / path).exists()
        ]
        # Always include the *effective* inferred source/test roots; a flat-layout
        # repo may have tests/ (making the default partially valid) while src/ is
        # absent, and must not silently omit the real package directory.
        return list(dict.fromkeys([*self.source_paths, *self.test_paths, *configured]))


# trace:v1 id=impl.src-bughunt-cli.-default-config-raw work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def default_config_raw() -> dict[str, Any]:
    raw: dict[str, Any] = {
        "project": {
            "python_paths": ["src", "tests"],
            "source_paths": ["src"],
            "test_paths": ["tests"],
        },
        "execution": {
            "max_parallel": 6,
            "fail_on": "findings",
            "raw_output_limit_kb": 512,
        },
        "timeouts": {"fast": 120, "pr": 900, "deep": 7200, "all": 14400},
        "profiles": {
            "fast": {
                "tools": ["compile", "ruff", "basedpyright", "mypy", "ty", "pyrefly"],
            },
            "pr": {
                "tools": [
                    "compile",
                    "ruff",
                    "basedpyright",
                    "mypy",
                    "ty",
                    "pyrefly",
                    "pylint",
                    "pylint-tests",
                    "complexity",
                    "complexipy",
                    "radon",
                    "lizard",
                    "policy",
                    "vulture",
                    "bandit",
                    "deptry",
                    "import-linter",
                    "ast-grep",
                    "semgrep",
                    "deal",
                    "crosshair",
                    "pytest",
                ],
            },
            "deep": {
                "tools": [
                    "compile",
                    "ruff",
                    "basedpyright",
                    "mypy",
                    "ty",
                    "pyrefly",
                    "pylint",
                    "complexity",
                    "pylint-tests",
                    "complexipy",
                    "radon",
                    "lizard",
                    "policy",
                    "vulture",
                    "bandit",
                    "deptry",
                    "import-linter",
                    "ast-grep",
                    "semgrep",
                    "codeql",
                    "pysa",
                    "deal",
                    "crosshair",
                    "pytest",
                    "mutmut",
                    "bugcorpus",
                    "system-ir",
                    "semantic",
                    "tracelayer",
                    "verify-gaps",
                    "protocol",
                    "schemathesis",
                    "atheris",
                    "custom",
                ],
            },
            "all": {
                "tools": [
                    "compile",
                    "ruff",
                    "basedpyright",
                    "mypy",
                    "ty",
                    "pyrefly",
                    "pylint",
                    "complexity",
                    "complexipy",
                    "pylint-tests",
                    "radon",
                    "lizard",
                    "policy",
                    "vulture",
                    "bandit",
                    "deptry",
                    "import-linter",
                    "ast-grep",
                    "semgrep",
                    "codeql",
                    "pysa",
                    "deal",
                    "crosshair",
                    "pytest",
                    "mutmut",
                    "bugcorpus",
                    "system-ir",
                    "semantic",
                    "tracelayer",
                    "verify-gaps",
                    "protocol",
                    "schemathesis",
                    "atheris",
                    "custom",
                ],
            },
        },
        "autodiscovery": {
            "enabled": True,
            "atheris_runs": 500000,
            "schemathesis_max_examples": 1000,
        },
        "complexity": {
            "cyclomatic_warn": 10,
            "cyclomatic_error": 20,
            "cognitive_max": 10,
            "function_loc_warn": 80,
            "function_loc_error": 150,
            "file_loc_warn": 500,
            "file_loc_error": 1200,
            "abc_warn": 30,
            "abc_error": 45,
            "js_file_kb_warn": 500,
            "css_file_kb_warn": 250,
            "wasm_file_kb_warn": 2000,
            "bundle_kb_warn": 1500,
        },
        "semgrep": {
            "configs": ["p/default"],
            "security_configs": ["p/security-audit", "p/secrets"],
            "include_security": False,
        },
        "codeql": {
            "languages": ["python"],
            "python_suite": (
                "codeql/python-queries:codeql-suites/python-security-and-quality.qls"
            ),
        },
        "pysa": {"no_verify": False},
        "mutmut": {"enabled": True},
        "bugcorpus": {"enabled": True},
        "coverage": {"branch": True},
        "tests": {"timeout_seconds": 300, "repro_seed": 1, "randomized": True},
        "hypofuzz": {"deep_seconds": 120, "all_seconds": 300, "workers": 2},
        "performance": {
            "import_ms_warn": 1000,
            "benchmark_regression_percent": 10,
            "memray": True,
        },
        "execution_imports": {"allow_importing_analyzers": False},
    }
    for profile, floor in (
        ("pr", PR_CORRECTNESS_FLOOR),
        ("deep", DEEP_CORRECTNESS_FLOOR),
        ("all", ALL_CORRECTNESS_FLOOR),
    ):
        for name in floor:
            if name not in raw["profiles"][profile]["tools"]:
                raw["profiles"][profile]["tools"].append(name)
    for name in TECH_PR_TOOLS:
        if name not in raw["profiles"]["pr"]["tools"]:
            raw["profiles"]["pr"]["tools"].append(name)
    for profile in ("deep", "all"):
        for name in TECH_DEEP_TOOLS:
            if name not in raw["profiles"][profile]["tools"]:
                raw["profiles"][profile]["tools"].append(name)
    return raw


# trace:v1 id=impl.src-bughunt-config.deep-merge work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


# trace:v1 id=impl.src-bughunt-config.load-config work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def load_config(root: Path, config_path: Path | None = None) -> Config:
    path = config_path or (root / CONFIG_NAME)
    raw = default_config_raw()
    if path.exists():
        raw = deep_merge(raw, tomllib.loads(path.read_text()))
    return Config(root=root, raw=raw)
