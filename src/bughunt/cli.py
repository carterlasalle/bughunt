from __future__ import annotations

import argparse
import asyncio
import dataclasses
import datetime as dt
import hashlib
import importlib.util
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import tomllib
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from enum import Enum
from functools import partial
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.live import Live
from rich.markup import escape
from rich.panel import Panel
from rich.progress_bar import ProgressBar
from rich.table import Table
from rich.text import Text

from bughunt.default_rules import DEFAULT_RULES

from .configurator import _JS_TOOL_IGNORES, configure_all, configure_custom_checks
from .discovery import (
    discover_all,
    infer_source_paths,
    infer_test_paths,
    load_generated_targets,
)
from .installers import install_all
from .technology import (
    ENGINE_CAPABILITY,
    ENGINE_CATEGORY,
    discover_technologies,
    engine_applicable,
    git_path_exists,
    llvm_executable,
    load_technology_inventory,
    project_executable,
    target_executable,
    target_has_module,
    target_python,
)

APP = "BugHunt"
CONFIG_NAME = "bughunt.toml"
REPORT_DIR = ".bughunt/reports"
CACHE_DIR = ".bughunt/cache"

console = Console()

TECH_PR_TOOLS = [
    "actionlint",
    "shellcheck",
    "dotenv-linter",
    "oasdiff",
    "buf",
    "sqlfluff",
    "squawk",
    "hadolint",
    "tflint",
    "golangci-lint",
    "clippy",
    "cppcheck",
    "phpstan",
    "oxlint",
    "eslint",
    "react-doctor",
    "tsc",
    "knip",
    "madge",
    "publint",
    "taplo",
    "yamllint",
    "check-jsonschema",
    "alembic-check",
    "django-migrations",
]
TECH_DEEP_TOOLS = [*TECH_PR_TOOLS, "clang-tidy", "infer", "pact-contracts"]

# Correctness floors are augmented at runtime so an old bughunt.toml cannot
# silently omit a defense introduced by a newer BugHunt release.
PR_CORRECTNESS_FLOOR = [
    "coverage",
    "seam",
    "evidence",
    "packaging",
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

# These defenses operate specifically on Python source or Python's runtime/test
# ecosystem. They are N/A in repositories where no first-party Python capability
# exists; N/A never lowers defense health. Lizard and Semgrep are intentionally
# excluded because they can analyze multiple languages, while Schemathesis can
# exercise an OpenAPI contract independently of the implementation language.
PYTHON_ONLY_TOOLS = {
    "compile",
    "ruff",
    "basedpyright",
    "mypy",
    "ty",
    "pyrefly",
    "pylint",
    "policy",
    "complexipy",
    "radon",
    "vulture",
    "bandit",
    "deptry",
    "import-linter",
    "ast-grep",
    "deal",
    "crosshair",
    "pytest",
    "codeql",
    "pysa",
    "mutmut",
    "atheris",
    "coverage",
    "seam",
    "evidence",
    "packaging",
    "runtime-types",
    "doctest",
    "pydoclint",
    "refurb",
    "pytest-random",
    "pytest-no-network",
    "pytest-xdist",
    "pytest-async-blocking",
    "pytest-parallel",
    "hypofuzz",
    "griffe",
    "importtime",
    "type-disagreement",
    "python-matrix",
    "timezone-matrix",
    "memray",
    "benchmark",
    "pyanalyze",
    "version-diff",
    "ghostwriter",
    "pynguin",
}


class Status(str, Enum):
    PASS = "PASS"
    FINDINGS = "FINDINGS"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"
    NA = "N/A"


# trace:v1 id=impl.src-bughunt-cli.finding work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
@dataclass(slots=True)
class Finding:
    tool: str
    message: str
    path: str | None = None
    line: int | None = None
    column: int | None = None
    code: str | None = None
    severity: str = "error"
    fixable: bool = False
    fix_safety: str | None = None
    fix_preview: str | None = None

    # trace:v1 id=impl.src-bughunt-cli.finding.fingerprint work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    @property
    def fingerprint(self) -> str:
        raw = "|".join(
            [
                self.tool,
                self.code or "",
                self.path or "",
                self.message.strip(),
            ],
        )
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    # trace:v1 id=impl.src-bughunt-cli.finding.signal-key work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    @property
    def signal_key(self) -> str:
        """Group repeated manifestations without merging unrelated diagnostics."""
        msg = self.message.lower()
        if self.tool == "mutmut":
            # Mutation IDs encode a specific mutant number. Group survivors by
            # owning function so the report says "42 survivors in foo" rather
            # than manufacturing 42 unrelated signal families.
            msg = re.sub(r"__mutmut_\d+.*$", "__mutmut_<n>", msg)
        msg = re.sub(r"`[^`]+`", "`<symbol>`", msg)
        msg = re.sub(r"(?:[A-Za-z]:)?[/\\][^\s:]+", "<path>", msg)
        msg = re.sub(r"\b0x[0-9a-f]+\b", "<hex>", msg)
        msg = re.sub(r"\b\d+(?:\.\d+)?\b", "<n>", msg)
        msg = re.sub(r"\s+", " ", msg).strip()
        code = str(self.code) if self.code is not None else ""
        # Some tools emit placeholder/generic codes (mypy ``misc`` and older
        # Pyrefly JSON's numeric negative codes). Those are not meaningful bug
        # families, so include the normalized diagnostic shape as well.
        generic = not code or code.lower() in {"misc", "unknown", "none", "-1", "-2"}
        if generic:
            prefix = f"{self.tool}:{code}:" if code else f"{self.tool}:"
            return prefix + msg[:180]
        return f"{self.tool}:{code}"

    @property
    def finding_id(self) -> str:
        return f"BH-{self.fingerprint.upper()}"


@dataclass(slots=True)
class Result:
    name: str
    category: str
    status: Status
    duration: float = 0.0
    exit_code: int | None = None
    findings: list[Finding] = field(default_factory=list)
    command: list[str] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    note: str | None = None
    artifacts: list[str] = field(default_factory=list)
    environment: dict[str, str] = field(default_factory=dict)

    @property
    def count(self) -> int:
        return len(self.findings)


# trace:v1 id=impl.src-bughunt-cli.check work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
@dataclass(slots=True)
class Check:
    name: str
    category: str
    command: list[str]
    parser: Callable[[str, str, int], list[Finding]]
    timeout: int
    cwd: Path
    env: dict[str, str] | None = None
    configured: bool = True
    skip_reason: str | None = None
    findings_exit_codes: set[int] = field(default_factory=lambda: {1})
    skip_exit_codes: set[int] = field(default_factory=set)
    # Banner substrings proving the tool ran but had nothing in scope (as
    # opposed to erroring). When the exit code is a findings code yet the
    # parser yields nothing and a marker is present, the result is SKIPPED
    # ("nothing in scope") instead of a synthetic FINDINGS entry.
    empty_scope_markers: tuple[str, ...] = ()
    record_progress: bool = True
    timeout_is_success: bool = False


# trace:v1 id=impl.src-bughunt-cli.config work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
@dataclass(slots=True)
class Config:
    root: Path
    raw: dict[str, Any]

    @property
    def project(self) -> dict[str, Any]:
        return self.raw.get("project", {})

    @property
    def max_parallel(self) -> int:
        return int(self.raw.get("execution", {}).get("max_parallel", 6))

    def timeout(self, profile: str) -> int:
        timeouts = self.raw.get("timeouts", {})
        fallback = timeouts.get("deep", 900) if profile == "all" else 900
        return int(timeouts.get(profile, fallback))

    # trace:v1 id=impl.src-bughunt-cli-config.tools work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
    def tools(self, profile: str) -> list[str]:
        profiles = self.raw.get("profiles", {})
        configured = list(profiles.get(profile, {}).get("tools", []))
        if not configured and profile == "all":
            # Backward compatibility with pre-`all` configs: maximal mode is the
            # union of every configured profile, preserving first-seen order.
            for data in profiles.values():
                for tool in data.get("tools", []):
                    if tool not in configured:
                        configured.append(tool)
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

    @property
    def source_paths(self) -> list[str]:
        configured = list(self.project.get("source_paths", ["src"]))
        if any((self.root / path).exists() for path in configured):
            return configured
        return infer_source_paths(self.root)

    @property
    def test_paths(self) -> list[str]:
        configured = list(self.project.get("test_paths", ["tests"]))
        if any((self.root / path).exists() for path in configured):
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
def _default_config_raw() -> dict[str, Any]:
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


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_config(root: Path, config_path: Path | None = None) -> Config:
    path = config_path or (root / CONFIG_NAME)
    raw = _default_config_raw()
    if path.exists():
        raw = _deep_merge(raw, tomllib.loads(path.read_text()))
    return Config(root=root, raw=raw)


# trace:exempt reason=internal-detail
def _optional_cmd(exe: str | None, args: Sequence[str]) -> list[str] | None:
    """Build a tool command when the executable resolved; None (SKIP) otherwise."""
    return [exe, *args] if exe else None


def executable(*names: str) -> str | None:
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    return None


def python_module_available(name: str) -> bool:
    """Check import availability without importing/triggering module side effects."""
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, AttributeError, ValueError):
        return False


# trace:v1 id=impl.src-bughunt-cli.atheris-available work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def atheris_available(root: Path) -> bool:
    if python_module_available("atheris"):
        return True
    runtime = root / ".bughunt" / "runtime" / "atheris"
    return (
        (runtime / "atheris").exists() or any(runtime.glob("atheris*.so"))
        if runtime.exists()
        else False
    )


def ast_grep_executable() -> str | None:
    """Find ast-grep without mistaking util-linux `sg` for ast-grep."""
    direct = shutil.which("ast-grep")
    if direct:
        return direct
    sg = shutil.which("sg")
    if not sg:
        return None
    try:
        probe = subprocess.run(
            [sg, "--version"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    banner = (probe.stdout + "\n" + probe.stderr).lower()
    return sg if "ast-grep" in banner else None


def existing_paths(root: Path, values: Iterable[str]) -> list[str]:
    out = [value for value in values if (root / value).exists()]
    return out or ["."]


def generated_config(root: Path, name: str) -> Path | None:
    path = root / ".bughunt" / "configs" / name
    return path if path.exists() else None


def analysis_scope(root: Path, values: Iterable[str]) -> list[str]:
    """Return first-party paths only; never fall back into .bughunt/runtime."""
    paths = existing_paths(root, values)
    if paths == ["."]:
        # `.` is still safe because every broad scanner gets explicit excludes,
        # but prefer real Python files/dirs when inference can find them.
        candidates = [x for x in ("src", "lib", "app", "tests") if (root / x).exists()]
        return candidates or ["."]
    return paths


def import_linter_configured(root: Path) -> bool:
    """Return True only when Import Linter has an actual project config.

    Import Linter searches .importlinter, setup.cfg, and pyproject.toml, but an
    installed CLI with no root package/contracts is a configuration gap, not a
    code finding.
    """
    ini = root / ".importlinter"
    if ini.exists() and "[importlinter" in ini.read_text(errors="ignore"):
        return True
    setup_cfg = root / "setup.cfg"
    if setup_cfg.exists() and "[importlinter" in setup_cfg.read_text(errors="ignore"):
        return True
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        try:
            data = tomllib.loads(pyproject.read_text())
        except (OSError, tomllib.TOMLDecodeError):
            return False
        tool = data.get("tool", {})
        return isinstance(tool, dict) and isinstance(tool.get("importlinter"), dict)
    return False


# trace:v1 id=impl.src-bughunt-cli.text-findings work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def text_findings(tool: str, stdout: str, stderr: str, exit_code: int) -> list[Finding]:
    if exit_code == 0:
        return []
    lines = (stdout + "\n" + stderr).splitlines()
    findings: list[Finding] = []
    patterns = [
        re.compile(
            r"^(?P<path>.+?):(?P<line>\d+):(?P<col>\d+):\s*(?:(?P<severity>error|warning|note):\s*)?(?P<msg>.+)$",
            re.IGNORECASE,
        ),
        re.compile(
            r"^(?P<path>.+?):(?P<line>\d+):\s*(?:(?P<severity>error|warning|note):\s*)?(?P<msg>.+)$",
            re.IGNORECASE,
        ),
    ]
    for line in lines:
        for pat in patterns:
            m = pat.match(line.strip())
            if not m:
                continue
            gd = m.groupdict()
            message = gd.get("msg", line).strip()
            code = None
            code_match = re.search(r"\s+\[([A-Za-z0-9_.-]+)\]$", message)
            if code_match:
                code = code_match.group(1)
                message = message[: code_match.start()].rstrip()
            findings.append(
                Finding(
                    tool=tool,
                    path=gd.get("path"),
                    line=int(gd["line"]) if gd.get("line") else None,
                    column=int(gd["col"]) if gd.get("col") else None,
                    code=code,
                    message=message,
                    severity=(gd.get("severity") or "error").lower(),
                ),
            )
            break
    if not findings:
        # A failing analysis with no parseable location is still a finding-like
        # signal, but tool crashes are classified separately by the runner.
        meaningful = next((x.strip() for x in reversed(lines) if x.strip()), "")
        if meaningful:
            findings.append(Finding(tool=tool, message=meaningful[:1000]))
    return findings


# trace:v1 id=impl.src-bughunt-cli.parse-ruff work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def parse_ruff(stdout: str, stderr: str, exit_code: int) -> list[Finding]:
    try:
        data = json.loads(stdout or "[]")
    except json.JSONDecodeError:
        return text_findings("ruff", stdout, stderr, exit_code)
    out = []
    for item in data:
        loc = item.get("location", {})
        code = item.get("code")
        severity = "error"
        # ALL really means ALL. Presentation/convention diagnostics are retained,
        # but ranked below likely correctness/security findings in agent queues.
        if code and (
            code.startswith(
                ("D", "COM", "Q", "I", "N", "PTH", "T20", "TD", "FIX", "ERA", "EM"),
            )
            or code in {"E501", "W505"}
        ):
            severity = "note"
        fix = item.get("fix") if isinstance(item, dict) else None
        applicability = None
        preview = None
        if isinstance(fix, dict):
            applicability = str(fix.get("applicability") or "unknown").lower()
            preview = fix.get("message")
        out.append(
            Finding(
                tool="ruff",
                path=item.get("filename"),
                line=loc.get("row"),
                column=loc.get("column"),
                code=code,
                message=item.get("message", "Ruff finding"),
                severity=severity,
                fixable=isinstance(fix, dict),
                fix_safety=applicability,
                fix_preview=str(preview) if preview else None,
            ),
        )
    return out


# trace:v1 id=impl.src-bughunt-cli.parse-basedpyright work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def parse_basedpyright(stdout: str, stderr: str, exit_code: int) -> list[Finding]:
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return text_findings("basedpyright", stdout, stderr, exit_code)
    out = []
    for item in data.get("generalDiagnostics", []):
        start = item.get("range", {}).get("start", {})
        out.append(
            Finding(
                tool="basedpyright",
                path=item.get("file"),
                line=(start.get("line") + 1)
                if isinstance(start.get("line"), int)
                else None,
                column=(start.get("character") + 1)
                if isinstance(start.get("character"), int)
                else None,
                code=item.get("rule"),
                message=item.get("message", "Type error"),
                severity=item.get("severity", "error"),
            ),
        )
    return out


# trace:v1 id=impl.src-bughunt-cli.parse-json-list work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def parse_json_list(
    tool: str,
    stdout: str,
    stderr: str,
    exit_code: int,
) -> list[Finding]:
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return text_findings(tool, stdout, stderr, exit_code)

    if isinstance(data, dict):
        # Common wrappers.
        for key in ("results", "errors", "issues", "diagnostics", "messages"):
            if isinstance(data.get(key), list):
                data = data[key]
                break
        else:
            data = []

    out: list[Finding] = []
    for item in data if isinstance(data, list) else []:
        if not isinstance(item, dict):
            continue
        start = item.get("start") or item.get("location") or {}
        if isinstance(start, dict) and "start" in start:
            start = start.get("start", {})
        path = item.get("path") or item.get("file") or item.get("filename")
        if isinstance(path, dict):
            path = path.get("path")
        msg = (
            item.get("message")
            or item.get("description")
            or item.get("name")
            or str(item)
        )
        code = (
            item.get("code")
            or item.get("rule")
            or item.get("check_id")
            or item.get("message-id")
            or item.get("symbol")
        )
        line = item.get("line")
        col = item.get("column")
        if isinstance(start, dict):
            line = line or start.get("line") or start.get("row")
            col = col or start.get("column") or start.get("col")
        out.append(
            Finding(
                tool=tool,
                path=str(path) if path else None,
                line=int(line) if isinstance(line, int) else None,
                column=int(col) if isinstance(col, int) else None,
                code=str(code) if code else None,
                message=str(msg),
                severity=str(
                    item.get("severity") or item.get("type") or "error",
                ).lower(),
            ),
        )
    if not out and exit_code:
        return text_findings(tool, stdout, stderr, exit_code)
    return out


# trace:v1 id=impl.src-bughunt-cli.parse-pyrefly work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def parse_pyrefly(stdout: str, stderr: str, exit_code: int) -> list[Finding]:
    """Parse Pyrefly JSON using the diagnostic *name*, not its internal numeric code."""
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return text_findings("pyrefly", stdout, stderr, exit_code)
    if isinstance(data, dict):
        for key in ("errors", "diagnostics", "results", "messages"):
            if isinstance(data.get(key), list):
                data = data[key]
                break
    out: list[Finding] = []
    for item in data if isinstance(data, list) else []:
        if not isinstance(item, dict):
            continue
        start = item.get("start") or item.get("location") or {}
        if isinstance(start, dict) and isinstance(start.get("start"), dict):
            start = start["start"]
        path = item.get("path") or item.get("file") or item.get("filename")
        if isinstance(path, dict):
            path = path.get("path") or path.get("uri")
        name = item.get("name") or item.get("rule") or item.get("check_id")
        internal = item.get("code")
        out.append(
            Finding(
                tool="pyrefly",
                path=str(path) if path else None,
                line=(
                    item.get("line")
                    or (start.get("line") if isinstance(start, dict) else None)
                ),
                column=(
                    item.get("column")
                    or (start.get("column") if isinstance(start, dict) else None)
                ),
                code=str(name or internal)
                if (name is not None or internal is not None)
                else None,
                message=str(
                    item.get("message")
                    or item.get("description")
                    or name
                    or "Pyrefly finding",
                ),
                severity=str(
                    item.get("severity") or item.get("type") or "error",
                ).lower(),
            ),
        )
    return out or (
        text_findings("pyrefly", stdout, stderr, exit_code) if exit_code else []
    )


# trace:v1 id=impl.src-bughunt-cli.parse-pylint work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def parse_pylint(stdout: str, stderr: str, exit_code: int) -> list[Finding]:
    """Parse Pylint JSON2, ranking convention/refactor/info below bug diagnostics."""
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return text_findings("pylint", stdout, stderr, exit_code)
    if isinstance(data, dict):
        data = data.get("messages", data.get("results", []))
    out: list[Finding] = []
    for item in data if isinstance(data, list) else []:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("type") or item.get("category") or "error").lower()
        severity = {
            "fatal": "error",
            "error": "error",
            "warning": "warning",
            "refactor": "note",
            "convention": "note",
            "info": "note",
        }.get(kind, "warning")
        out.append(
            Finding(
                tool="pylint",
                path=item.get("path") or item.get("abspath") or item.get("module"),
                line=item.get("line"),
                column=item.get("column"),
                code=item.get("symbol")
                or item.get("message-id")
                or item.get("messageId"),
                message=str(item.get("message") or "Pylint finding"),
                severity=severity,
            ),
        )
    return out or (
        text_findings("pylint", stdout, stderr, exit_code) if exit_code else []
    )


# trace:v1 id=impl.src-bughunt-cli.parse-deptry work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def parse_deptry(stdout: str, stderr: str, exit_code: int) -> list[Finding]:
    """Parse deptry's text output, including pyproject findings without line numbers."""
    out: list[Finding] = []
    pattern = re.compile(
        r"^(?P<path>.+?)(?::(?P<line>\d+):(?P<col>\d+))?:\s+"
        r"(?P<code>DEP\d{3})\s+(?P<msg>.+)$",
    )
    for raw in (stdout + "\n" + stderr).splitlines():
        m = pattern.match(raw.strip())
        if not m:
            continue
        gd = m.groupdict()
        out.append(
            Finding(
                tool="deptry",
                path=gd["path"],
                line=int(gd["line"]) if gd.get("line") else None,
                column=int(gd["col"]) if gd.get("col") else None,
                code=gd["code"],
                message=gd["msg"],
                severity="error",
            ),
        )
    return out or text_findings("deptry", stdout, stderr, exit_code)


# trace:v1 id=impl.src-bughunt-cli.parse-semgrep work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def parse_semgrep(stdout: str, stderr: str, exit_code: int) -> list[Finding]:
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return text_findings("semgrep", stdout, stderr, exit_code)
    out = []
    for item in data.get("results", []):
        extra = item.get("extra", {})
        start = item.get("start", {})
        out.append(
            Finding(
                tool="semgrep",
                path=item.get("path"),
                line=start.get("line"),
                column=start.get("col"),
                code=item.get("check_id"),
                message=extra.get("message", "Semgrep finding"),
                severity=str(extra.get("severity", "error")).lower(),
                fixable=bool(extra.get("fix")),
                fix_safety="rule" if extra.get("fix") else None,
                fix_preview=str(extra.get("fix"))[:500] if extra.get("fix") else None,
            ),
        )
    return out


# trace:v1 id=impl.src-bughunt-cli.parse-deal work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def parse_deal(stdout: str, stderr: str, exit_code: int) -> list[Finding]:
    """Parse `python -m deal lint --json` JSON-lines output."""
    out: list[Finding] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        out.append(
            Finding(
                tool="deal",
                path=item.get("filename") or item.get("path"),
                line=item.get("row") or item.get("line"),
                column=item.get("col") or item.get("column"),
                code=item.get("code"),
                message=item.get("text")
                or item.get("message")
                or item.get("value")
                or "Deal contract finding",
                severity="error",
            ),
        )
    if out:
        return out
    return text_findings("deal", stdout, stderr, exit_code)


def parse_bandit(stdout: str, stderr: str, exit_code: int) -> list[Finding]:
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return text_findings("bandit", stdout, stderr, exit_code)
    return [
        Finding(
            tool="bandit",
            path=i.get("filename"),
            line=i.get("line_number"),
            column=i.get("col_offset"),
            code=i.get("test_id"),
            message=i.get("issue_text", "Bandit finding"),
            severity=str(i.get("issue_severity", "error")).lower(),
        )
        for i in data.get("results", [])
    ]


# trace:v1 id=impl.src-bughunt-cli.parse-ast-grep work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def parse_ast_grep(stdout: str, stderr: str, exit_code: int) -> list[Finding]:
    try:
        data = json.loads(stdout or "[]")
    except json.JSONDecodeError:
        return text_findings("ast-grep", stdout, stderr, exit_code)
    out = []
    for i in data:
        rng = i.get("range", {})
        start = rng.get("start", {})
        out.append(
            Finding(
                tool="ast-grep",
                path=i.get("file"),
                line=(start.get("line") + 1)
                if isinstance(start.get("line"), int)
                else None,
                column=(start.get("column") + 1)
                if isinstance(start.get("column"), int)
                else None,
                code=i.get("ruleId"),
                message=i.get("message") or i.get("text") or "ast-grep finding",
            ),
        )
    return out


# trace:v1 id=impl.src-bughunt-cli.parse-complexipy work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def parse_complexipy(stdout: str, stderr: str, exit_code: int) -> list[Finding]:
    out: list[Finding] = []
    for line in (stdout + "\n" + stderr).splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("Analyzing", "Summary", "─", "=")):
            continue
        match = re.match(
            r"^(?P<path>.+?\.py)\s+(?P<name>\S+)\s+(?P<score>\d+)\s*$",
            stripped,
        )
        if not match:
            continue
        score = int(match.group("score"))
        out.append(
            Finding(
                tool="complexipy",
                path=match.group("path"),
                code="COG001",
                message=(
                    f"`{match.group('name')}` cognitive complexity is {score} "
                    "(budget 10)"
                ),
                severity="warning" if score <= 20 else "error",
            ),
        )
    if not out and exit_code not in {0, 1}:
        return text_findings("complexipy", stdout, stderr, exit_code)
    return out


# trace:v1 id=impl.src-bughunt-cli.parse-radon-mi work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def parse_radon_mi(stdout: str, stderr: str, exit_code: int) -> list[Finding]:
    try:
        data = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        return text_findings("radon", stdout, stderr, exit_code)
    out: list[Finding] = []
    if not isinstance(data, dict):
        return out
    for path, item in data.items():
        if not isinstance(item, dict):
            continue
        mi = item.get("mi")
        rank = item.get("rank")
        if not isinstance(mi, (int, float)) or mi > 19:
            continue
        out.append(
            Finding(
                tool="radon",
                path=str(path),
                code="RADON_MI",
                message=f"maintainability index is {mi:.1f} (rank {rank or '?'})",
                severity="error" if mi <= 9 else "warning",
            ),
        )
    return out


# trace:v1 id=impl.src-bughunt-cli.parse-lizard work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def parse_lizard(stdout: str, stderr: str, exit_code: int) -> list[Finding]:
    out: list[Finding] = []
    pattern = re.compile(
        r"^(?P<path>.+?):(?P<line>\d+):\s*warning:\s*(?P<msg>.+)$",
        re.IGNORECASE,
    )
    for line in (stdout + "\n" + stderr).splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        msg = match.group("msg")
        code = (
            "LIZARD_CCN"
            if "CCN" in msg
            else ("LIZARD_NLOC" if "NLOC" in msg else "LIZARD")
        )
        out.append(
            Finding(
                tool="lizard",
                path=match.group("path"),
                line=int(match.group("line")),
                code=code,
                message=msg,
                severity="warning",
            ),
        )
    if not out and exit_code not in {0, 1}:
        return text_findings("lizard", stdout, stderr, exit_code)
    return out


def _severity(value: object, default: str = "error") -> str:
    raw = str(value or default).lower()
    if raw in {"fatal", "critical", "high", "error"}:
        return "error"
    if raw in {"warn", "warning", "medium"}:
        return "warning"
    if raw in {"info", "information", "note", "low", "style"}:
        return "note"
    return default


# trace:v1 id=impl.src-bughunt-cli.parse-actionlint work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def parse_actionlint(stdout: str, stderr: str, exit_code: int) -> list[Finding]:
    """Parse actionlint's one-JSON-object-per-diagnostic formatter."""
    out: list[Finding] = []
    for line in stdout.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        out.append(
            Finding(
                tool="actionlint",
                path=item.get("filepath") or item.get("file"),
                line=item.get("line"),
                column=item.get("column") or item.get("col"),
                code=item.get("kind") or item.get("code"),
                message=str(item.get("message") or "GitHub Actions workflow problem"),
                severity="error",
            ),
        )
    return out or (
        text_findings("actionlint", stdout, stderr, exit_code) if exit_code else []
    )


# trace:v1 id=impl.src-bughunt-cli.parse-shellcheck work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def parse_shellcheck(stdout: str, stderr: str, exit_code: int) -> list[Finding]:
    try:
        data = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        return text_findings("shellcheck", stdout, stderr, exit_code)
    comments = data.get("comments", []) if isinstance(data, dict) else data
    out: list[Finding] = []
    for item in comments if isinstance(comments, list) else []:
        if not isinstance(item, dict):
            continue
        out.append(
            Finding(
                tool="shellcheck",
                path=item.get("file"),
                line=item.get("line"),
                column=item.get("column"),
                code=f"SC{item.get('code')}" if item.get("code") is not None else None,
                message=str(item.get("message") or "ShellCheck finding"),
                severity=_severity(item.get("level"), "warning"),
            ),
        )
    return out or (
        text_findings("shellcheck", stdout, stderr, exit_code) if exit_code else []
    )


# trace:v1 id=impl.src-bughunt-cli.parse-sqlfluff work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def parse_sqlfluff(stdout: str, stderr: str, exit_code: int) -> list[Finding]:
    try:
        data = json.loads(stdout or "[]")
    except json.JSONDecodeError:
        return text_findings("sqlfluff", stdout, stderr, exit_code)
    out: list[Finding] = []
    for file_item in data if isinstance(data, list) else []:
        if not isinstance(file_item, dict):
            continue
        path = file_item.get("filepath") or file_item.get("path")
        for item in file_item.get("violations", []) or []:
            if not isinstance(item, dict):
                continue
            out.append(
                Finding(
                    tool="sqlfluff",
                    path=str(path) if path else None,
                    line=item.get("start_line_no") or item.get("line_no"),
                    column=item.get("start_line_pos") or item.get("line_pos"),
                    code=item.get("code"),
                    message=str(
                        item.get("description")
                        or item.get("message")
                        or "SQLFluff finding",
                    ),
                    severity="error",
                ),
            )
    return out or (
        text_findings("sqlfluff", stdout, stderr, exit_code) if exit_code else []
    )


# trace:v1 id=impl.src-bughunt-cli.parse-hadolint work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def parse_hadolint(stdout: str, stderr: str, exit_code: int) -> list[Finding]:
    try:
        data = json.loads(stdout or "[]")
    except json.JSONDecodeError:
        return text_findings("hadolint", stdout, stderr, exit_code)
    return (
        [
            Finding(
                tool="hadolint",
                path=item.get("file"),
                line=item.get("line"),
                column=item.get("column"),
                code=item.get("code"),
                message=str(item.get("message") or "Hadolint finding"),
                severity=_severity(item.get("level"), "warning"),
            )
            for item in data
            if isinstance(item, dict)
        ]
        if isinstance(data, list)
        else text_findings("hadolint", stdout, stderr, exit_code)
    )


# trace:v1 id=impl.src-bughunt-cli.parse-tflint work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def parse_tflint(stdout: str, stderr: str, exit_code: int) -> list[Finding]:
    try:
        data = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        return text_findings("tflint", stdout, stderr, exit_code)
    out: list[Finding] = []
    for item in data.get("issues", []) if isinstance(data, dict) else []:
        if not isinstance(item, dict):
            continue
        rule = item.get("rule") or {}
        rng = item.get("range") or {}
        start = rng.get("start") or {}
        out.append(
            Finding(
                tool="tflint",
                path=rng.get("filename") or item.get("filename"),
                line=start.get("line"),
                column=start.get("column"),
                code=rule.get("name") if isinstance(rule, dict) else None,
                message=str(item.get("message") or "TFLint finding"),
                severity=_severity(
                    rule.get("severity") if isinstance(rule, dict) else None,
                    "warning",
                ),
            ),
        )
    return out or (
        text_findings("tflint", stdout, stderr, exit_code) if exit_code else []
    )


# trace:v1 id=impl.src-bughunt-cli.parse-golangci work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def parse_golangci(stdout: str, stderr: str, exit_code: int) -> list[Finding]:
    try:
        data = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        return text_findings("golangci-lint", stdout, stderr, exit_code)
    issues = (
        data.get("Issues", data.get("issues", [])) if isinstance(data, dict) else []
    )
    out: list[Finding] = []
    for item in issues if isinstance(issues, list) else []:
        if not isinstance(item, dict):
            continue
        pos = item.get("Pos") or item.get("pos") or {}
        out.append(
            Finding(
                tool="golangci-lint",
                path=pos.get("Filename") or pos.get("filename"),
                line=pos.get("Line") or pos.get("line"),
                column=pos.get("Column") or pos.get("column"),
                code=item.get("FromLinter")
                or item.get("fromLinter")
                or item.get("linter"),
                message=str(
                    item.get("Text") or item.get("text") or "Go correctness finding",
                ),
                severity="error",
            ),
        )
    return out or (
        text_findings("golangci-lint", stdout, stderr, exit_code) if exit_code else []
    )


# trace:v1 id=impl.src-bughunt-cli.parse-clippy work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def parse_clippy(stdout: str, stderr: str, exit_code: int) -> list[Finding]:
    out: list[Finding] = []
    for line in stdout.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict) or item.get("reason") != "compiler-message":
            continue
        msg = item.get("message") or {}
        if not isinstance(msg, dict) or msg.get("level") not in {"error", "warning"}:
            continue
        spans = msg.get("spans") or []
        primary = next(
            (x for x in spans if isinstance(x, dict) and x.get("is_primary")),
            {},
        )
        code_obj = msg.get("code") or {}
        out.append(
            Finding(
                tool="clippy",
                path=primary.get("file_name"),
                line=primary.get("line_start"),
                column=primary.get("column_start"),
                code=code_obj.get("code") if isinstance(code_obj, dict) else None,
                message=str(msg.get("message") or "Clippy finding"),
                severity=_severity(msg.get("level")),
            ),
        )
    return out or (
        text_findings("clippy", stdout, stderr, exit_code) if exit_code else []
    )


# trace:v1 id=impl.src-bughunt-cli.parse-cppcheck work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def parse_cppcheck(stdout: str, stderr: str, exit_code: int) -> list[Finding]:
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(stderr.strip())
    except ET.ParseError:
        return text_findings("cppcheck", stdout, stderr, exit_code)
    out: list[Finding] = []
    for error in root.findall(".//error"):
        locations = error.findall("location")
        loc = locations[0] if locations else None
        out.append(
            Finding(
                tool="cppcheck",
                path=loc.get("file") if loc is not None else None,
                line=int(str(loc.get("line")))
                if loc is not None and str(loc.get("line") or "").isdigit()
                else None,
                column=int(str(loc.get("column")))
                if loc is not None and str(loc.get("column") or "").isdigit()
                else None,
                code=error.get("id"),
                message=error.get("verbose") or error.get("msg") or "Cppcheck finding",
                severity=_severity(error.get("severity"), "warning"),
            ),
        )
    return out


# trace:v1 id=impl.src-bughunt-cli.parse-phpstan work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def parse_phpstan(stdout: str, stderr: str, exit_code: int) -> list[Finding]:
    try:
        data = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        return text_findings("phpstan", stdout, stderr, exit_code)
    out: list[Finding] = []
    files = data.get("files", {}) if isinstance(data, dict) else {}
    for path, payload in files.items() if isinstance(files, dict) else []:
        if not isinstance(payload, dict):
            continue
        for item in payload.get("messages", []) or []:
            if not isinstance(item, dict):
                continue
            out.append(
                Finding(
                    tool="phpstan",
                    path=str(path),
                    line=item.get("line"),
                    code=item.get("identifier"),
                    message=str(item.get("message") or "PHPStan finding"),
                    severity="error",
                ),
            )
    for message in data.get("errors", []) if isinstance(data, dict) else []:
        out.append(Finding(tool="phpstan", message=str(message), severity="error"))
    return out or (
        text_findings("phpstan", stdout, stderr, exit_code) if exit_code else []
    )


# Banner ESLint prints (to stderr) when ignore patterns exclude every file
# under the lint target. The caller maps this to SKIPPED ("nothing in scope")
# via empty_scope_markers.
ESLINT_EMPTY_SCOPE = "all of the files matching the glob pattern"


# trace:v1 id=impl.src-bughunt-cli.parse-eslint work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def parse_eslint(
    stdout: str,
    stderr: str,
    exit_code: int,
    *,
    tool: str = "eslint",
) -> list[Finding]:
    if ESLINT_EMPTY_SCOPE in stdout or ESLINT_EMPTY_SCOPE in stderr:
        return []
    try:
        data = json.loads(stdout or "[]")
    except json.JSONDecodeError:
        return text_findings(tool, stdout, stderr, exit_code)
    out: list[Finding] = []
    if isinstance(data, dict):
        data = data.get("results") or data.get("diagnostics") or data.get("files") or []
        if isinstance(data, dict):
            data = [
                {"filePath": k, **(v if isinstance(v, dict) else {})}
                for k, v in data.items()
            ]
    for file_item in data if isinstance(data, list) else []:
        if not isinstance(file_item, dict):
            continue
        path = (
            file_item.get("filePath")
            or file_item.get("path")
            or file_item.get("filename")
        )
        messages = (
            file_item.get("messages") or file_item.get("diagnostics") or [file_item]
        )
        for item in messages if isinstance(messages, list) else []:
            if not isinstance(item, dict):
                continue
            out.append(
                Finding(
                    tool=tool,
                    path=str(path) if path else item.get("file"),
                    line=item.get("line") or item.get("start_line"),
                    column=item.get("column") or item.get("start_column"),
                    code=item.get("ruleId") or item.get("rule_id") or item.get("code"),
                    message=str(
                        item.get("message")
                        or item.get("description")
                        or f"{tool} finding",
                    ),
                    severity="error"
                    if item.get("severity") in {2, "error"}
                    else "warning",
                    fixable=bool(item.get("fix")),
                    fix_safety="review" if item.get("fix") else None,
                ),
            )
    return out or (text_findings(tool, stdout, stderr, exit_code) if exit_code else [])


# Banner oxlint prints when ignore patterns exclude every candidate file.
# The caller maps this to SKIPPED ("nothing in scope") via empty_scope_markers.
OXLINT_EMPTY_SCOPE = "No files found to lint"


# trace:v1 id=impl.src-bughunt-cli.parse-oxlint work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def parse_oxlint(stdout: str, stderr: str, exit_code: int) -> list[Finding]:
    if OXLINT_EMPTY_SCOPE in stdout:
        return []
    return parse_eslint(stdout, stderr, exit_code, tool="oxlint")


# trace:v1 id=impl.src-bughunt-cli.parse-squawk work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def parse_squawk(stdout: str, stderr: str, exit_code: int) -> list[Finding]:
    try:
        data = json.loads(stdout or "[]")
    except json.JSONDecodeError:
        return text_findings("squawk", stdout, stderr, exit_code)
    if isinstance(data, dict):
        data = (
            data.get("messages") or data.get("diagnostics") or data.get("results") or []
        )
    return parse_json_list("squawk", json.dumps(data), stderr, exit_code)


# trace:v1 id=impl.src-bughunt-cli.parse-buf-json-lines work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def parse_buf_json_lines(stdout: str, stderr: str, exit_code: int) -> list[Finding]:
    out: list[Finding] = []
    for raw in stdout.splitlines():
        try:
            item = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        out.append(
            Finding(
                tool="buf",
                path=item.get("path") or item.get("filename"),
                line=item.get("start_line") or item.get("line"),
                column=item.get("start_column") or item.get("column"),
                code=item.get("rule_id") or item.get("rule"),
                message=str(item.get("message") or "Buf schema finding"),
                severity="error",
            ),
        )
    return out or (text_findings("buf", stdout, stderr, exit_code) if exit_code else [])


# trace:v1 id=impl.src-bughunt-cli.parse-sarif work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def parse_sarif(path: Path, tool: str) -> list[Finding]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return []
    out: list[Finding] = []
    for run in data.get("runs", []):
        for result in run.get("results", []):
            locs = result.get("locations", [])
            phys = (locs[0].get("physicalLocation", {}) if locs else {}) or {}
            art = phys.get("artifactLocation", {})
            region = phys.get("region", {})
            msg = result.get("message", {})
            out.append(
                Finding(
                    tool=tool,
                    path=art.get("uri"),
                    line=region.get("startLine"),
                    column=region.get("startColumn"),
                    code=result.get("ruleId"),
                    message=msg.get("text") or msg.get("markdown") or "SARIF finding",
                    severity=result.get("level", "error"),
                ),
            )
    return out


# trace:v1 id=impl.src-bughunt-cli.parse-bughunt-helper work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def parse_bughunt_helper(
    tool: str,
    stdout: str,
    stderr: str,
    exit_code: int,
) -> list[Finding]:
    """Parse BugHunt helper modules that emit {findings:[...]} JSON."""
    try:
        data = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        return text_findings(tool, stdout, stderr, exit_code)
    raw = data.get("findings", []) if isinstance(data, dict) else []
    out: list[Finding] = []
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue
        out.append(
            Finding(
                tool=str(item.get("tool") or tool),
                message=str(item.get("message") or "BugHunt helper finding"),
                path=str(item.get("path")) if item.get("path") else None,
                line=int(item["line"]) if isinstance(item.get("line"), int) else None,
                column=int(item["column"])
                if isinstance(item.get("column"), int)
                else None,
                code=str(item.get("code")) if item.get("code") is not None else None,
                severity=str(item.get("severity") or "warning"),
            ),
        )
    return out


def python_package_names(root: Path, source_paths: Sequence[str]) -> list[str]:
    """Infer importable first-party top-level packages without importing them."""
    names: list[str] = []
    for rel in source_paths:
        base = root / rel
        if base.is_file() and base.suffix == ".py" and base.stem != "__init__":
            names.append(base.stem)
            continue
        if not base.is_dir():
            continue
        if (base / "__init__.py").exists():
            names.append(base.name)
        else:
            for child in sorted(base.iterdir()):
                if child.is_dir() and (child / "__init__.py").exists():
                    names.append(child.name)
    return list(dict.fromkeys(x for x in names if x.isidentifier()))


# trace:v1 id=impl.src-bughunt-cli.local-schema-pairs work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def local_schema_pairs(root: Path, files: Sequence[str]) -> list[tuple[str, str]]:
    """Resolve explicit *local* $schema references without network access."""
    pairs: list[tuple[str, str]] = []
    root_resolved = root.resolve(strict=False)
    for rel in files:
        path = root / rel
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        schema_ref: str | None = None
        if path.suffix.lower() == ".json":
            try:
                payload = json.loads(text)
                raw = payload.get("$schema") if isinstance(payload, dict) else None
                schema_ref = raw if isinstance(raw, str) else None
            except json.JSONDecodeError:
                pass
        if schema_ref is None:
            match = re.search(r"(?m)^\s*\$schema\s*:\s*[\"']?([^\"'\s#]+)", text)
            if match:
                schema_ref = match.group(1)
        if not schema_ref or re.match(
            r"^[a-z][a-z0-9+.-]*://",
            schema_ref,
            re.IGNORECASE,
        ):
            continue
        schema = (path.parent / schema_ref).resolve(strict=False)
        try:
            schema.relative_to(root_resolved)
        except ValueError:
            continue
        if schema.is_file():
            pairs.append((rel, schema.relative_to(root_resolved).as_posix()))
    return pairs


# trace:v1 id=impl.src-bughunt-cli.pact-json-files work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def pact_json_files(root: Path, files: Sequence[str]) -> list[str]:
    out: list[str] = []
    for rel in files:
        path = root / rel
        if path.suffix.lower() != ".json" or not path.is_file():
            continue
        try:
            payload = json.loads(path.read_text(errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict):
            continue
        if (
            isinstance(payload.get("consumer"), dict)
            and isinstance(payload.get("provider"), dict)
            and isinstance(payload.get("interactions"), list)
        ):
            out.append(rel)
    return out


# trace:v1 id=impl.src-bughunt-cli.type-disagreement-result work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def type_disagreement_result(results: list[Result]) -> Result | None:
    """Make cross-checker disagreement a first-class, deduplicated signal."""
    checker_names = {"mypy", "basedpyright", "pyrefly", "ty"}
    by_location: dict[tuple[str, int], dict[str, list[Finding]]] = {}
    present = {
        r.name
        for r in results
        if r.name in checker_names
        and r.status not in {Status.SKIPPED, Status.NA, Status.ERROR}
    }
    if len(present) < 2:
        return None
    for result in results:
        if result.name not in checker_names:
            continue
        for f in result.findings:
            if f.path and f.line:
                by_location.setdefault((f.path, f.line), {}).setdefault(
                    result.name,
                    [],
                ).append(f)
    findings: list[Finding] = []
    for (path, line), tools in by_location.items():
        reporters = set(tools)
        if not reporters or reporters == present:
            continue
        silent = sorted(present - reporters)
        loud = sorted(reporters)
        findings.append(
            Finding(
                tool="type-disagreement",
                code="BHDIS001",
                path=path,
                line=line,
                severity="warning",
                message=(
                    f"type-checker disagreement: {', '.join(loud)} reports a problem "
                    f"here while {', '.join(silent)} does not; inspect erased/dynamic "
                    "typing at this seam"
                ),
            ),
        )
    if not findings:
        return Result(
            "type-disagreement",
            "cross-tool-correlation",
            Status.PASS,
            note="type checkers agreed on diagnostic locations",
        )
    return Result(
        "type-disagreement",
        "cross-tool-correlation",
        Status.FINDINGS,
        findings=findings,
        note=f"{len(findings)} disagreement location(s)",
    )


# trace:v1 id=impl.src-bughunt-cli.correlated-issue-groups work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def correlated_issue_groups(results: list[Result]) -> list[dict[str, Any]]:
    """Correlate independent tools per source location; keep raw evidence."""
    buckets: dict[tuple[str, int], list[Finding]] = {}
    for r in results:
        for f in r.findings:
            if f.path and f.line:
                buckets.setdefault((f.path, f.line), []).append(f)
    out: list[dict[str, Any]] = []
    for (path, line), findings in buckets.items():
        tools = sorted({f.tool for f in findings})
        if len(tools) < 2:
            continue
        out.append(
            {
                "path": path,
                "line": line,
                "tools": tools,
                "tool_count": len(tools),
                "finding_count": len(findings),
                "codes": sorted({str(f.code) for f in findings if f.code}),
                "severity": min((f.severity for f in findings), key=severity_priority),
            },
        )
    return sorted(
        out,
        key=lambda x: (
            -int(x["tool_count"]),
            -int(x["finding_count"]),
            str(x["path"]),
            int(x["line"]),
        ),
    )


# trace:v1 id=impl.src-bughunt-cli.logical-issue-groups work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def logical_issue_groups(results: list[Result]) -> list[dict[str, Any]]:
    """Build a non-destructive logical dedup view.

    Raw analyzer findings remain untouched. Findings at the same source location
    and ODC class are grouped into one logical issue so agents can fix the seam/
    statement once while preserving every independent analyzer as evidence.
    Findings without a stable location retain their own fingerprint-backed group.
    """
    buckets: dict[tuple[str, int, str], list[tuple[Result, Finding]]] = {}
    for result in results:
        for finding in result.findings:
            if finding.path and finding.line:
                key = (
                    finding.path,
                    int(finding.line),
                    odc_class(result.category, finding),
                )
            else:
                key = (
                    f"<unlocated:{finding.fingerprint}>",
                    0,
                    odc_class(result.category, finding),
                )
            buckets.setdefault(key, []).append((result, finding))

    groups: list[dict[str, Any]] = []
    for (path, line, defect_class), items in buckets.items():
        findings = [item[1] for item in items]
        tools = sorted({f.tool for f in findings})
        primary = min(
            findings,
            key=lambda f: (
                severity_priority(f.severity),
                0 if f.code and str(f.code).startswith("BH") else 1,
                f.tool,
            ),
        )
        groups.append(
            {
                "id": "LOG-"
                + hashlib.sha256(f"{path}|{line}|{defect_class}".encode())
                .hexdigest()[:12]
                .upper(),
                "path": None if path.startswith("<unlocated:") else path,
                "line": line or None,
                "odc_class": defect_class,
                "finding_count": len(findings),
                "tool_count": len(tools),
                "tools": tools,
                "codes": sorted({str(f.code) for f in findings if f.code}),
                "severity": primary.severity,
                "primary_message": primary.message,
                "finding_ids": [f.finding_id for f in findings],
            },
        )
    return sorted(
        groups,
        key=lambda g: (
            severity_priority(str(g["severity"])),
            -int(g["tool_count"]),
            -int(g["finding_count"]),
            str(g.get("path") or ""),
            int(g.get("line") or 0),
        ),
    )


# trace:v1 id=impl.src-bughunt-cli.odc-class work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def odc_class(category: str, finding: Finding | None = None) -> str:
    text = (category + " " + (finding.code or "") if finding else category).lower()
    if any(
        x in text
        for x in ("seam", "api", "schema", "architecture", "contract", "migration")
    ):
        return "interface"
    if any(x in text for x in ("concurrency", "async", "time", "random", "matrix")):
        return "timing/serialization"
    if any(x in text for x in ("package", "build", "dependency", "ci-")):
        return "build/package/merge"
    if any(x in text for x in ("doc", "doctest")):
        return "documentation"
    if any(x in text for x in ("complexity", "performance", "benchmark", "memory")):
        return "algorithm"
    if any(
        x in text for x in ("type", "coverage", "test", "validation", "lint", "static")
    ):
        return "checking"
    return "function"


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
    if not technology.has("python"):
        for name, category in (
            ("codeql", "whole-program"),
            ("pysa", "taint"),
            ("mutmut", "mutation"),
        ):
            if name in wanted:
                skipped.append(
                    Result(
                        name,
                        category,
                        Status.NA,
                        note=(
                            "not applicable: no first-party Python capability detected"
                        ),
                    ),
                )
    for name in sorted(excluded & set(profile_tools)):
        skipped.append(
            Result(
                name=name,
                category=category_by_tool.get(name, "excluded"),
                status=Status.SKIPPED,
                note="explicitly skipped by user",
            ),
        )

    # trace:v1 id=impl.src-bughunt-cli-build-checks.add work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
    def add(
        name: str,
        category: str,
        command: Sequence[str] | None,
        parser: Callable[[str, str, int], list[Finding]] | None = None,
        *,
        reason: str | None = None,
        findings_exit_codes: set[int] | None = None,
        skip_exit_codes: set[int] | None = None,
        empty_scope_markers: tuple[str, ...] | None = None,
        check_timeout: int | None = None,
        env: dict[str, str] | None = None,
        timeout_is_success: bool = False,
    ) -> None:
        if name not in wanted:
            return
        if name in PYTHON_ONLY_TOOLS and not technology.has("python"):
            skipped.append(
                Result(
                    name=name,
                    category=category,
                    status=Status.NA,
                    note="not applicable: no first-party Python capability detected",
                ),
            )
            return
        if command is None:
            skipped.append(
                Result(
                    name=name,
                    category=category,
                    status=Status.SKIPPED,
                    note=reason or "not configured",
                ),
            )
            return
        checks.append(
            Check(
                name=name,
                category=category,
                command=list(command),
                parser=(partial(text_findings, name) if parser is None else parser),
                timeout=check_timeout or timeout,
                cwd=root,
                findings_exit_codes=findings_exit_codes
                if findings_exit_codes is not None
                else {1},
                skip_exit_codes=skip_exit_codes
                if skip_exit_codes is not None
                else set(),
                empty_scope_markers=empty_scope_markers or (),
                env=env,
                timeout_is_success=timeout_is_success,
            ),
        )

    add(
        "compile",
        "syntax",
        [sys.executable, "-m", "compileall", "-q", *py],
        findings_exit_codes={1},
    )
    ruff_cfg = generated_config(root, "ruff.toml")
    ruff_cmd = _optional_cmd(executable("ruff"), ["check", *py, "--output-format=json"])
    if ruff_cmd and ruff_cfg:
        ruff_cmd += ["--config", str(ruff_cfg)]
    add("ruff", "lint", ruff_cmd, parse_ruff, reason="ruff not installed")
    bp_cfg = generated_config(root, "basedpyrightconfig.json")
    bp_cmd = _optional_cmd(
        executable("basedpyright"),
        ["--outputjson", "--pythonpath", sys.executable],
    )
    if bp_cmd and bp_cfg:
        bp_cmd += ["--project", str(bp_cfg)]
    add(
        "basedpyright",
        "types",
        bp_cmd,
        parse_basedpyright,
        reason="basedpyright not installed",
        findings_exit_codes={1},
    )
    mypy_cfg = generated_config(root, "mypy.ini")
    mypy_cmd = _optional_cmd(
        executable("mypy"),
        [*py, "--show-error-codes", "--no-pretty", "--no-color-output"],
    )
    if mypy_cmd and mypy_cfg:
        mypy_cmd += ["--config-file", str(mypy_cfg)]
    add("mypy", "types", mypy_cmd, reason="mypy not installed")
    ty_cfg = generated_config(root, "ty.toml")
    ty_cmd = _optional_cmd(executable("ty"), ["check", *py])
    if ty_cmd and ty_cfg:
        ty_cmd += ["--config-file", str(ty_cfg)]
    add("ty", "types", ty_cmd, reason="ty not installed", findings_exit_codes={1})
    pyrefly_cfg = generated_config(root, "pyrefly.toml")
    pyrefly_cmd = _optional_cmd(
        executable("pyrefly"),
        ["check", "--output-format=json"],
    )
    if pyrefly_cmd and pyrefly_cfg:
        pyrefly_cmd += ["--config", str(pyrefly_cfg)]
    add(
        "pyrefly",
        "types",
        pyrefly_cmd,
        parse_pyrefly,
        reason="pyrefly not installed",
        findings_exit_codes={1},
    )
    pylint_cfg = generated_config(root, "pylintrc")
    pylint_cmd = _optional_cmd(executable("pylint"), [*py, "--output-format=json2"])
    if pylint_cmd and pylint_cfg:
        pylint_cmd += ["--rcfile", str(pylint_cfg)]
    add(
        "pylint",
        "lint",
        pylint_cmd,
        parse_pylint,
        reason="pylint not installed",
        findings_exit_codes={code for code in range(1, 32)},
    )

    # Built-in policy + complexity scanners are always available with BugHunt.
    policy_cmd = [sys.executable, "-m", "bughunt.policy_scan", "--root", str(root)]
    for path in src:
        policy_cmd += ["--source", path]
    for path in tests:
        policy_cmd += ["--test", path]
    add(
        "policy",
        "repository-policy",
        policy_cmd,
        lambda o, e, c: parse_json_list("policy", o, e, c),
        findings_exit_codes={1},
    )

    metrics_cmd = [sys.executable, "-m", "bughunt.metrics_scan", "--root", str(root)]
    for path in src:
        metrics_cmd += ["--source", path]
    add(
        "complexity",
        "complexity-budgets",
        metrics_cmd,
        lambda o, e, c: parse_json_list("complexity", o, e, c),
        findings_exit_codes={1},
    )

    complexipy = executable("complexipy")
    complexipy_cmd = (
        [
            complexipy,
            *src,
            "--plain",
            "--failed",
            "--check-script",
            "--no-ignore",
            "--report-ignored",
            "--max-complexity-allowed",
            str(int(cfg.raw.get("complexity", {}).get("cognitive_max", 10))),
        ]
        if complexipy
        else None
    )
    add(
        "complexipy",
        "cognitive-complexity",
        complexipy_cmd,
        parse_complexipy,
        reason="complexipy not installed",
        findings_exit_codes={1},
    )

    radon = executable("radon")
    radon_cmd = [radon, "mi", "-j", "-s", *src] if radon else None
    add(
        "radon",
        "maintainability",
        radon_cmd,
        parse_radon_mi,
        reason="radon not installed",
        findings_exit_codes=set(),
    )

    lizard = executable("lizard")
    lizard_cmd = (
        [
            lizard,
            "-w",
            "-C",
            str(int(cfg.raw.get("complexity", {}).get("cyclomatic_warn", 10))),
            "-L",
            str(int(cfg.raw.get("complexity", {}).get("function_loc_warn", 80))),
            "-a",
            "8",
            "-t",
            str(max(1, cfg.max_parallel)),
            *src,
        ]
        if lizard
        else None
    )
    add(
        "lizard",
        "cross-language-complexity",
        lizard_cmd,
        parse_lizard,
        reason="lizard not installed",
        findings_exit_codes={1},
    )

    vulture_confidence = (
        "0" if profile in {"deep", "all"} else ("60" if profile == "pr" else "80")
    )
    add(
        "vulture",
        "dead-code",
        _optional_cmd(
            executable("vulture"),
            [*py, "--min-confidence", vulture_confidence],
        ),
        reason="vulture not installed",
        findings_exit_codes={3},
    )
    bandit_cfg = generated_config(root, "bandit.yaml")
    bandit_cmd = _optional_cmd(executable("bandit"), ["-r", *src, "-f", "json", "-q"])
    if bandit_cmd and bandit_cfg:
        bandit_cmd += ["-c", str(bandit_cfg)]
    add("bandit", "security", bandit_cmd, parse_bandit, reason="bandit not installed")
    deptry_cmd = _optional_cmd(
        executable("deptry"),
        [
            *src,
            "--extend-exclude",
            r"(^|/)(.bughunt|build|dist|mutants|node_modules)(/|$)",
            "--experimental-namespace-package",
            "--no-ansi",
        ],
    )
    add(
        "deptry",
        "dependencies",
        deptry_cmd,
        parse_deptry,
        reason="deptry not installed",
    )
    import_linter = executable("lint-imports", "import-linter")
    generated_import_cfg = generated_config(root, "importlinter.toml")
    if import_linter and generated_import_cfg:
        add(
            "import-linter",
            "architecture",
            [
                import_linter,
                "--config",
                str(generated_import_cfg),
                "--no-logo",
                "--show-timings",
            ],
            reason="import-linter not installed",
        )
    elif import_linter and import_linter_configured(root):
        add(
            "import-linter",
            "architecture",
            [import_linter, "--no-logo", "--show-timings"],
            reason="import-linter not installed",
        )
    else:
        add(
            "import-linter",
            "architecture",
            None,
            reason=(
                "import-linter not installed"
                if not import_linter
                else "no safe import contract could be inferred; run configure --auto"
            ),
        )

    sg = ast_grep_executable()
    sgconfig = generated_config(root, "sgconfig.yml")
    if not sgconfig:
        sgconfig = next(
            (
                root / p
                for p in ("sgconfig.yml", "sgconfig.yaml")
                if (root / p).exists()
            ),
            None,
        )
    sg_cmd = (
        [sg, "scan", "--json=compact", "--config", str(sgconfig), *py]
        if sg and sgconfig
        else None
    )
    add(
        "ast-grep",
        "structural",
        sg_cmd,
        parse_ast_grep,
        reason="ast-grep missing or no generated/project sgconfig.yml",
    )

    semgrep = executable("semgrep")
    semgrep_settings = cfg.raw.get("semgrep", {})
    requested_semgrep = list(semgrep_settings.get("configs", []))
    # `auto` requires Semgrep's metrics/inventory exchange. BugHunt keeps metrics
    # off, so map it to a deterministic baseline instead. Correctness is the
    # default goal; security-only packs are opt-in rather than forcibly injected.
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
    local_semgrep = config_dir / "semgrep" / "rules"
    if local_semgrep.exists() and any(
        path.suffix in {".yml", ".yaml"} for path in local_semgrep.rglob("*")
    ):
        semgrep_cfgs.append(str(local_semgrep))
    semgrep_cmd = (
        [semgrep, "scan", "--json", "--metrics=off", "--disable-version-check"]
        if semgrep
        else []
    )
    # If the user has authenticated Semgrep Code, spend the extra analysis;
    # otherwise explicitly select CE so behavior is stable and non-interactive.
    if semgrep_cmd:
        semgrep_cmd.append(
            "--pro" if os.environ.get("SEMGREP_APP_TOKEN") else "--oss-only",
        )
    for c in dict.fromkeys(str(x) for x in semgrep_cfgs):
        semgrep_cmd.extend(["--config", c])
    semgrep_cmd.extend(py)
    add(
        "semgrep",
        "semantic-static",
        semgrep_cmd if semgrep else None,
        parse_semgrep,
        reason="semgrep not installed",
    )

    deal_ready = python_module_available("deal")
    add(
        "deal",
        "contracts",
        [sys.executable, "-m", "deal", "lint", *src, "--json"] if deal_ready else None,
        parse_deal,
        reason="deal Python module not installed",
        findings_exit_codes=set(range(1, 256)),
    )

    crosshair = executable("crosshair")
    crosshair_cmd = None
    if crosshair:
        per_path = "8" if profile == "all" else ("5" if profile == "deep" else "3")
        per_condition = (
            "180" if profile == "all" else ("90" if profile == "deep" else "45")
        )
        iterations = (
            "1000" if profile == "all" else ("300" if profile == "deep" else "100")
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
            *src,
        ]
    add(
        "crosshair",
        "symbolic",
        crosshair_cmd,
        reason="crosshair not installed",
        findings_exit_codes={1},
    )

    _target_py = target_python(root)
    pytest = target_executable(root, "pytest")
    hypothesis_plugin = generated_config(root, "hypothesis_plugin.py")
    repro_seed = int(cfg.raw.get("tests", {}).get("repro_seed", 1))
    test_timeout = int(cfg.raw.get("tests", {}).get("timeout_seconds", 300))
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
    if pytest_cmd and target_has_module(_target_py, "pytest_timeout"):
        pytest_cmd += ["--timeout", str(test_timeout)]
    if pytest_cmd and profile in {"deep", "all"}:
        # Resource/deprecation/runtime warnings are often latent bugs. Developer
        # mode also enables faulthandler and extra CPython runtime checks.
        pytest_cmd += ["-W", "error"]
        pytest_env["PYTHONDEVMODE"] = "1"
        pytest_env["PYTHONASYNCIODEBUG"] = "1"
    if pytest_cmd and hypothesis_plugin and target_has_module(_target_py, "hypothesis"):
        pytest_cmd += ["-p", "hypothesis_plugin"]
        pytest_env["PYTHONPATH"] = (
            str(hypothesis_plugin.parent)
            + os.pathsep
            + os.environ.get("PYTHONPATH", "")
        )
    if pytest_cmd:
        pytest_cmd += tests
    if "pytest" in wanted:
        if not technology.has("python"):
            skipped.append(
                Result(
                    "pytest",
                    "tests/property/state",
                    Status.NA,
                    note="not applicable: no first-party Python capability detected",
                ),
            )
        elif pytest_cmd:
            checks.append(
                Check(
                    "pytest",
                    "tests/property/state",
                    pytest_cmd,
                    lambda o, e, c: text_findings("pytest", o, e, c),
                    timeout,
                    root,
                    env=pytest_env,
                    findings_exit_codes={1},
                ),
            )
        else:
            skipped.append(
                Result(
                    "pytest",
                    "tests/property/state",
                    Status.SKIPPED,
                    note="pytest not installed",
                ),
            )

    # Structural-hole defenses: execution coverage, runtime annotation truth,
    # environment/order variation, API drift, packaging, docs, and async behavior.
    if technology.has("python"):
        if "coverage" in wanted:
            cov_python = (
                _target_py
                if target_has_module(_target_py, "bughunt")
                else sys.executable
            )
            if target_has_module(cov_python, "coverage") and pytest:
                add(
                    "coverage",
                    "coverage/branches",
                    [cov_python, "-m", "bughunt.coverage_runner", str(root), *tests],
                    lambda o, e, c: parse_bughunt_helper("coverage", o, e, c),
                    findings_exit_codes={1},
                )
            else:
                add(
                    "coverage",
                    "coverage/branches",
                    None,
                    reason="coverage.py/pytest not installed",
                )

        if "seam" in wanted:
            add(
                "seam",
                "contract-drift",
                [
                    sys.executable,
                    "-m",
                    "bughunt.seam_scan",
                    str(root),
                    ",".join(cfg.source_paths),
                    ",".join(cfg.test_paths),
                ],
                lambda o, e, c: parse_bughunt_helper("seam", o, e, c),
                findings_exit_codes={1},
            )

        if "evidence" in wanted:
            add(
                "evidence",
                "evidence-preservation",
                [
                    sys.executable,
                    "-m",
                    "bughunt.evidence_scan",
                    str(root),
                    *cfg.source_paths,
                ],
                lambda o, e, c: parse_bughunt_helper("evidence", o, e, c),
                findings_exit_codes={1},
            )

        if "packaging" in wanted:
            add(
                "packaging",
                "package-correctness",
                [sys.executable, "-m", "bughunt.package_checks", str(root)],
                lambda o, e, c: parse_bughunt_helper("packaging", o, e, c),
                findings_exit_codes={1},
            )

        if "runtime-types" in wanted:
            packages = python_package_names(root, cfg.source_paths)
            tg_cmd = None
            if pytest and target_has_module(_target_py, "typeguard") and packages:
                tg_cmd = [
                    pytest,
                    "-q",
                    "--tb=short",
                    f"--typeguard-packages={','.join(packages)}",
                    *tests,
                ]
                if target_has_module(_target_py, "pytest_timeout"):
                    tg_cmd += ["--timeout", str(test_timeout)]
            add(
                "runtime-types",
                "runtime-type-contracts",
                tg_cmd,
                reason=(
                    "no importable package roots for Typeguard"
                    if not packages
                    else "typeguard/pytest not installed"
                ),
                env={"PYTHONHASHSEED": str(repro_seed)},
            )

        if "doctest" in wanted:
            doctest_cmd = (
                [pytest, "-q", "--tb=short", "--doctest-modules", *src]
                if pytest
                else None
            )
            add(
                "doctest",
                "executable-docs",
                doctest_cmd,
                reason="pytest not installed",
                skip_exit_codes={5},
            )

        if "pydoclint" in wanted:
            pd = executable("pydoclint")
            add(
                "pydoclint",
                "doc-contracts",
                [pd, *src] if pd else None,
                reason="pydoclint not installed",
                findings_exit_codes={1},
            )

        if "refurb" in wanted:
            rb = executable("refurb")
            add(
                "refurb",
                "correctness-modernization",
                [rb, *src] if rb else None,
                reason="refurb not installed",
                findings_exit_codes={1},
            )

        if "pytest-random" in wanted:
            seed = secrets.randbelow(2**31 - 2) + 1
            cmd = (
                [pytest, "-q", "--tb=short", f"--randomly-seed={seed}", *tests]
                if pytest and target_has_module(_target_py, "pytest_randomly")
                else None
            )
            add(
                "pytest-random",
                "determinism/order",
                cmd,
                reason="pytest-randomly not installed",
                env={"PYTHONHASHSEED": str(seed), "PYTHONASYNCIODEBUG": "1"},
                findings_exit_codes={1},
            )

        if "pytest-no-network" in wanted:
            cmd = (
                [
                    pytest,
                    "-q",
                    "--tb=short",
                    "--disable-socket",
                    "--allow-unix-socket",
                    *tests,
                ]
                if pytest and target_has_module(_target_py, "pytest_socket")
                else None
            )
            add(
                "pytest-no-network",
                "hidden-io",
                cmd,
                reason="pytest-socket not installed",
                env={"PYTHONHASHSEED": str(repro_seed)},
                findings_exit_codes={1},
            )

        if "pytest-xdist" in wanted:
            cmd = (
                [pytest, "-q", "--tb=short", "-n", "auto", "--dist", "loadfile", *tests]
                if pytest and target_has_module(_target_py, "xdist")
                else None
            )
            add(
                "pytest-xdist",
                "cross-test-state",
                cmd,
                reason="pytest-xdist not installed",
                env={"PYTHONHASHSEED": str(repro_seed)},
                findings_exit_codes={1},
            )

        if "pytest-async-blocking" in wanted:
            blocker = generated_config(root, "blockbuster_plugin.py")
            cmd = (
                [pytest, "-q", "--tb=short", "-p", "blockbuster_plugin", *tests]
                if pytest and blocker and target_has_module(_target_py, "blockbuster")
                else None
            )
            env = {"PYTHONASYNCIODEBUG": "1", "PYTHONHASHSEED": str(repro_seed)}
            if blocker:
                env["PYTHONPATH"] = (
                    str(blocker.parent) + os.pathsep + os.environ.get("PYTHONPATH", "")
                )
            add(
                "pytest-async-blocking",
                "async-runtime",
                cmd,
                reason="Blockbuster plugin not configured/installed",
                env=env,
                findings_exit_codes={1},
            )

        if "pytest-parallel" in wanted:
            cmd = (
                [
                    pytest,
                    "-q",
                    "--tb=short",
                    "--parallel-threads=auto",
                    "--iterations=3",
                    *tests,
                ]
                if pytest and python_module_available("pytest_run_parallel")
                else None
            )
            add(
                "pytest-parallel",
                "thread-safety",
                cmd,
                reason="pytest-run-parallel not installed",
                env={"PYTHONASYNCIODEBUG": "1", "PYTHONHASHSEED": str(repro_seed)},
                findings_exit_codes={1},
            )

        if "hypofuzz" in wanted:
            hypothesis_cli = executable("hypothesis")
            budget = int(
                cfg.raw.get("hypofuzz", {}).get(
                    f"{profile}_seconds",
                    300 if profile == "all" else 120,
                ),
            )
            workers = int(cfg.raw.get("hypofuzz", {}).get("workers", 2))
            cmd = (
                [
                    hypothesis_cli,
                    "fuzz",
                    "--no-dashboard",
                    "-n",
                    str(workers),
                    "--",
                    *tests,
                ]
                if hypothesis_cli
                else None
            )
            add(
                "hypofuzz",
                "coverage-guided-property-fuzz",
                cmd,
                reason="HypoFuzz/Hypothesis CLI not installed",
                check_timeout=budget,
                timeout_is_success=True,
                env={"PYTHONHASHSEED": str(repro_seed)},
                skip_exit_codes={5},
            )

        if "griffe" in wanted:
            griffe = executable("griffe")
            baseline = technology.git_baseline
            packages = python_package_names(root, cfg.source_paths)
            if griffe and baseline and packages:
                # One aggregate command keeps the defense readable; Griffe accepts
                # repeated packages.
                cmd = [griffe, "check", *packages, "--against", baseline]
                for sp in cfg.source_paths:
                    cmd += ["--search", sp]
                add(
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
                add("griffe", "python-api-compatibility", None, reason=reason)

        if "importtime" in wanted:
            packages = python_package_names(root, cfg.source_paths)
            threshold = int(cfg.raw.get("performance", {}).get("import_ms_warn", 1000))
            add(
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

        if "python-matrix" in wanted:
            nox = executable("nox")
            noxfile = root / ".bughunt" / "generated" / "noxfile.py"
            add(
                "python-matrix",
                "interpreter-compatibility",
                [nox, "-f", str(noxfile), "--download-python", "auto"]
                if nox and noxfile.exists()
                else None,
                reason="Nox matrix not configured/installed",
                check_timeout=cfg.timeout("all"),
                findings_exit_codes={1},
            )

        if "timezone-matrix" in wanted:
            # Two hostile timezone passes; locale variation is only added when a
            # matching locale exists.
            for tz in ("UTC", "Pacific/Kiritimati"):
                name = f"timezone-matrix:{tz}"
                checks.append(
                    Check(
                        name,
                        "environment-variation",
                        [pytest, "-q", "--tb=short", *tests],
                        partial(text_findings, name),
                        timeout,
                        root,
                        env={
                            "TZ": tz,
                            "PYTHONHASHSEED": str(repro_seed),
                            "PYTHONASYNCIODEBUG": "1",
                        },
                        findings_exit_codes={1},
                    ),
                ) if pytest else None
            # macOS commonly exposes Turkish as tr_TR.UTF-8/tr_TR.UTF-8-like names;
            # only run it if installed.
            try:
                locale_lines = subprocess.run(
                    ["locale", "-a"],
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
            if turkish and pytest:
                name = "locale-matrix:tr_TR"
                checks.append(
                    Check(
                        name,
                        "environment-variation",
                        [pytest, "-q", "--tb=short", *tests],
                        partial(text_findings, name),
                        timeout,
                        root,
                        env={
                            "LC_ALL": turkish,
                            "LANG": turkish,
                            "PYTHONHASHSEED": str(repro_seed),
                        },
                        findings_exit_codes={1},
                    ),
                )

        if "memray" in wanted:
            cmd = (
                [pytest, "-q", "--tb=short", "--memray", "--fail-on-increase", *tests]
                if pytest and target_has_module(_target_py, "pytest_memray")
                else None
            )
            add(
                "memray",
                "memory-runtime",
                cmd,
                reason="pytest-memray not installed",
                check_timeout=cfg.timeout(profile),
                findings_exit_codes={1},
            )

        if "benchmark" in wanted:
            if (
                technology.has("benchmark-tests")
                and pytest
                and target_has_module(_target_py, "pytest_benchmark")
            ):
                cmd = [pytest, "-q", "--benchmark-only", "--benchmark-autosave"]
                if (root / ".benchmarks").exists():
                    regression = int(
                        cfg.raw.get("performance", {}).get(
                            "benchmark_regression_percent",
                            10,
                        ),
                    )
                    cmd += [
                        "--benchmark-compare",
                        f"--benchmark-compare-fail=mean:{regression}%",
                    ]
                cmd += tests
                add("benchmark", "performance-regression", cmd, findings_exit_codes={1})
            else:
                skipped.append(
                    Result(
                        "benchmark",
                        "performance-regression",
                        Status.NA
                        if not technology.has("benchmark-tests")
                        else Status.SKIPPED,
                        note="no pytest-benchmark tests detected"
                        if not technology.has("benchmark-tests")
                        else "pytest-benchmark not installed",
                    ),
                )

        if "pyanalyze" in wanted:
            pa = executable("pyanalyze")
            allowed = bool(
                cfg.raw.get("execution_imports", {}).get(
                    "allow_importing_analyzers",
                    False,
                ),
            )
            add(
                "pyanalyze",
                "runtime-informed-static",
                [pa, *src] if pa and allowed else None,
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
        if "version-diff" in wanted:
            baseline = technology.git_baseline
            add(
                "version-diff",
                "behavior-compatibility",
                [
                    sys.executable,
                    "-m",
                    "bughunt.version_diff_runner",
                    str(root),
                    baseline,
                    *cfg.source_paths,
                ]
                if baseline
                else None,
                lambda o, e, c: parse_bughunt_helper("version-diff", o, e, c),
                reason="no local Git baseline for behavioral differential",
                findings_exit_codes={1},
            )
        if "ghostwriter" in wanted:
            skipped.append(
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
        if "pynguin" in wanted:
            skipped.append(
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

    # Bug Corpus is the V2 learning subsystem, not a third-party executable.
    # Keep it visible as an intentional blind spot until the integrated engine
    # lands rather than pretending an imaginary `bugcorpus` package is missing.
    if "bugcorpus" in wanted:
        skipped.append(
            Result(
                "bugcorpus",
                "historical/custom-static",
                Status.SKIPPED,
                note=(
                    "integrated Bug Corpus execution is a V2 feature; "
                    "see docs/V2_SPEC.md"
                ),
            ),
        )

    # Target-specific fuzz / API / custom checks. Explicit config and safe
    # auto-discovered targets are merged. Auto-discovery never points at a
    # non-local HTTP server.
    if "schemathesis" in wanted:
        explicit = list(cfg.raw.get("schemathesis", {}).get("targets", []))
        auto = [
            t
            for t in generated_targets
            if t.kind == "schemathesis" and t.runnable and t.command
        ]
        added = 0
        st = executable("st", "schemathesis")
        schemathesis_ready = bool(st) or python_module_available("schemathesis")
        for target in explicit:
            if not st:
                continue
            name = f"schemathesis:{target.get('name', 'api')}"
            schema = str(target["schema"])
            st_cfg = generated_config(root, "schemathesis.toml")
            cmd = [st]
            if st_cfg:
                cmd += ["--config-file", str(st_cfg)]
            cmd += ["run", schema]
            if target.get("url"):
                cmd += ["--url", str(target["url"])]
            cmd += [
                "--max-examples",
                str(target.get("max_examples", 1000)),
                "--continue-on-failure",
                "--checks",
                "all",
                "--output-truncate",
                "false",
            ]
            checks.append(
                Check(
                    name,
                    "api-fuzz",
                    cmd,
                    partial(text_findings, name),
                    int(target.get("timeout", timeout)),
                    root,
                ),
            )
            added += 1
        for target in auto:
            if not schemathesis_ready:
                continue
            name = f"schemathesis:auto:{target.name}"
            checks.append(
                Check(
                    name,
                    "api-fuzz",
                    list(target.command or []),
                    partial(text_findings, name),
                    timeout,
                    root,
                ),
            )
            added += 1
        if not added:
            candidates = sum(
                t.kind == "schemathesis-candidate" for t in generated_targets
            )
            if (explicit or auto) and not schemathesis_ready:
                reason = "Schemathesis target exists but the engine is not installed"
            else:
                reason = "no safe runnable API target discovered/configured"
                if candidates:
                    reason += f" ({candidates} schema candidate(s) need a local URL)"
            skipped.append(
                Result("schemathesis", "api-fuzz", Status.SKIPPED, note=reason),
            )

    if "atheris" in wanted and not technology.has("python"):
        skipped.append(
            Result(
                "atheris",
                "coverage-fuzz",
                Status.NA,
                note="not applicable: no first-party Python capability detected",
            ),
        )
    elif "atheris" in wanted:
        explicit = list(cfg.raw.get("atheris", {}).get("targets", []))
        auto = [
            t
            for t in generated_targets
            if t.kind == "atheris" and t.runnable and t.command
        ]
        added = 0
        atheris_ready = atheris_available(root)
        for target in explicit:
            name = f"atheris:{target.get('name', 'fuzzer')}"
            cmd = [str(x) for x in target["command"]]
            checks.append(
                Check(
                    name,
                    "coverage-fuzz",
                    cmd,
                    partial(text_findings, name),
                    int(target.get("timeout", timeout)),
                    root,
                ),
            )
            added += 1
        for target in auto:
            if not atheris_ready:
                continue
            name = f"atheris:auto:{target.name}"
            checks.append(
                Check(
                    name,
                    "coverage-fuzz",
                    list(target.command or []),
                    partial(text_findings, name),
                    timeout,
                    root,
                ),
            )
            added += 1
        if not added:
            if auto and not atheris_ready:
                reason = (
                    "Atheris target discovered, but the Atheris "
                    "engine is not importable"
                )
            else:
                reason = (
                    "no safe one-argument parser/decoder fuzz target "
                    "discovered/configured"
                )
            skipped.append(
                Result("atheris", "coverage-fuzz", Status.SKIPPED, note=reason),
            )

    if "custom" in wanted:
        explicit_custom = list(cfg.raw.get("custom", {}).get("checks", []))
        generated_custom = [
            {
                "name": target.name,
                "category": target.kind.removeprefix("custom-"),
                "profile": "deep",
                "command": list(target.command or []),
                "timeout": int((target.metadata or {}).get("timeout", timeout)),
                "generated": True,
                "confidence": target.confidence,
            }
            for target in generated_targets
            if target.kind.startswith("custom-")
            and target.runnable
            and target.command
            and target.confidence == "high"
        ]
        merged_custom: list[dict[str, Any]] = []
        seen_custom: set[tuple[str, tuple[str, ...]]] = set()
        for item in [*explicit_custom, *generated_custom]:
            command = tuple(str(x) for x in item.get("command", []))
            key = (str(item.get("name", "custom")), command)
            if not command or key in seen_custom:
                continue
            seen_custom.add(key)
            merged_custom.append(item)
        if not merged_custom:
            skipped.append(
                Result(
                    "custom",
                    "custom",
                    Status.SKIPPED,
                    note=(
                        "no high-confidence repository-specific "
                        "semantic campaign could be inferred"
                    ),
                ),
            )
        else:
            rank = {"fast": 0, "pr": 1, "deep": 2, "all": 3}
            for item in merged_custom:
                required = str(item.get("profile", "deep"))
                if rank[profile] < rank.get(required, 2):
                    continue
                name = f"custom:{item['name']}"
                checks.append(
                    Check(
                        name,
                        str(item.get("category", "custom")),
                        [str(x) for x in item["command"]],
                        partial(text_findings, name),
                        int(item.get("timeout", timeout)),
                        root,
                    ),
                )

    # Technology-aware correctness engines. Absence of the technology itself is
    # N/A, not a blind spot. An applicable technology with a missing engine is
    # a real skipped defense and lowers coverage health.
    # trace:v1 id=impl.src-bughunt-cli-build-checks.add-technology work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
    def add_technology(
        engine: str,
        command: Sequence[str] | None,
        parser_fn: Callable[[str, str, int], list[Finding]] | None = None,
        *,
        reason: str | None = None,
        findings_exit_codes: set[int] | None = None,
        empty_scope_markers: tuple[str, ...] | None = None,
        name: str | None = None,
        check_timeout: int | None = None,
    ) -> None:
        if engine not in wanted:
            return
        category = ENGINE_CATEGORY[engine]
        logical = name or engine
        if not engine_applicable(technology, engine):
            # Only emit the base logical result once for engines which may have
            # multiple per-file checks (oasdiff etc.).
            if not any(x.name == engine and x.status == Status.NA for x in skipped):
                cap = ENGINE_CAPABILITY[engine]
                skipped.append(
                    Result(
                        engine,
                        category,
                        Status.NA,
                        note=f"not applicable: no {cap} capability detected",
                    ),
                )
            return
        if command is None:
            skipped.append(
                Result(
                    logical,
                    category,
                    Status.SKIPPED,
                    note=reason or f"{engine} not installed/configured",
                ),
            )
            return
        checks.append(
            Check(
                logical,
                category,
                list(command),
                partial(text_findings, logical) if parser_fn is None else parser_fn,
                check_timeout or timeout,
                root,
                findings_exit_codes=findings_exit_codes
                if findings_exit_codes is not None
                else {1},
                empty_scope_markers=empty_scope_markers or (),
            ),
        )

    # GitHub Actions: semantic workflow checking plus embedded shell/Python
    # checks when actionlint can find those helpers.
    actionlint = project_executable(root, "actionlint")
    action_files = technology.files.get("github-actions", [])
    action_cmd = (
        [actionlint, "-format", "{{json .}}", *action_files] if actionlint else None
    )
    add_technology(
        "actionlint",
        action_cmd,
        parse_actionlint,
        reason="GitHub Actions detected but actionlint is not installed",
        findings_exit_codes={1},
    )

    shellcheck = project_executable(root, "shellcheck")
    shell_files = technology.files.get("shell", [])
    shell_cmd = (
        [shellcheck, "-f", "json1", *shell_files]
        if shellcheck and shell_files
        else None
    )
    add_technology(
        "shellcheck",
        shell_cmd,
        parse_shellcheck,
        reason="shell scripts detected but ShellCheck is not installed",
        findings_exit_codes={1},
    )

    dotenv = project_executable(root, "dotenv-linter")
    env_files = technology.files.get("dotenv", [])
    dotenv_cmd = [dotenv, "check", *env_files] if dotenv and env_files else None
    add_technology(
        "dotenv-linter",
        dotenv_cmd,
        reason="environment files detected but dotenv-linter is not installed",
        findings_exit_codes={1},
    )
    if (
        "dotenv-linter" in wanted
        and technology.has("dotenv")
        and dotenv
        and ".env" in env_files
        and ".env.example" in env_files
    ):
        checks.append(
            Check(
                "dotenv-linter:contract",
                ENGINE_CATEGORY["dotenv-linter"],
                [dotenv, "diff", ".env", ".env.example"],
                lambda o, e, c: text_findings("dotenv-linter", o, e, c),
                timeout,
                root,
                findings_exit_codes={1},
            ),
        )

    # OpenAPI: validate HEAD and, when the file existed at the selected local
    # Git baseline, test backwards compatibility. This catches temporal bugs
    # which no single-revision linter can see.
    oasdiff = project_executable(root, "oasdiff")
    openapi_files = technology.files.get("openapi", [])
    if "oasdiff" in wanted:
        if not technology.has("openapi"):
            add_technology("oasdiff", None)
        elif not oasdiff:
            add_technology(
                "oasdiff",
                None,
                reason="OpenAPI detected but oasdiff is not installed",
            )
        else:
            for spec in openapi_files:
                safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", spec)
                checks.append(
                    Check(
                        f"oasdiff:validate:{safe_name}",
                        ENGINE_CATEGORY["oasdiff"],
                        [oasdiff, "validate", spec],
                        partial(text_findings, f"oasdiff:validate:{safe_name}"),
                        timeout,
                        root,
                        findings_exit_codes={1},
                    ),
                )
                if technology.git_baseline and git_path_exists(
                    root,
                    technology.git_baseline,
                    spec,
                ):
                    checks.append(
                        Check(
                            f"oasdiff:breaking:{safe_name}",
                            ENGINE_CATEGORY["oasdiff"],
                            [
                                oasdiff,
                                "breaking",
                                "--format",
                                "json",
                                f"{technology.git_baseline}:{spec}",
                                spec,
                            ],
                            partial(parse_json_list, f"oasdiff:breaking:{safe_name}"),
                            timeout,
                            root,
                            findings_exit_codes={1},
                        ),
                    )

    buf = project_executable(root, "buf")
    if "buf" in wanted:
        if not technology.has("protobuf"):
            add_technology("buf", None)
        elif not buf:
            add_technology(
                "buf",
                None,
                reason="Protocol Buffers detected but buf is not installed",
            )
        else:
            buf_cfg = generated_config(root, "buf.yaml")
            lint_cmd = [buf, "lint", ".", "--error-format=json"]
            if buf_cfg:
                lint_cmd += ["--config", str(buf_cfg)]
            checks.append(
                Check(
                    "buf:lint",
                    ENGINE_CATEGORY["buf"],
                    lint_cmd,
                    parse_buf_json_lines,
                    timeout,
                    root,
                    findings_exit_codes={1, 100},
                ),
            )
            if technology.git_baseline:
                breaking_cmd = [
                    buf,
                    "breaking",
                    ".",
                    "--against",
                    f".git#ref={technology.git_baseline}",
                    "--error-format=json",
                ]
                if buf_cfg:
                    breaking_cmd += ["--config", str(buf_cfg)]
                checks.append(
                    Check(
                        "buf:breaking",
                        ENGINE_CATEGORY["buf"],
                        breaking_cmd,
                        parse_buf_json_lines,
                        timeout,
                        root,
                        findings_exit_codes={1, 100},
                    ),
                )

    sqlfluff = project_executable(root, "sqlfluff")
    sql_files = technology.files.get("sql", [])
    sql_cfg = generated_config(root, "sqlfluff.ini")
    sql_cmd = (
        [sqlfluff, "lint", *sql_files, "--format", "json"]
        if sqlfluff and sql_files
        else None
    )
    if sql_cmd and sql_cfg:
        sql_cmd += ["--config", str(sql_cfg)]
    add_technology(
        "sqlfluff",
        sql_cmd,
        parse_sqlfluff,
        reason="SQL detected but SQLFluff is not installed",
        findings_exit_codes={1},
    )

    squawk = project_executable(root, "squawk")
    migration_files = technology.files.get("postgres-migrations", [])
    squawk_cmd = (
        [squawk, "--reporter", "json", *migration_files]
        if squawk and migration_files
        else None
    )
    add_technology(
        "squawk",
        squawk_cmd,
        parse_squawk,
        reason="PostgreSQL migrations detected but Squawk is not installed",
        findings_exit_codes={1},
    )

    hadolint = project_executable(root, "hadolint")
    docker_files = technology.files.get("docker", [])
    hadolint_cfg = generated_config(root, "hadolint.yaml")
    hadolint_cmd = [hadolint, "-f", "json"] if hadolint and docker_files else None
    if hadolint_cmd and hadolint_cfg:
        hadolint_cmd += ["--config", str(hadolint_cfg)]
    if hadolint_cmd:
        hadolint_cmd += docker_files
    add_technology(
        "hadolint",
        hadolint_cmd,
        parse_hadolint,
        reason="Dockerfiles detected but Hadolint is not installed",
        findings_exit_codes={1},
    )

    tflint = project_executable(root, "tflint")
    tflint_cfg = generated_config(root, "tflint.hcl")
    tflint_cmd = [tflint, "--recursive", "--format=json"] if tflint else None
    if tflint_cmd and tflint_cfg:
        tflint_cmd += [f"--config={tflint_cfg}"]
    add_technology(
        "tflint",
        tflint_cmd,
        parse_tflint,
        reason="Terraform detected but TFLint is not installed",
        findings_exit_codes={1},
    )

    golangci = project_executable(root, "golangci-lint")
    go_linters = [
        "errcheck",
        "govet",
        "staticcheck",
        "ineffassign",
        "unused",
        "bodyclose",
        "durationcheck",
        "errorlint",
        "exhaustive",
        "makezero",
        "rowserrcheck",
        "sqlclosecheck",
    ]
    go_cmd = [golangci, "run", "--default=none"] if golangci else None
    if go_cmd:
        for linter in go_linters:
            go_cmd += ["--enable", linter]
        go_cmd += [
            "--output.json.path=stdout",
            "--output.text.path=",
            "--show-stats=false",
            "--issues-exit-code=1",
        ]
    add_technology(
        "golangci-lint",
        go_cmd,
        parse_golangci,
        reason="Go detected but golangci-lint is not installed",
        findings_exit_codes={1},
    )

    cargo = project_executable(root, "cargo")
    clippy_cmd = (
        [
            cargo,
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--message-format=json",
            "--",
            "-D",
            "clippy::correctness",
            "-D",
            "clippy::suspicious",
            "-W",
            "clippy::complexity",
            "-W",
            "clippy::perf",
        ]
        if cargo
        else None
    )
    add_technology(
        "clippy",
        clippy_cmd,
        parse_clippy,
        reason="Rust detected but cargo/clippy is not installed",
        findings_exit_codes={1, 101},
    )

    compile_db = technology.files.get("cpp-compile-db", [])
    cpp_files = technology.files.get("cpp", [])
    cppcheck = project_executable(root, "cppcheck")
    cppcheck_cmd: list[str] | None = None
    if cppcheck:
        cppcheck_cmd = [
            cppcheck,
            "--xml",
            "--xml-version=2",
            "--error-exitcode=1",
            "--enable=warning,performance,portability",
            "--inconclusive",
        ]
        if compile_db:
            cppcheck_cmd += [f"--project={compile_db[0]}"]
        else:
            cppcheck_cmd += cpp_files
    add_technology(
        "cppcheck",
        cppcheck_cmd,
        parse_cppcheck,
        reason="C/C++ detected but Cppcheck is not installed",
        findings_exit_codes={1},
    )

    run_clang_tidy = llvm_executable(root, "run-clang-tidy") or llvm_executable(
        root,
        "run-clang-tidy.py",
    )
    clang_cmd = None
    if run_clang_tidy and compile_db:
        clang_cmd = [
            run_clang_tidy,
            f"-p={Path(compile_db[0]).parent or Path('.')}",
            "-checks=-*,clang-analyzer-*,bugprone-*,concurrency-*",
            "-warnings-as-errors=*",
        ]
    add_technology(
        "clang-tidy",
        clang_cmd,
        reason=(
            "C/C++ compile_commands.json detected but run-clang-tidy is not installed"
            if compile_db
            else "clang-tidy requires compile_commands.json"
        ),
        findings_exit_codes={1},
    )

    infer = project_executable(root, "infer")
    infer_cmd = (
        [
            infer,
            "run",
            "--compilation-database",
            compile_db[0],
            "--fail-on-issue",
            "--results-dir",
            str(root / ".bughunt" / "cache" / "infer"),
        ]
        if infer and compile_db
        else None
    )
    add_technology(
        "infer",
        infer_cmd,
        reason="C/C++ compilation database detected but Infer is not installed",
        findings_exit_codes={2},
    )

    phpstan = project_executable(root, "phpstan")
    php_cfg = generated_config(root, "phpstan.neon")
    php_cmd = (
        [phpstan, "analyse", "--no-progress", "--error-format=json"]
        if phpstan
        else None
    )
    if php_cmd and php_cfg:
        php_cmd += ["--configuration", str(php_cfg)]
    add_technology(
        "phpstan",
        php_cmd,
        parse_phpstan,
        reason="PHP detected but PHPStan is not installed",
        findings_exit_codes={1},
    )

    oxlint = project_executable(root, "oxlint")
    oxlint_cfg = generated_config(root, "oxlintrc.json")
    oxlint_cmd = [oxlint, "--format=json", "--deny-warnings"] if oxlint else None
    if oxlint_cmd:
        # oxlint config-file ignorePatterns cannot address files outside the
        # generated config's own directory (`..` is rejected), so root-relative
        # ignores travel as cwd-relative CLI flags instead. Bare directory
        # names: the `/**` form misbehaves on tracked dot-directories.
        oxlint_cmd += [
            f"--ignore-pattern={p.removesuffix('/**')}" for p in _JS_TOOL_IGNORES
        ]
    if oxlint_cmd and oxlint_cfg:
        oxlint_cmd += ["--config", str(oxlint_cfg)]
    add_technology(
        "oxlint",
        oxlint_cmd,
        parse_oxlint,
        reason="JavaScript/TypeScript detected but Oxlint is not installed",
        findings_exit_codes={1},
        empty_scope_markers=(OXLINT_EMPTY_SCOPE,),
    )

    eslint = project_executable(root, "eslint")
    eslint_cfg = generated_config(root, "eslint.config.mjs")
    existing_eslint = next(
        (
            p
            for p in (
                "eslint.config.js",
                "eslint.config.mjs",
                "eslint.config.cjs",
                ".eslintrc",
                ".eslintrc.json",
                ".eslintrc.js",
            )
            if (root / p).exists()
        ),
        None,
    )
    chosen_eslint = eslint_cfg or (
        (root / existing_eslint) if existing_eslint else None
    )
    eslint_cmd = [eslint, ".", "--format", "json"] if eslint and chosen_eslint else None
    if eslint_cmd and eslint_cfg:
        eslint_cmd += ["--config", str(eslint_cfg)]
    add_technology(
        "eslint",
        eslint_cmd,
        parse_eslint,
        reason=(
            "JavaScript/TypeScript detected but ESLint is not installed"
            if not eslint
            else "ESLint detected but no safe config is available"
        ),
        findings_exit_codes={1},
        empty_scope_markers=(ESLINT_EMPTY_SCOPE,),
    )

    react_doctor = project_executable(root, "react-doctor")
    react_cmd = (
        [react_doctor, ".", "--json", "--no-supply-chain"] if react_doctor else None
    )
    add_technology(
        "react-doctor",
        react_cmd,
        lambda o, e, c: parse_eslint(o, e, c, tool="react-doctor"),
        reason="React detected but React Doctor is not installed",
        findings_exit_codes={1},
    )

    # Additional configuration/contract/language surfaces. These are selected only
    # when technology.py proves the corresponding capability exists.
    tsc = project_executable(root, "tsc")
    add_technology(
        "tsc",
        [tsc, "--noEmit", "--pretty", "false"] if tsc else None,
        reason="TypeScript detected but tsc is not installed",
        findings_exit_codes={1, 2},
    )

    knip = project_executable(root, "knip")
    add_technology(
        "knip",
        [knip, "--strict"] if knip else None,
        reason="JavaScript/TypeScript detected but Knip is not installed",
        findings_exit_codes={1},
    )

    madge = project_executable(root, "madge")
    add_technology(
        "madge",
        [madge, "--circular", "."] if madge else None,
        reason="JavaScript/TypeScript detected but Madge is not installed",
        findings_exit_codes={1},
    )

    publint = project_executable(root, "publint")
    package_json = root / "package.json"
    add_technology(
        "publint",
        [publint, str(package_json)] if publint and package_json.exists() else None,
        reason=(
            "JavaScript package detected but publint is not installed/package.json "
            "missing"
        ),
        findings_exit_codes={1},
    )

    taplo = project_executable(root, "taplo")
    toml_files = technology.files.get("toml", [])
    add_technology(
        "taplo",
        [taplo, "lint", *toml_files] if taplo and toml_files else None,
        reason="TOML detected but Taplo is not installed",
        findings_exit_codes={1},
    )

    yamllint = project_executable(root, "yamllint")
    yaml_files = technology.files.get("yaml", [])
    add_technology(
        "yamllint",
        [
            yamllint,
            "-d",
            (
                "{extends: default, rules: {line-length: disable, truthy: disable, "
                "document-start: disable}}"
            ),
            *yaml_files,
        ]
        if yamllint and yaml_files
        else None,
        reason="YAML detected but yamllint is not installed",
        findings_exit_codes={1},
    )

    if "check-jsonschema" in wanted:
        if not technology.has("schema-ref"):
            add_technology("check-jsonschema", None)
        else:
            checker = project_executable(root, "check-jsonschema")
            pairs = local_schema_pairs(root, technology.files.get("schema-ref", []))
            if checker and pairs:
                for instance, schema in pairs:
                    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", instance)
                    checks.append(
                        Check(
                            f"check-jsonschema:{safe}",
                            ENGINE_CATEGORY["check-jsonschema"],
                            [
                                checker,
                                "--schemafile",
                                schema,
                                "--output-format",
                                "JSON",
                                instance,
                            ],
                            partial(text_findings, f"check-jsonschema:{safe}"),
                            timeout,
                            root,
                            findings_exit_codes={1},
                        ),
                    )
            elif not checker:
                add_technology(
                    "check-jsonschema",
                    None,
                    reason=(
                        "local schema reference detected but check-jsonschema "
                        "is not installed"
                    ),
                )
            else:
                skipped.append(
                    Result(
                        "check-jsonschema",
                        ENGINE_CATEGORY["check-jsonschema"],
                        Status.SKIPPED,
                        note=(
                            "schema references exist, but none "
                            "resolve to a repository-local schema; "
                            "BugHunt refuses to fetch arbitrary "
                            "remote schemas"
                        ),
                    ),
                )

    alembic = project_executable(root, "alembic")
    add_technology(
        "alembic-check",
        [alembic, "check"] if alembic else None,
        reason="Alembic project detected but alembic is not installed",
        findings_exit_codes={1},
    )

    manage = root / "manage.py"
    add_technology(
        "django-migrations",
        [sys.executable, str(manage), "makemigrations", "--check", "--dry-run"]
        if manage.exists()
        else None,
        reason="Django detected but manage.py is unavailable",
        findings_exit_codes={1},
    )

    if "pact-contracts" in wanted:
        if not technology.has("pact"):
            add_technology("pact-contracts", None)
        else:
            pacts = pact_json_files(root, technology.files.get("pact", []))
            asgi = [
                t
                for t in generated_targets
                if t.kind == "schemathesis"
                and (t.metadata or {}).get("transport") == "asgi"
            ]
            pact_ready = python_module_available("pact") and python_module_available(
                "uvicorn",
            )
            if len(asgi) == 1 and pacts and pact_ready:
                app = asgi[0].name
                add_technology(
                    "pact-contracts",
                    [
                        sys.executable,
                        "-m",
                        "bughunt.pact_runner",
                        str(root),
                        app,
                        *pacts,
                    ],
                    lambda o, e, c: parse_bughunt_helper("pact-contracts", o, e, c),
                    reason="Pact contract/provider target unavailable",
                    findings_exit_codes={1},
                    check_timeout=cfg.timeout(profile),
                )
            else:
                reasons = []
                if not pacts:
                    reasons.append("no concrete local Pact JSON files")
                if len(asgi) != 1:
                    reasons.append(
                        f"need exactly one high-confidence local ASGI provider target "
                        f"(found {len(asgi)})",
                    )
                if not pact_ready:
                    reasons.append("pact-python/uvicorn not installed")
                skipped.append(
                    Result(
                        "pact-contracts",
                        ENGINE_CATEGORY["pact-contracts"],
                        Status.SKIPPED,
                        note=(
                            "Pact capability detected but auto-verification "
                            "is guarded: "
                        )
                        + "; ".join(reasons),
                    ),
                )

    return checks, skipped


# trace:v1 id=impl.src-bughunt-cli.liverunstate work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
class LiveRunState:
    """Live heartbeat for long scans; state is updated by async check tasks."""

    def __init__(self, total: int) -> None:
        self.total = total
        self.started_at = time.perf_counter()
        self.running: dict[str, dict[str, Any]] = {}
        self.completed: list[Result] = []

    def start(self, check: Check) -> None:
        now = time.perf_counter()
        self.running[check.name] = {
            "category": check.category,
            "started": now,
            "timeout": check.timeout,
            "last_activity": now,
            "last_line": "spawned process",
            "output_lines": 0,
        }

    def activity(self, name: str, line: str) -> None:
        entry = self.running.get(name)
        if not entry:
            return
        cleaned = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", line).strip()
        if not cleaned:
            return
        entry["last_activity"] = time.perf_counter()
        entry["last_line"] = cleaned[-180:]
        entry["output_lines"] = int(entry.get("output_lines", 0)) + 1

    def finish(self, result: Result) -> None:
        self.running.pop(result.name, None)
        if result.name == "codeql":
            self.running.pop("codeql-db", None)
        self.completed.append(result)

    # trace:v1 id=impl.src-bughunt-cli-liverunstate.render work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
    def render(self) -> Table:
        elapsed = time.perf_counter() - self.started_at
        table = Table(
            title=f"[bold bright_cyan]LIVE BUG HUNT[/]  [dim]{elapsed:.1f}s elapsed[/]",
            box=box.ROUNDED,
            expand=True,
        )
        table.add_column("STATE", width=12)
        table.add_column("DEFENSE", min_width=22)
        table.add_column("CLASS", min_width=16)
        table.add_column("ELAPSED", justify="right", width=10)
        table.add_column("ACTIVITY", ratio=3)

        now = time.perf_counter()
        for name, entry in sorted(
            self.running.items(),
            key=lambda kv: float(kv[1]["started"]),
        ):
            age = now - float(entry["started"])
            quiet = now - float(entry["last_activity"])
            timeout = int(entry["timeout"])
            ratio = age / timeout if timeout else 0
            last = escape(str(entry.get("last_line") or ""))
            if ratio >= 0.9:
                state = "[bold red]▶ RUNNING[/]"
                activity = f"[bold red]near timeout[/] • quiet {quiet:.0f}s • {last}"
            elif quiet >= 120:
                state = "[bold yellow]▶ QUIET[/]"
                activity = f"[yellow]no output for {quiet:.0f}s[/] • last: {last}"
            elif quiet >= 30:
                state = "[cyan]▶ RUNNING[/]"
                activity = f"[yellow]quiet {quiet:.0f}s[/] • last: {last}"
            else:
                state = "[bold cyan]▶ RUNNING[/]"
                activity = f"[cyan]● output {quiet:.0f}s ago[/] • {last}"
            table.add_row(state, name, str(entry["category"]), f"{age:.1f}s", activity)

        for result in self.completed[-8:]:
            glyph = {
                Status.PASS: "[green]✓ PASS[/]",
                Status.FINDINGS: "[yellow]◆ FOUND[/]",
                Status.ERROR: "[red]✕ ERROR[/]",
                Status.SKIPPED: "[dim]○ SKIP[/]",
                Status.NA: "[dim cyan]— N/A[/]",
            }[result.status]
            detail = result.note or (
                f"{result.count} finding(s)" if result.count else "complete"
            )
            table.add_row(
                glyph,
                result.name,
                result.category,
                f"{result.duration:.1f}s",
                escape(detail[:120]),
            )

        completed = len(self.completed)
        queued = max(0, self.total - completed - len(self.running))
        table.caption = (
            f"completed {completed}/{self.total}  •  running {len(self.running)}  •  "
            f"queued {queued}"
        )
        return table


# trace:v1 id=impl.src-bughunt-cli.run-process work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
async def run_process(
    check: Check,
    raw_limit: int,
    progress: LiveRunState | None = None,
) -> Result:
    started = time.perf_counter()
    if progress:
        progress.start(check)

    def finish(result: Result) -> Result:
        if progress:
            progress.running.pop(check.name, None)
            if check.record_progress:
                progress.finish(result)
        return result

    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []

    # trace:v1 id=impl.src-bughunt-cli-run-process.drain work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
    async def drain(stream: asyncio.StreamReader | None, chunks: list[bytes]) -> None:
        if stream is None:
            return
        # Never use readline() here. Several analyzers emit giant single-line JSON
        # payloads; asyncio's StreamReader has a separator limit and used to crash
        # BugHunt itself with LimitOverrunError. Fixed-size reads have no line limit.
        activity_tail = ""
        while True:
            chunk = await stream.read(64 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
            if progress:
                text = activity_tail + chunk.decode(errors="replace")
                parts = text.splitlines()
                if text and not text.endswith(("\n", "\r")):
                    activity_tail = parts.pop()[-300:] if parts else text[-300:]
                else:
                    activity_tail = ""
                meaningful = next(
                    (line.strip() for line in reversed(parts) if line.strip()),
                    "",
                )
                if not meaningful and activity_tail.strip():
                    meaningful = activity_tail.strip()
                if meaningful:
                    progress.activity(check.name, meaningful[-500:])
        if progress and activity_tail.strip():
            progress.activity(check.name, activity_tail.strip()[-500:])

    try:
        proc = await asyncio.create_subprocess_exec(
            *check.command,
            cwd=str(check.cwd),
            env={**os.environ, **(check.env or {})},
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out_task = asyncio.create_task(drain(proc.stdout, stdout_chunks))
        err_task = asyncio.create_task(drain(proc.stderr, stderr_chunks))
        try:
            await asyncio.wait_for(proc.wait(), timeout=check.timeout)
            await asyncio.gather(out_task, err_task)
        except TimeoutError:
            proc.kill()
            await proc.wait()
            await asyncio.gather(out_task, err_task, return_exceptions=True)
            stdout = b"".join(stdout_chunks).decode(errors="replace")
            stderr = b"".join(stderr_chunks).decode(errors="replace")
            timeout_findings: list[Finding] = []
            try:
                timeout_findings = check.parser(stdout, stderr, 0)
            except Exception:  # noqa: BLE001 - parser isolation: a parser crash must not kill the runner
                timeout_findings = []
            status = (
                (Status.FINDINGS if timeout_findings else Status.PASS)
                if check.timeout_is_success
                else Status.ERROR
            )
            note = (
                f"search budget exhausted after {check.timeout}s"
                if check.timeout_is_success
                else f"timed out after {check.timeout}s"
            )
            return finish(
                Result(
                    name=check.name,
                    category=check.category,
                    status=status,
                    duration=time.perf_counter() - started,
                    command=check.command,
                    stdout=stdout[-raw_limit:],
                    stderr=stderr[-raw_limit:],
                    findings=timeout_findings,
                    note=note,
                    environment=dict(check.env or {}),
                ),
            )
    except (FileNotFoundError, PermissionError, OSError) as exc:
        return finish(
            Result(
                name=check.name,
                category=check.category,
                status=Status.ERROR,
                duration=time.perf_counter() - started,
                command=check.command,
                note=f"could not execute: {exc}",
            ),
        )

    stdout = b"".join(stdout_chunks).decode(errors="replace")
    stderr = b"".join(stderr_chunks).decode(errors="replace")
    exit_code = int(proc.returncode or 0)
    findings: list[Finding] = []
    parse_error: str | None = None
    try:
        findings = check.parser(stdout, stderr, exit_code)
    except Exception as exc:  # noqa: BLE001 - parser isolation: failure is recorded in the result note
        parse_error = f"output parser failed: {type(exc).__name__}: {exc}"

    if parse_error:
        status = Status.ERROR
    elif not findings and any(
        m in stdout or m in stderr for m in check.empty_scope_markers
    ):
        status = Status.SKIPPED
        parse_error = f"exited {exit_code}: nothing in scope"
    elif exit_code == 0:
        status = Status.FINDINGS if findings else Status.PASS
    elif exit_code in check.findings_exit_codes:
        status = Status.FINDINGS
        if not findings:
            findings = [
                Finding(
                    tool=check.name,
                    message=f"{check.name} exited {exit_code} with findings",
                )
            ]
    elif exit_code in check.skip_exit_codes:
        status = Status.SKIPPED
        parse_error = f"exited {exit_code}: nothing collected"
    else:
        status = Status.ERROR

    return finish(
        Result(
            name=check.name,
            category=check.category,
            status=status,
            duration=time.perf_counter() - started,
            exit_code=exit_code,
            findings=findings,
            command=check.command,
            stdout=stdout[-raw_limit:],
            stderr=stderr[-raw_limit:],
            note=parse_error,
            environment=dict(check.env or {}),
        ),
    )


# trace:v1 id=impl.src-bughunt-cli.run-parallel work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
async def run_parallel(
    checks: list[Check],
    max_parallel: int,
    raw_limit: int,
    progress: LiveRunState | None = None,
) -> list[Result]:
    sem = asyncio.Semaphore(max_parallel)

    async def one(check: Check) -> Result:
        async with sem:
            return await run_process(check, raw_limit, progress)

    return await asyncio.gather(*(one(c) for c in checks))


# trace:v1 id=impl.src-bughunt-cli.reset-tool-dir work=WORK-BUG-4ABH9VEY satisfies=REQ-BUG-KZG483AX implements=PLAN-BUG-560GXA79
def _reset_tool_dir(path: Path) -> None:
    """Best-effort writable recursive delete for tool output trees.

    Analyzer database directories routinely contain read-only files that make
    the tool's own overwrite/delete step fail (observed: CodeQL
    MultiIOException on the second consecutive scan). Making the tree writable
    first lets our own removal succeed; leftovers are the tool's problem.
    """
    if not path.exists():
        return
    try:
        subprocess.run(
            ["chmod", "-R", "u+w", str(path)],
            capture_output=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        pass
    shutil.rmtree(path, ignore_errors=True)


# trace:v1 id=impl.src-bughunt-cli.run-codeql work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
async def run_codeql(
    cfg: Config,
    profile: str,
    raw_limit: int,
    progress: LiveRunState | None = None,
) -> Result:
    if "codeql" not in cfg.tools(profile):
        return Result("codeql", "whole-program", Status.SKIPPED, note="not in profile")
    ql = executable("codeql")
    if not ql:
        return Result(
            "codeql",
            "whole-program",
            Status.SKIPPED,
            note="codeql CLI not installed",
        )

    language = "python"
    db = cfg.root / CACHE_DIR / "codeql" / language
    sarif = cfg.root / CACHE_DIR / "codeql" / f"{language}.sarif"
    db.parent.mkdir(parents=True, exist_ok=True)
    _reset_tool_dir(db)

    suite = cfg.raw.get("codeql", {}).get(
        "python_suite",
        "codeql/python-queries:codeql-suites/python-security-and-quality.qls",
    )
    started = time.perf_counter()

    source_roots = [cfg.root / p for p in cfg.source_paths if (cfg.root / p).exists()]
    codeql_source_root = (
        source_roots[0]
        if len(source_roots) == 1 and source_roots[0].is_dir()
        else cfg.root
    )

    create = Check(
        "codeql-db",
        "whole-program",
        [
            ql,
            "database",
            "create",
            str(db),
            "--language=python",
            "--source-root",
            str(codeql_source_root),
            "--overwrite",
        ],
        lambda o, e, c: [],
        cfg.timeout(profile),
        cfg.root,
        findings_exit_codes=set(),
        record_progress=False,
    )
    cr = await run_process(create, raw_limit, progress)
    if cr.status == Status.ERROR:
        cr.name = "codeql"
        cr.note = "database creation failed" + (f": {cr.note}" if cr.note else "")
        return cr

    custom_query_dir = cfg.root / ".bughunt" / "configs" / "codeql" / "queries"
    custom_queries = (
        sorted(str(path) for path in custom_query_dir.rglob("*.ql"))
        if custom_query_dir.exists()
        else []
    )
    analyze_targets = [str(suite), *custom_queries]
    analyze = Check(
        "codeql",
        "whole-program",
        [
            ql,
            "database",
            "analyze",
            str(db),
            *analyze_targets,
            "--format=sarif-latest",
            f"--output={sarif}",
            "--download",
        ],
        lambda o, e, c: [],
        cfg.timeout(profile),
        cfg.root,
        findings_exit_codes=set(),
        record_progress=False,
    )
    ar = await run_process(analyze, raw_limit, progress)
    ar.duration = time.perf_counter() - started
    ar.artifacts.append(str(sarif))
    if ar.status == Status.ERROR:
        return ar
    ar.findings = parse_sarif(sarif, "codeql")
    ar.status = Status.FINDINGS if ar.findings else Status.PASS
    return ar


def pysa_executable(root: Path) -> str | None:
    """Prefer BugHunt's isolated Pysa runtime over the project's Pyre CLI."""
    private = root / ".bughunt" / "runtime" / "pysa-venv" / "bin" / "pyre"
    if private.exists() and os.access(private, os.X_OK):
        return str(private)
    return executable("pyre")


# trace:v1 id=impl.src-bughunt-cli.run-pysa work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
async def run_pysa(
    cfg: Config,
    profile: str,
    raw_limit: int,
    progress: LiveRunState | None = None,
) -> Result:
    if "pysa" not in cfg.tools(profile):
        return Result("pysa", "taint", Status.SKIPPED, note="not in profile")
    pyre = pysa_executable(cfg.root)
    if not pyre:
        return Result(
            "pysa",
            "taint",
            Status.SKIPPED,
            note="Pysa/Pyre not installed; run `uv run bughunt install --only pysa`",
        )
    if not (cfg.root / ".pyre_configuration").exists():
        return Result(
            "pysa",
            "taint",
            Status.SKIPPED,
            note="no .pyre_configuration / Pysa models configured",
        )

    out_dir = cfg.root / CACHE_DIR / "pysa"
    out_dir.mkdir(parents=True, exist_ok=True)
    # pyre-check's historical Click CLI has a known enum-default compatibility
    # failure with newer Click releases. Explicit values protect even fallback
    # project installs; the private runtime additionally pins Click<8.2.
    cmd = [
        pyre,
        "--version=none",
        "--noninteractive",
        "analyze",
        "--version=none",
        "--save-results-to",
        str(out_dir),
    ]

    check = Check(
        "pysa",
        "taint",
        cmd,
        lambda o, e, c: parse_json_list("pysa", o, e, c),
        cfg.timeout(profile),
        cfg.root,
        findings_exit_codes={1},
        record_progress=False,
    )
    result = await run_process(check, raw_limit, progress)
    result.artifacts.append(str(out_dir))

    if not result.findings and result.stdout:
        text = result.stdout
        first, last = text.find("["), text.rfind("]")
        if 0 <= first < last:
            try:
                payload = json.loads(text[first : last + 1])
                result.findings = parse_json_list("pysa", json.dumps(payload), "", 0)
                if result.findings:
                    result.status = Status.FINDINGS
            except json.JSONDecodeError:
                pass
    return result


# trace:v1 id=impl.src-bughunt-cli.run-mutmut work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
async def run_mutmut(
    cfg: Config,
    profile: str,
    raw_limit: int,
    progress: LiveRunState | None = None,
) -> Result:
    if "mutmut" not in cfg.tools(profile):
        return Result("mutmut", "mutation", Status.SKIPPED, note="not in profile")
    mm = executable("mutmut")
    if not mm:
        return Result("mutmut", "mutation", Status.SKIPPED, note="mutmut not installed")
    if not cfg.raw.get("mutmut", {}).get("enabled", True):
        return Result(
            "mutmut",
            "mutation",
            Status.SKIPPED,
            note="disabled in bughunt.toml",
        )

    run = Check(
        "mutmut",
        "mutation",
        [mm, "run"],
        lambda o, e, c: [],
        cfg.timeout(profile),
        cfg.root,
        findings_exit_codes=set(),
        record_progress=False,
    )
    rr = await run_process(run, raw_limit, progress)
    if rr.status == Status.ERROR:
        return rr

    result_check = Check(
        "mutmut-results",
        "mutation",
        [mm, "results"],
        lambda o, e, c: [],
        120,
        cfg.root,
        findings_exit_codes=set(),
        record_progress=False,
    )
    rs = await run_process(result_check, raw_limit, progress)
    combined = (rs.stdout + "\n" + rs.stderr).strip()
    findings: list[Finding] = []

    # mutmut 3 output includes status groupings; conservatively treat survived
    # and suspicious mutants as findings.
    for line in combined.splitlines():
        low = line.lower()
        if "survived" in low or "suspicious" in low:
            findings.append(
                Finding(tool="mutmut", message=line.strip(), severity="warning"),
            )

    return Result(
        name="mutmut",
        category="mutation",
        status=Status.FINDINGS if findings else Status.PASS,
        duration=rr.duration + rs.duration,
        exit_code=rr.exit_code,
        findings=findings,
        command=rr.command,
        stdout=(rr.stdout + "\n\n--- mutmut results ---\n" + combined)[-raw_limit:],
        stderr=rr.stderr[-raw_limit:],
    )


def status_style(status: Status) -> str:
    return {
        Status.PASS: "bold green",
        Status.FINDINGS: "bold yellow",
        Status.ERROR: "bold red",
        Status.SKIPPED: "dim",
        Status.NA: "dim cyan",
    }[status]


def overall_score(results: list[Result]) -> int:
    applicable = [result for result in results if result.status != Status.NA]
    if not applicable:
        return 100
    # N/A defenses do not count against a repository: Rust tooling is not a
    # blind spot in a Python-only project. Skipped *applicable* defenses are.
    weight = {
        Status.PASS: 1.0,
        Status.FINDINGS: 0.65,
        Status.SKIPPED: 0.20,
        Status.ERROR: 0.0,
    }
    return round(100 * sum(weight[r.status] for r in applicable) / len(applicable))


# trace:v1 id=impl.src-bughunt-cli.canonical-finding-path work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def canonical_finding_path(root: Path, raw: str | None) -> str | None:
    """Canonicalize tool paths so absolute/relative spellings collapse together."""
    if not raw:
        return raw
    value = raw.removeprefix("file://")
    path = Path(value)
    try:
        if path.is_absolute():
            return (
                path.resolve(strict=False)
                .relative_to(root.resolve(strict=False))
                .as_posix()
            )
    except ValueError:
        return path.as_posix()
    normalized = path.as_posix().lstrip("./")
    if (root / normalized).exists():
        return normalized
    # CodeQL databases rooted at `src/` can emit package-relative paths.
    candidate = Path("src") / normalized
    if (root / candidate).exists():
        return candidate.as_posix()
    return normalized


_TRACE_MARKER_LINE = re.compile(r"^\s*(?:#\s*|<!--\s*)trace:(?:v1|exempt)\b")


# trace:v1 id=impl.src-bughunt-cli.finding-on-trace-marker work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _finding_on_trace_marker(
    root: Path, finding: Finding, cache: dict[str, list[str]]
) -> bool:
    """True when a finding points at a TraceLayer marker line.

    Marker lines carry trace identity, never product logic, so no analyzer
    verdict about them is actionable. The scan exempts them centrally here
    instead of scattering per-tool suppressions.
    """
    if not finding.path or not finding.line:
        return False
    lines = cache.get(finding.path)
    if lines is None:
        try:
            lines = (root / finding.path).read_text(errors="replace").splitlines()
        except OSError:
            lines = []
        cache[finding.path] = lines
    if not 1 <= finding.line <= len(lines):
        return False
    return _TRACE_MARKER_LINE.match(lines[finding.line - 1]) is not None


# trace:v1 id=impl.src-bughunt-cli.canonicalize-findings work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def canonicalize_findings(root: Path, results: list[Result]) -> None:
    cache: dict[str, list[str]] = {}
    for result in results:
        kept = []
        for finding in result.findings:
            finding.path = canonical_finding_path(root, finding.path)
            if _finding_on_trace_marker(root, finding, cache):
                continue
            kept.append(finding)
        result.findings = kept


# trace:v1 id=impl.src-bughunt-cli.severity-priority work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def severity_priority(value: str) -> int:
    return {
        "critical": 0,
        "high": 0,
        "error": 0,
        "warning": 1,
        "medium": 1,
        "note": 2,
        "low": 2,
        "info": 3,
    }.get(value.lower(), 1)


# trace:v1 id=impl.src-bughunt-cli.signal-groups work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def signal_groups(results: list[Result]) -> list[dict[str, Any]]:
    grouped: dict[str, list[Finding]] = {}
    for result in results:
        for finding in result.findings:
            grouped.setdefault(finding.signal_key, []).append(finding)
    out: list[dict[str, Any]] = []
    for key, findings in grouped.items():
        first = findings[0]
        locations = []
        for f in findings[:8]:
            if f.path:
                locations.append(f"{f.path}:{f.line or '?'}")
        out.append(
            {
                "key": key,
                "count": len(findings),
                "tool": first.tool,
                "code": first.code,
                "message": first.message,
                "severity": first.severity,
                "locations": locations,
                "finding_ids": [f.finding_id for f in findings],
            },
        )
    return sorted(
        out,
        key=lambda g: (
            severity_priority(str(g["severity"])),
            -g["count"],
            g["tool"],
            g.get("code") or g["message"],
        ),
    )


# trace:v1 id=impl.src-bughunt-cli.signal-label work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def signal_label(group: dict[str, Any], max_len: int = 88) -> str:
    base = (
        f"{group['tool']}:{group['code']}" if group.get("code") else str(group["tool"])
    )
    key = str(group.get("key") or base)
    label = key if key != base else base
    return label if len(label) <= max_len else label[: max_len - 1] + "…"


def hotspot_files(results: list[Result]) -> list[tuple[str, int]]:
    counter: Counter[str] = Counter()
    for result in results:
        for finding in result.findings:
            if finding.path:
                counter[finding.path] += 1
    return counter.most_common(20)


# trace:v1 id=impl.src-bughunt-cli.autofix-summary work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def autofix_summary(results: list[Result]) -> dict[str, Any]:
    fixable = [
        finding for result in results for finding in result.findings if finding.fixable
    ]
    safe = [
        finding for finding in fixable if (finding.fix_safety or "").lower() == "safe"
    ]
    unsafe = [
        finding for finding in fixable if (finding.fix_safety or "").lower() == "unsafe"
    ]
    review = [
        finding for finding in fixable if finding not in safe and finding not in unsafe
    ]
    by_tool = Counter(finding.tool for finding in fixable)
    return {
        "total": len(fixable),
        "safe": len(safe),
        "unsafe": len(unsafe),
        "review": len(review),
        "by_tool": dict(by_tool.most_common()),
        "finding_ids": [finding.finding_id for finding in fixable],
    }


# trace:v1 id=impl.src-bughunt-cli.agent-queue work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def agent_queue(results: list[Result]) -> list[dict[str, Any]]:
    command_by_tool: dict[str, list[str]] = {}
    correlations = correlated_issue_groups(results)
    correlation_ids = {
        (str(g["path"]), int(g["line"])): f"CORR-{i:04d}"
        for i, g in enumerate(correlations, 1)
    }
    for result in results:
        command_by_tool[result.name] = result.command
        command_by_tool.setdefault(result.name.split(":", 1)[0], result.command)
    severity_rank = {
        "error": 0,
        "high": 0,
        "warning": 1,
        "medium": 1,
        "note": 2,
        "low": 2,
    }
    items: list[dict[str, Any]] = []
    for result in results:
        for finding in result.findings:
            verify = (
                command_by_tool.get(result.name)
                or command_by_tool.get(finding.tool)
                or []
            )
            items.append(
                {
                    "id": finding.finding_id,
                    "state": "todo",
                    "tool": finding.tool,
                    "result": result.name,
                    "category": result.category,
                    "odc_class": odc_class(result.category, finding),
                    "signal_key": finding.signal_key,
                    "severity": finding.severity,
                    "code": finding.code,
                    "path": finding.path,
                    "line": finding.line,
                    "column": finding.column,
                    "message": finding.message,
                    "fingerprint": finding.fingerprint,
                    "correlation_id": correlation_ids.get(
                        (finding.path or "", finding.line or 0),
                    ),
                    "fixable": finding.fixable,
                    "fix_safety": finding.fix_safety,
                    "fix_preview": finding.fix_preview,
                    "verification_command": verify,
                    "workflow": [
                        "inspect the finding and surrounding code",
                        (
                            "determine whether it is a true defect, "
                            "duplicate, or analyzer false positive"
                        ),
                        "fix the root cause rather than suppressing the symptom",
                        "run verification_command",
                        "run the narrowest relevant tests",
                        (
                            "if this is a real escaped bug, teach "
                            "Bug Corpus the bug family/detector"
                        ),
                    ],
                },
            )
    return sorted(
        items,
        key=lambda x: (
            severity_rank.get(str(x["severity"]).lower(), 1),
            x["path"] or "",
            x["line"] or 0,
            x["tool"],
        ),
    )


# trace:v1 id=impl.src-bughunt-cli.coverage-summary-from-results work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def coverage_summary_from_results(results: list[Result]) -> dict[str, Any]:
    result = next((r for r in results if r.name == "coverage"), None)
    if not result or not result.stdout:
        return {}
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {}
    return (
        dict(payload.get("summary", {}))
        if isinstance(payload, dict) and isinstance(payload.get("summary"), dict)
        else {}
    )


# trace:v1 id=impl.src-bughunt-cli.risk-map work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def risk_map(results: list[Result]) -> list[dict[str, Any]]:
    """Coverage-weighted per-file risk map for agents/V2.

    This is prioritization, not a probability model: uncovered code, branch gaps,
    independent-tool agreement and complexity raise a file's attention score.
    """
    by_file: dict[str, dict[str, Any]] = {}
    sev_weight = {
        "critical": 8,
        "high": 8,
        "error": 6,
        "warning": 3,
        "medium": 3,
        "note": 1,
        "low": 1,
        "info": 1,
    }
    for result in results:
        for f in result.findings:
            if not f.path:
                continue
            row = by_file.setdefault(
                f.path,
                {
                    "path": f.path,
                    "score": 0,
                    "findings": 0,
                    "tools": set(),
                    "coverage_gaps": 0,
                    "branch_gaps": 0,
                    "complexity_signals": 0,
                    "odc": Counter(),
                },
            )
            row["findings"] += 1
            row["tools"].add(f.tool)
            row["score"] += sev_weight.get(f.severity.lower(), 3)
            row["odc"][odc_class(result.category, f)] += 1
            if f.code == "BHCOV001":
                row["coverage_gaps"] += 1
                row["score"] += 12
            elif f.code == "BHCOV002":
                row["branch_gaps"] += 1
                row["score"] += 16
            if "complex" in result.category or str(f.code or "").startswith("BHCX"):
                row["complexity_signals"] += 1
                row["score"] += 5
    out: list[dict[str, Any]] = []
    for row in by_file.values():
        diversity = len(row["tools"])
        row["score"] += max(0, diversity - 1) * 8
        row["tools"] = sorted(row["tools"])
        row["tool_count"] = diversity
        row["odc"] = dict(row["odc"].most_common())
        out.append(row)
    return sorted(
        out,
        key=lambda x: (-int(x["score"]), -int(x["tool_count"]), str(x["path"])),
    )


# trace:v1 id=impl.src-bughunt-cli.render-terminal work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def render_terminal(
    results: list[Result],
    profile: str,
    elapsed: float,
    report_md: Path,
    report_json: Path,
) -> None:
    counts = Counter(r.status for r in results)
    findings_total = sum(r.count for r in results)
    score = overall_score(results)
    groups = signal_groups(results)
    hotspots = hotspot_files(results)
    fixes = autofix_summary(results)
    correlations = correlated_issue_groups(results)
    logical = logical_issue_groups(results)
    coverage_summary = coverage_summary_from_results(results)

    title = Text()
    title.append("◈ ", style="bold bright_cyan")
    title.append("ZERO-BUG HUNT", style="bold white")
    title.append("  //  ", style="dim")
    title.append(profile.upper(), style="bold bright_magenta")

    subtitle = (
        f"[bold]{len(results)}[/] defenses  •  "
        f"[green]{counts[Status.PASS]} passed[/]  •  "
        f"[yellow]{counts[Status.FINDINGS]} with findings[/]  •  "
        f"[red]{counts[Status.ERROR]} failed[/]  •  "
        f"[dim]{counts[Status.SKIPPED]} unavailable[/]  •  "
        f"[cyan]{counts[Status.NA]} not applicable[/]\n"
        f"[bold]{findings_total}[/] raw normalized findings  •  "
        f"[bold]{len(logical)}[/] logical issue clusters  •  "
        f"[bold]{len(groups)}[/] distinct signals  •  "
        f"[bold]{len(correlations)}[/] cross-tool correlated locations  •  "
        f"{elapsed:.1f}s\n"
        f"[bold green]{fixes['safe']} safe auto-fixable[/]  •  "
        f"[yellow]{fixes['unsafe'] + fixes['review']} review/unsafe "
        "auto-fixable[/]  •  "
        f"[bold]{fixes['total']} total deterministic fixes[/]"
        + (
            f" [dim]({fixes['total'] / findings_total * 100:.1f}% of findings)[/]"
            if findings_total
            else ""
        )
        + (
            f"\n[bold]Coverage[/] "
            f"{float(coverage_summary.get('percent_covered', 0.0)):.1f}%"
            f"  •  {coverage_summary.get('missing_lines', '?')} missing lines"
            f"  •  {coverage_summary.get('missing_branches', '?')} missing branch edges"
            if coverage_summary.get("percent_covered") is not None
            else ""
        )
    )
    console.print()
    console.print(
        Panel(subtitle, title=title, border_style="bright_cyan", padding=(1, 2)),
    )

    bar = ProgressBar(total=100, completed=score, width=60)
    health = Table.grid(expand=True)
    health.add_column(ratio=1)
    health.add_column(justify="right")
    health.add_row(
        Text("DEFENSE HEALTH", style="bold"),
        Text(f"{score}/100", style="bold bright_cyan"),
    )
    health.add_row(
        bar,
        Text("execution coverage, not bug-free probability", style="dim italic"),
    )
    console.print(Panel(health, border_style="blue"))

    table = Table(
        title="Defense Rings",
        box=box.ROUNDED,
        header_style="bold bright_cyan",
        expand=True,
    )
    table.add_column("STATUS", width=11)
    table.add_column("DEFENSE", min_width=16)
    table.add_column("CLASS", min_width=14)
    table.add_column("HITS", justify="right", width=7)
    table.add_column("FIX", justify="right", width=7)
    table.add_column("TIME", justify="right", width=9)
    table.add_column("NOTE", ratio=2)
    order = {
        Status.ERROR: 0,
        Status.FINDINGS: 1,
        Status.PASS: 2,
        Status.SKIPPED: 3,
        Status.NA: 4,
    }
    for r in sorted(results, key=lambda x: (order[x.status], x.category, x.name)):
        glyph = {
            Status.PASS: "✓ PASS",
            Status.FINDINGS: "◆ FOUND",
            Status.ERROR: "✕ ERROR",
            Status.SKIPPED: "○ SKIP",
            Status.NA: "— N/A",
        }[r.status]
        note = r.note or ""
        if r.status == Status.FINDINGS and r.findings:
            first = r.findings[0]
            where = (
                f"{first.path}:{first.line}"
                if first.path and first.line
                else (first.path or "")
            )
            note = f"{where} {first.message}".strip()
            if len(note) > 96:
                note = note[:93] + "..."
        fix_count = sum(1 for finding in r.findings if finding.fixable)
        table.add_row(
            Text(glyph, style=status_style(r.status)),
            r.name,
            r.category,
            str(r.count) if r.count else "—",
            str(fix_count) if fix_count else "—",
            f"{r.duration:.1f}s" if r.duration else "—",
            Text(
                note,
                style="dim" if r.status in {Status.SKIPPED, Status.NA} else "none",
            ),
        )
    console.print(table)

    if fixes["total"]:
        tool_bits = "  •  ".join(
            f"{count}× {tool}" for tool, count in list(fixes["by_tool"].items())[:6]
        )
        fix_text = (
            f"[bold green]{fixes['safe']} safe[/] can be applied by deterministic "
            "tool fixes  •  "
            f"[yellow]{fixes['unsafe']} unsafe[/]  •  [yellow]{fixes['review']} "
            "rule/review[/]\n"
            f"[dim]{tool_bits}[/]"
        )
        console.print(
            Panel(
                fix_text,
                title="[bold]Auto-fix Availability[/]",
                border_style="green",
            ),
        )

    if groups:
        freq = Table(
            title="Top Bug Signals (severity, then frequency)",
            box=box.SIMPLE_HEAVY,
            expand=True,
        )
        freq.add_column("COUNT", justify="right", style="bold yellow", width=7)
        freq.add_column("SIGNAL", min_width=28)
        freq.add_column("EXAMPLE", ratio=2)
        for g in groups[:10]:
            label = signal_label(g)
            example = g["message"]
            if g["locations"]:
                example += f"  [dim]({g['locations'][0]})[/]"
            freq.add_row(f"×{g['count']}", label, example[:160])
        console.print(freq)
        low = sorted(
            (g for g in groups if severity_priority(str(g["severity"])) >= 2),
            key=lambda g: (-g["count"], g["tool"]),
        )[:5]
        if low:
            noise = Table(
                title="Most Frequent Low-Priority / Style Diagnostics",
                box=box.SIMPLE,
                expand=True,
            )
            noise.add_column("COUNT", justify="right", width=7)
            noise.add_column("SIGNAL", min_width=28)
            noise.add_column("EXAMPLE", ratio=2)
            for g in low:
                label = signal_label(g)
                noise.add_row(f"×{g['count']}", label, str(g["message"])[:140])
            console.print(noise)

    if hotspots:
        hot = "  •  ".join(f"[bold]{count}×[/] {path}" for path, count in hotspots[:5])
        console.print(Panel(hot, title="[bold]Hot Files[/]", border_style="yellow"))

    failures = [r for r in results if r.status == Status.ERROR]
    if failures:
        errors = Table(title="Execution Failures", box=box.SIMPLE_HEAVY, expand=True)
        errors.add_column("DEFENSE")
        errors.add_column("DETAIL")
        for r in failures[:10]:
            errors.add_row(
                f"[red]{r.name}[/]",
                r.note
                or (
                    r.stderr.strip().splitlines()[-1]
                    if r.stderr.strip()
                    else "tool failed"
                ),
            )
        console.print(errors)
        console.print(
            "[yellow]CI/debugging hint:[/] if a tool/test is hanging, flaky, "
            "environment-dependent, or failing for unclear infrastructure reasons, "
            "use the [bold]ci-fix-dont-freeze[/] skill before weakening or "
            "disabling the defense.",
        )

    verdict = "CLEAN ACROSS EXECUTED DEFENSES"
    style = "bold green"
    if counts[Status.ERROR]:
        verdict = "INCOMPLETE — ONE OR MORE DEFENSES FAILED TO EXECUTE"
        style = "bold red"
    elif counts[Status.FINDINGS]:
        verdict = "BUG SIGNALS FOUND — AGENT FIX QUEUE READY"
        style = "bold yellow"
    elif counts[Status.SKIPPED]:
        verdict = "NO FINDINGS IN EXECUTED DEFENSES — BLIND SPOTS REMAIN"
        style = "bold yellow"

    footer = Text()
    footer.append(verdict + "\n", style=style)
    footer.append(f"Human report    {report_md}\n", style="dim")
    footer.append(f"Machine report  {report_json}\n", style="dim")
    footer.append(
        f"Agent queue     {report_md.parent / 'agent' / 'FIX_QUEUE.md'}",
        style="bold bright_cyan",
    )
    console.print(Panel(footer, border_style="bright_magenta", padding=(1, 2)))
    console.print(
        (
            "[dim]Debugging protocol:[/] if a defense is hanging, flaky, "
            "environment-dependent, or failing for unclear CI/infrastructure "
            "reasons, use the [bold]ci-fix-dont-freeze[/] skill before "
            "weakening, skipping, quarantining, or disabling it."
        ),
    )
    console.print()


def result_to_dict(r: Result) -> dict[str, Any]:
    d = dataclasses.asdict(r)
    d["status"] = r.status.value
    return d


# trace:v1 id=impl.src-bughunt-cli.write-reports work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def write_reports(
    cfg: Config,
    results: list[Result],
    profile: str,
    elapsed: float,
) -> tuple[Path, Path]:
    now = dt.datetime.now().astimezone()
    stamp = now.strftime("%Y%m%d-%H%M%S")
    out = cfg.root / REPORT_DIR / stamp
    agent_dir = out / "agent"
    tasks_dir = agent_dir / "tasks"
    tasks_dir.mkdir(parents=True, exist_ok=True)

    groups = signal_groups(results)
    queue = agent_queue(results)
    hotspots = hotspot_files(results)
    fixes = autofix_summary(results)
    correlations = correlated_issue_groups(results)
    logical_issues = logical_issue_groups(results)
    risks = risk_map(results)
    odc_counts: Counter[str] = Counter()
    for result in results:
        for finding in result.findings:
            odc_counts[odc_class(result.category, finding)] += 1
    payload: dict[str, Any] = {
        "schema_version": 2,
        "generated_at": now.isoformat(),
        "profile": profile,
        "root": str(cfg.root),
        "elapsed_seconds": elapsed,
        "defense_health": overall_score(results),
        "summary": {
            "tools": len(results),
            "passed": sum(r.status == Status.PASS for r in results),
            "with_findings": sum(r.status == Status.FINDINGS for r in results),
            "errors": sum(r.status == Status.ERROR for r in results),
            "skipped": sum(r.status == Status.SKIPPED for r in results),
            "not_applicable": sum(r.status == Status.NA for r in results),
            "findings": sum(r.count for r in results),
            "distinct_signals": len(groups),
            "autofixable": fixes["total"],
            "safe_autofixable": fixes["safe"],
            "unsafe_autofixable": fixes["unsafe"],
            "review_autofixable": fixes["review"],
            "correlated_issue_locations": len(correlations),
            "logical_issue_clusters": len(logical_issues),
            "raw_to_logical_ratio": (
                sum(r.count for r in results) / len(logical_issues)
            )
            if logical_issues
            else 0.0,
        },
        "coverage": coverage_summary_from_results(results),
        "odc_taxonomy": dict(odc_counts.most_common()),
        "correlated_issues": correlations,
        "logical_issues": logical_issues,
        "risk_map": risks,
        "autofix": fixes,
        "top_signals": groups,
        "hotspots": [{"path": p, "count": c} for p, c in hotspots],
        "agent_queue": queue,
        "results": [result_to_dict(r) for r in results],
    }

    json_path = out / "report.json"
    json_path.write_text(json.dumps(payload, indent=2, default=str))
    (out / "findings.jsonl").write_text(
        "\n".join(json.dumps(item, default=str) for item in queue)
        + ("\n" if queue else ""),
    )
    (agent_dir / "queue.json").write_text(
        json.dumps(
            {
                "schema_version": 3,
                "autofix": fixes,
                "correlated_issues": correlations,
                "risk_map": risks,
                "items": queue,
            },
            indent=2,
        ),
    )
    (agent_dir / "risk-map.json").write_text(
        json.dumps({"schema_version": 1, "files": risks}, indent=2),
    )
    risk_lines = [
        "# BugHunt Coverage-weighted Risk Map",
        "",
        (
            "This is a prioritization score, not a probability "
            "of bugs. Coverage/branch gaps, complexity and independent-tool "
            "agreement raise priority."
        ),
        "",
        "| Rank | Score | File | Tools | Findings | Coverage | Branch |",
        "|---:|---:|---|---:|---:|---:|---:|",
    ]
    for i, item in enumerate(risks[:200], 1):
        risk_lines.append(
            (
                f"| {i} | {item['score']} | `{item['path']}` | {item['tool_count']} | "
                f"{item['findings']} | {item['coverage_gaps']} | "
                f"{item['branch_gaps']} |"
            ),
        )
    (agent_dir / "RISK_MAP.md").write_text("\n".join(risk_lines) + "\n")

    agent_instructions = """# BugHunt Agent Instructions

You are fixing a BugHunt report. Treat `queue.json` as the machine-readable source of
truth.

Work in this order:

1. Start with execution errors because an analyzer that did not run leaves a blind spot.
2. Then process `queue.json` in order. Fix one finding or coherent repeated-signal
cluster at a time.
3. Inspect the surrounding code before editing. Do not blindly obey analyzer text.
4. Fix root causes. Do not add `noqa`, type ignores, Semgrep suppressions, or
broad exclusions unless the finding is proven false-positive and the suppression
is narrowly justified.
5. Run each item's `verification_command` after the fix, then the narrowest
relevant tests.
6. Re-run BugHunt after a cluster is cleared; line movement can make stale
report locations inaccurate.
7. If a finding reveals a genuine bug that escaped existing defenses, add it
to Bug Corpus / create a permanent detector or property test.
8. Never interpret a missing/crashed analyzer as clean.
9. If CI, a tool, or a test is hanging, flaky, environment-dependent, or failing
infrastructure reasons, use the `ci-fix-dont-freeze` skill before weakening, skipping,
quarantining, or disabling that defense. Preserve the failure evidence and
root-cause it.
10. Use `RISK_MAP.md` and cross-tool correlations to prioritize code with
uncovered branches plus independent analyzer agreement.

Useful files:

- `queue.json`: one item per finding, sorted for repair, including deterministic autofix
metadata.
- `AUTOFIX.md`: exactly which findings have safe or review-required deterministic fixes.
- `FIX_QUEUE.md`: human/agent readable queue.
- `BLIND_SPOTS.md`: analyzers that errored or never ran.
- `RISK_MAP.md` / `risk-map.json`: coverage-weighted file priority for repair and V2
exploration.
- `tasks/`: repeated-signal clusters with all known locations.
- `../findings.jsonl`: streaming-friendly one-record-per-finding representation.
- `../report.json`: full scan facts, commands, raw outputs, and statuses.
"""
    (agent_dir / "AGENT_INSTRUCTIONS.md").write_text(agent_instructions)

    autofix_lines = [
        "# BugHunt Deterministic Auto-fixes",
        "",
        f"- Safe: **{fixes['safe']}**",
        f"- Unsafe: **{fixes['unsafe']}**",
        f"- Rule/review: **{fixes['review']}**",
        f"- Total: **{fixes['total']}**",
        "",
        (
            "BugHunt does not apply these automatically during "
            "a scan. Safe Ruff fixes are the strongest auto-apply "
            "candidates; unsafe Ruff fixes and Semgrep rule fixes "
            "require review."
        ),
        "",
        "## Findings",
        "",
    ]
    for item in queue:
        if not item.get("fixable"):
            continue
        loc = (
            f"{item['path'] or '<unknown>'}:{item['line'] or '?'}:"
            f"{item['column'] or '?'}"
        )
        autofix_lines.append(
            (
                f"- `{item['id']}` **{item['tool']}** `{item.get('code') or ''}` — "
                f"`{loc}` — safety `{item.get('fix_safety') or 'review'}`"
            ),
        )
        if item.get("fix_preview"):
            autofix_lines.append(
                (
                    f"  - Preview: "
                    f"`{str(item['fix_preview']).replace(chr(96), chr(39))[:300]}`"
                ),
            )
    (agent_dir / "AUTOFIX.md").write_text("\n".join(autofix_lines) + "\n")

    blindspots = [r for r in results if r.status in {Status.ERROR, Status.SKIPPED}]
    blind_lines = [
        "# BugHunt Blind Spots",
        "",
        (
            "These defenses did not provide a trusted clean result. "
            "Fix execution errors first; configure/install skipped "
            "defenses when they are relevant to this repository."
        ),
        "",
        (
            "If a defense is hanging, flaky, environment-dependent, "
            "or failing for unclear CI/infrastructure reasons, "
            "use the `ci-fix-dont-freeze` skill before weakening "
            "or disabling it."
        ),
        "",
    ]
    for r in blindspots:
        blind_lines += [
            f"## {r.status.value}: {r.name}",
            "",
            f"- Category: `{r.category}`",
            f"- Reason: {r.note or 'no trusted result'}",
        ]
        if r.command:
            blind_lines += [f"- Command: `{' '.join(r.command)}`"]
        blind_lines.append("")
    if not blindspots:
        blind_lines += ["_No execution blind spots were recorded in this run._", ""]
    (agent_dir / "BLIND_SPOTS.md").write_text("\n".join(blind_lines))

    checklist_lines = [
        "# BugHunt Repair Checklist",
        "",
        "Use this checklist before weakening any defense.",
        "",
        (
            "- [ ] Read `RISK_MAP.md` and start with uncovered/complex/high-agreement "
            "code."
        ),
        (
            "- [ ] Read `DEDUPLICATED_QUEUE.md`; fix one logical "
            "issue rather than independently chasing duplicate "
            "analyzer messages."
        ),
        (
            "- [ ] Apply only deterministic **safe** autofixes "
            "first; review unsafe/review fixes."
        ),
        "- [ ] Re-run the narrow verification command after each root-cause fix.",
        (
            "- [ ] Re-run relevant tests under the canonical seed "
            "and at least one randomized seed."
        ),
        (
            "- [ ] Treat branch coverage gaps, seam drift, migration/API "
            "drift, and mutation survivors as different bug classes."
        ),
        (
            "- [ ] If CI, an analyzer, fuzzing, concurrency, or "
            "environment-matrix execution hangs or behaves inconsistently, "
            "use the `ci-fix-dont-freeze` skill before weakening, "
            "skipping, quarantining, or disabling it."
        ),
        (
            "- [ ] If a real escaped bug is confirmed, add a "
            "regression/property/detector and teach Bug Corpus when "
            "available."
        ),
        "",
    ]
    (agent_dir / "CHECKLIST.md").write_text("\n".join(checklist_lines))

    dedup_lines = [
        "# Deduplicated Logical Issue Queue",
        "",
        (
            f"Raw analyzer findings are preserved elsewhere. "
            f"These {len(logical_issues)} clusters group "
            "same-location/same-defect-class evidence for repair."
        ),
        "",
    ]
    for index, issue in enumerate(logical_issues[:2000], 1):
        loc = f"{issue.get('path') or '<unknown>'}:{issue.get('line') or '?'}"
        dedup_lines += [
            (
                f"- [ ] **{index}. `{issue['id']}`** — `{loc}` — "
                f"**{issue['tool_count']} tool(s), "
                f"{issue['finding_count']} raw finding(s)** — `{issue['odc_class']}`"
            ),
            f"  - Tools: {', '.join(issue['tools'])}",
            f"  - Codes: {', '.join(issue['codes']) or '—'}",
            f"  - Representative: {issue['primary_message']}",
        ]
    (agent_dir / "DEDUPLICATED_QUEUE.md").write_text("\n".join(dedup_lines) + "\n")

    # One task per repeated semantic/rule signal. Agents can often fix these much
    # faster as a coherent family while still validating individual locations.
    for index, group in enumerate(groups[:500], 1):
        safe = (
            re.sub(r"[^A-Za-z0-9_.-]+", "-", (group.get("code") or group["tool"]))[
                :60
            ].strip("-")
            or "signal"
        )
        relevant = [q for q in queue if q["signal_key"] == group["key"]]
        lines = [
            f"# Task {index:04d}: {group['tool']} {group.get('code') or ''}".rstrip(),
            "",
            f"**Occurrences:** {group['count']}",
            f"**Severity:** {group['severity']}",
            f"**Signal key:** `{group['key']}`",
            "",
            "## Representative message",
            "",
            group["message"],
            "",
            "## Locations",
            "",
        ]
        for item in relevant:
            lines.append(
                (
                    f"- `{item['id']}` — `{item['path'] or '<unknown>'}:"
                    f"{item['line'] or '?'}:{item['column'] or '?'}:`"
                ),
            )
        lines += [
            "",
            "## Repair protocol",
            "",
            (
                "Fix the root cause, run the verification command "
                "for the affected analyzer, then re-run BugHunt "
                "to refresh the queue."
            ),
            "",
        ]
        if relevant and relevant[0]["verification_command"]:
            lines += [
                "```bash",
                " ".join(relevant[0]["verification_command"]),
                "```",
                "",
            ]
        (tasks_dir / f"{index:04d}-{safe}.md").write_text("\n".join(lines))

    fix_lines = [
        "# BugHunt Fix Queue",
        "",
        f"Generated `{now.isoformat()}` from profile `{profile}`.",
        "",
        f"**{len(queue)} findings** across **{len(groups)} repeated-signal groups**.",
        (
            f"**{fixes['total']} deterministic auto-fixes available**: {fixes['safe']} "
            "safe, "
            f"{fixes['unsafe']} unsafe, {fixes['review']} review-required."
        ),
        "",
        (
            "Read `AGENT_INSTRUCTIONS.md` and `CHECKLIST.md` first. "
            "`queue.json` is authoritative."
        ),
        (
            "`DEDUPLICATED_QUEUE.md` is the preferred repair view; "
            "raw findings remain available for evidence."
        ),
        "",
        (
            "Also inspect `BLIND_SPOTS.md`; analyzer execution "
            "errors should be repaired before claiming coverage."
        ),
        (
            "Prioritize `RISK_MAP.md`, especially files combining "
            "uncovered branches, complexity, and cross-tool agreement."
        ),
        (
            "If debugging a hanging/flaky/CI-dependent defense, "
            "use the `ci-fix-dont-freeze` skill before weakening "
            "it."
        ),
        "",
        "## Highest-priority repeated signals",
        "",
        "| # | Count | Signal | Example |",
        "|---:|---:|---|---|",
    ]
    for i, g in enumerate(groups[:100], 1):
        label = signal_label(g)
        msg = g["message"].replace("|", "\\|").replace("\n", " ")
        fix_lines.append(f"| {i} | {g['count']} | `{label}` | {msg[:180]} |")
    fix_lines += ["", "## One-by-one queue", ""]
    for i, item in enumerate(queue[:2000], 1):
        loc = (
            f"{item['path'] or '<unknown>'}:{item['line'] or '?'}:"
            f"{item['column'] or '?'}"
        )
        code = f"/{item['code']}" if item["code"] else ""
        fix_lines.append(
            f"- [ ] **{i}. `{item['id']}`** `{item['tool']}{code}` — `{loc}` — "
            f"{item['message']}",
        )
    if len(queue) > 2000:
        fix_lines += [
            "",
            (
                f"_Queue truncated in Markdown at 2000 items; all {len(queue)} items "
                "remain in `queue.json` and `../findings.jsonl`._"
            ),
        ]
    (agent_dir / "FIX_QUEUE.md").write_text("\n".join(fix_lines) + "\n")

    md_path = out / "report.md"
    lines = [
        "# BugHunt Report",
        "",
        f"- Generated: `{now.isoformat()}`",
        f"- Profile: `{profile}`",
        (
            f"- Defense health: **{payload['defense_health']}/100** (execution/defense "
            "health, not probability of bug-freedom)"
        ),
        f"- Elapsed: **{elapsed:.1f}s**",
        f"- Raw normalized findings: **{payload['summary']['findings']}**",
        (
            f"- Logical issue clusters: **{len(logical_issues)}** "
            "(non-destructive dedup view)"
        ),
        f"- Distinct repeated signals: **{len(groups)}**",
        f"- Cross-tool correlated locations: **{len(correlations)}**",
        (
            f"- Deterministic auto-fixes: **{fixes['total']}** total "
            f"(**{fixes['safe']} safe**, "
            f"{fixes['unsafe']} unsafe, {fixes['review']} review-required)"
        ),
        "- Agent repair queue: [`agent/FIX_QUEUE.md`](agent/FIX_QUEUE.md)",
        "- Auto-fix inventory: [`agent/AUTOFIX.md`](agent/AUTOFIX.md)",
        "- Coverage-weighted risk map: [`agent/RISK_MAP.md`](agent/RISK_MAP.md)",
        (
            "- Deduplicated repair queue: "
            "[`agent/DEDUPLICATED_QUEUE.md`](agent/DEDUPLICATED_QUEUE.md)"
        ),
        "- Repair checklist: [`agent/CHECKLIST.md`](agent/CHECKLIST.md)",
        "",
        "## ODC-style defect taxonomy",
        "",
        *[f"- **{count}** — `{kind}`" for kind, count in odc_counts.most_common()],
        "",
        "## Highest-priority repeated signals",
        "",
        "| Count | Tool / rule | Representative message |",
        "|---:|---|---|",
    ]
    for g in groups[:25]:
        label = signal_label(g)
        message = g["message"].replace("|", "\\|").replace(chr(10), " ")[:200]
        lines.append(f"| {g['count']} | `{label}` | {message} |")
    lines += ["", "## Hot files", ""]
    for path, count in hotspots[:20]:
        lines.append(f"- **{count}** findings — `{path}`")
    lines += [
        "",
        "## Defense results",
        "",
        "| Status | Tool | Class | Findings | Time | Note |",
        "|---|---|---|---:|---:|---|",
    ]
    for r in results:
        note = (r.note or "").replace("|", "\\|").replace("\n", " ")
        lines.append(
            (
                f"| {r.status.value} | `{r.name}` | {r.category} | {r.count} | "
                f"{r.duration:.1f}s | {note} |"
            ),
        )
    lines += ["", "## Findings", ""]
    if queue:
        for item in queue:
            loc = (
                f"{item['path'] or '<unknown>'}:{item['line'] or '?'}:"
                f"{item['column'] or '?'}"
            )
            lines += [
                (
                    f"### {item['id']} — {item['tool']}"
                    f"{' / ' + item['code'] if item['code'] else ''}"
                ),
                "",
                f"- Location: `{loc}`",
                f"- Severity: `{item['severity']}`",
                f"- Signal: `{item['signal_key']}`",
                f"- Fingerprint: `{item['fingerprint']}`",
                "",
                item["message"],
                "",
            ]
    else:
        lines += [
            "_No normalized findings from defenses that successfully executed._",
            "",
        ]
    lines += ["## Execution failures / unavailable defenses", ""]
    for r in results:
        if r.status in {Status.ERROR, Status.SKIPPED}:
            lines.append(
                f"- **{r.name}** — {r.status.value}: {r.note or 'see raw output'}",
            )
    lines += ["", "## Raw output", ""]
    for r in results:
        if r.stdout or r.stderr:
            lines += [
                f"### {r.name}",
                "",
                "```text",
                (r.stdout + ("\n[stderr]\n" + r.stderr if r.stderr else "")).strip(),
                "```",
                "",
            ]
    md_path.write_text("\n".join(lines))
    return md_path, json_path


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
    has_python = technology.has("python")
    engine_rows: list[tuple[str, str, str]] = []

    # trace:v1 id=impl.src-bughunt-cli-doctor.cli-row work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
    def cli_row(label: str, *names: str, python_only: bool = False) -> None:
        if python_only and not has_python:
            engine_rows.append(
                (label, "N/A", "no first-party Python capability detected"),
            )
            return
        path = executable(*names)
        engine_rows.append(
            (label, "READY" if path else "MISSING", path or "not on PATH"),
        )

    cli_row("ruff", "ruff", python_only=True)
    cli_row("basedpyright", "basedpyright", python_only=True)
    cli_row("mypy", "mypy", python_only=True)
    cli_row("ty", "ty", python_only=True)
    cli_row("pyrefly", "pyrefly", python_only=True)
    cli_row("pylint", "pylint", python_only=True)
    engine_rows.append(
        ("BugHunt policy pack", "READY", "built-in repository policy scanner"),
    )
    engine_rows.append(
        (
            "BugHunt complexity",
            "READY",
            "built-in cyclomatic/LOC/ABC/asset budget scanner",
        ),
    )
    engine_rows.append(
        (
            "BugHunt default rules",
            "READY",
            f"{len(DEFAULT_RULES)} shipped rules; inspect with `uv run bughunt rules`",
        ),
    )
    cli_row("complexipy", "complexipy", python_only=True)
    cli_row("radon", "radon", python_only=True)
    cli_row("lizard", "lizard")
    cli_row("vulture", "vulture", python_only=True)
    cli_row("bandit", "bandit", python_only=True)
    cli_row("deptry", "deptry", python_only=True)
    cli_row("import-linter", "lint-imports", python_only=True)
    ag = ast_grep_executable()
    engine_rows.append(("ast-grep", "READY" if ag else "MISSING", ag or "not on PATH"))
    cli_row("semgrep", "semgrep")
    cli_row("CodeQL", "codeql", python_only=True)

    pyre = pysa_executable(cfg.root) if has_python else None
    if not has_python:
        engine_rows.append(
            ("Pysa runner", "N/A", "no first-party Python capability detected"),
        )
    elif pyre:
        private = str(cfg.root / ".bughunt" / "runtime" / "pysa-venv") in pyre
        probe_cmd = [
            pyre,
            "--version=none",
            "--noninteractive",
            "analyze",
            "--version=none",
            "--help",
        ]
        try:
            probe = subprocess.run(
                probe_cmd,
                cwd=cfg.root,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            engine_rows.append(
                ("Pysa runner", "BROKEN", f"{pyre}: probe failed: {exc}"),
            )
        else:
            if probe.returncode == 0:
                runtime_kind = (
                    "private compatibility runtime" if private else "project runtime"
                )
                detail = f"{runtime_kind}: {pyre}"
                engine_rows.append(("Pysa runner", "READY", detail))
            else:
                tail = (probe.stderr or probe.stdout).strip().splitlines()
                detail = (
                    tail[-1] if tail else "CLI probe failed"
                ) + "; run `uv run bughunt install --only pysa`"
                engine_rows.append(("Pysa runner", "BROKEN", detail))
    else:
        engine_rows.append(
            ("Pysa runner", "MISSING", "run `uv run bughunt install --only pysa`"),
        )

    engine_rows.append(
        (
            "deal",
            "N/A"
            if not has_python
            else ("READY" if python_module_available("deal") else "MISSING"),
            "no first-party Python capability detected"
            if not has_python
            else (
                f"{sys.executable} -m deal"
                if python_module_available("deal")
                else "Python module not importable"
            ),
        ),
    )
    cli_row("CrossHair", "crosshair", python_only=True)
    cli_row("pytest", "pytest", python_only=True)
    engine_rows.append(
        (
            "Hypothesis",
            "N/A"
            if not has_python
            else ("READY" if python_module_available("hypothesis") else "MISSING"),
            "no first-party Python capability detected"
            if not has_python
            else (
                "Python module importable"
                if python_module_available("hypothesis")
                else "Python module not importable"
            ),
        ),
    )
    for label, module in (
        ("coverage.py branch coverage", "coverage"),
        ("Typeguard runtime contracts", "typeguard"),
        ("pytest-randomly", "pytest_randomly"),
        ("pytest-timeout", "pytest_timeout"),
        ("pytest-socket", "pytest_socket"),
        ("pytest-xdist", "xdist"),
        ("pytest-run-parallel", "pytest_run_parallel"),
        ("Blockbuster asyncio", "blockbuster"),
        ("pytest-memray", "pytest_memray"),
        ("pytest-benchmark", "pytest_benchmark"),
    ):
        engine_rows.append(
            (
                label,
                "N/A"
                if not has_python
                else ("READY" if python_module_available(module) else "MISSING"),
                "no first-party Python capability detected"
                if not has_python
                else (
                    "Python module importable"
                    if python_module_available(module)
                    else "Python module not importable"
                ),
            ),
        )
    engine_rows.append(
        (
            "HypoFuzz",
            "N/A"
            if not has_python
            else (
                "READY"
                if python_module_available("hypofuzz") and executable("hypothesis")
                else "MISSING"
            ),
            "no first-party Python capability detected"
            if not has_python
            else (
                "hypofuzz module + Hypothesis CLI available"
                if python_module_available("hypofuzz") and executable("hypothesis")
                else "install hypofuzz; the base Hypothesis CLI alone is not sufficient"
            ),
        ),
    )
    for label, names in (
        ("Nox matrix", ("nox",)),
        ("Griffe API drift", ("griffe",)),
        ("pydoclint", ("pydoclint",)),
        ("refurb", ("refurb",)),
        ("pyanalyze", ("pyanalyze",)),
        ("validate-pyproject", ("validate-pyproject",)),
        ("twine", ("twine",)),
        ("check-manifest", ("check-manifest",)),
        ("py-spy diagnostics", ("py-spy",)),
    ):
        cli_row(label, *names, python_only=True)
    engine_rows.append(
        (
            "BugHunt seam/contract drift",
            "READY" if has_python else "N/A",
            "built-in BHSEAM/BHDB/BHTIME scanner"
            if has_python
            else "no first-party Python capability detected",
        ),
    )
    engine_rows.append(
        (
            "Version differential",
            "READY"
            if has_python and technology.git_baseline
            else ("N/A" if not has_python else "BASELINE NEEDED"),
            f"safe pure-function differential against {technology.git_baseline[:12]}"
            if has_python and technology.git_baseline
            else "requires first-party Python plus local Git baseline",
        ),
    )
    cli_row("mutmut", "mutmut", python_only=True)
    cli_row("Schemathesis", "st", "schemathesis")
    a_ready = atheris_available(cfg.root) if has_python else False
    engine_rows.append(
        (
            "Atheris",
            "N/A" if not has_python else ("READY" if a_ready else "MISSING"),
            "no first-party Python capability detected"
            if not has_python
            else (
                f"private runtime: {cfg.root / '.bughunt' / 'runtime' / 'atheris'}"
                if not python_module_available("atheris") and a_ready
                else (
                    "Python module importable"
                    if python_module_available("atheris")
                    else "not importable; run `uv run bughunt install --only atheris`"
                )
            ),
        ),
    )

    tech_exec_names = {
        "actionlint": ("actionlint",),
        "shellcheck": ("shellcheck",),
        "dotenv-linter": ("dotenv-linter",),
        "oasdiff": ("oasdiff",),
        "buf": ("buf",),
        "sqlfluff": ("sqlfluff",),
        "squawk": ("squawk",),
        "hadolint": ("hadolint",),
        "tflint": ("tflint",),
        "golangci-lint": ("golangci-lint",),
        "cppcheck": ("cppcheck",),
        "infer": ("infer",),
        "phpstan": ("phpstan",),
        "oxlint": ("oxlint",),
        "eslint": ("eslint",),
        "react-doctor": ("react-doctor",),
        "tsc": ("tsc",),
        "knip": ("knip",),
        "madge": ("madge",),
        "publint": ("publint",),
        "taplo": ("taplo",),
        "yamllint": ("yamllint",),
        "check-jsonschema": ("check-jsonschema",),
        "alembic-check": ("alembic",),
    }
    for engine in TECH_DEEP_TOOLS:
        capability = ENGINE_CAPABILITY[engine]
        if not engine_applicable(technology, engine):
            engine_rows.append((engine, "N/A", f"no {capability} capability detected"))
            continue
        if engine == "clippy":
            cargo = project_executable(cfg.root, "cargo")
            path = cargo if cargo else None
        elif engine == "django-migrations":
            path = (
                str(cfg.root / "manage.py")
                if (cfg.root / "manage.py").exists()
                else None
            )
        elif engine == "clang-tidy":
            path = llvm_executable(cfg.root, "run-clang-tidy") or llvm_executable(
                cfg.root,
                "clang-tidy",
            )
        elif engine == "pact-contracts":
            ready = python_module_available("pact") and python_module_available(
                "uvicorn",
            )
            path = "pact-python + local Uvicorn verifier" if ready else None
        else:
            path = project_executable(cfg.root, *tech_exec_names.get(engine, (engine,)))
        engine_rows.append(
            (
                engine,
                "READY" if path else "MISSING",
                path or f"applicable ({capability}) but not installed",
            ),
        )

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
    for label, state, detail in engine_rows:
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

    # trace:v1 id=impl.src-bughunt-cli-doctor.helper-module work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
    def helper_module(
        label: str,
        module: str,
        role: str,
        *,
        applicable: bool = True,
        install_name: str | None = None,
    ) -> None:
        if not has_python or not applicable:
            guarded.add_row(label, "[cyan]N/A[/]", "not applicable to this repository")
            return
        ready = python_module_available(module)
        detail = role
        if not ready and install_name:
            detail += (
                f"; install explicitly with `bughunt install --only {install_name}` "
                "when desired"
            )
        guarded.add_row(
            label,
            "[green]READY[/]" if ready else "[yellow]OPTIONAL[/]",
            detail,
        )

    helper_module(
        "time-machine",
        "time_machine",
        (
            "time-boundary test helper; BHTIME001 detects missing "
            "boundary evidence rather than inventing expected clock "
            "behavior"
        ),
        install_name="time-machine",
    )
    helper_module(
        "freezegun",
        "freezegun",
        (
            "alternative time-control helper; not required when "
            "time-machine or equivalent evidence exists"
        ),
        install_name="freezegun",
    )
    helper_module(
        "VCR.py",
        "vcr",
        "recorded external-payload corpus helper for BHSEAM006",
        install_name="vcrpy",
    )
    helper_module(
        "openapi-core",
        "openapi_core",
        (
            "client/server OpenAPI response/request runtime validation "
            "library; seam rule recommends validation rather than "
            "auto-rewriting application code"
        ),
        install_name="openapi-core",
    )
    helper_module(
        "nplusone",
        "nplusone",
        "optional ORM runtime N+1 detector; BugHunt also ships static BHDB001",
        install_name="nplusone",
    )
    helper_module(
        "icontract-hypothesis",
        "icontract_hypothesis",
        (
            "contract-derived property generation; guarded because "
            "compatibility varies with current Hypothesis/Python"
        ),
        install_name="icontract-hypothesis",
    )
    helper_module(
        "Slipcover",
        "slipcover",
        (
            "optional fast coverage engine; coverage.py branch "
            "coverage remains the canonical portable baseline"
        ),
        install_name="slipcover",
    )
    helper_module(
        "beartype",
        "beartype",
        (
            "alternative runtime type checker; Typeguard is the "
            "canonical pytest verification layer"
        ),
        install_name="beartype",
    )
    helper_module(
        "sqlglot",
        "sqlglot",
        (
            "optional SQL parser second opinion; SQLFluff is the "
            "configured correctness scanner"
        ),
        install_name="sqlglot",
    )
    pynguin = executable("pynguin")
    guarded.add_row(
        "Pynguin",
        "[green]READY[/]" if pynguin else "[yellow]GUARDED[/]",
        (
            "search-based test generation executes modules under "
            "test; only enable in a throwaway/OS-sandboxed environment"
        ),
    )
    wemake = python_module_available("wemake_python_styleguide")
    guarded.add_row(
        "wemake-python-styleguide",
        "[green]READY[/]" if wemake else "[yellow]ADVISORY[/]",
        (
            "Ruff companion with additional Python rules; deliberately "
            "outside correctness-health because many WPS rules "
            "are opinionated/style-heavy"
        ),
    )
    joern = executable("joern", "joern-parse")
    guarded.add_row(
        "Joern",
        "[green]READY[/]" if joern else "[yellow]MANUAL[/]",
        (
            "optional CodeQL-style CPG/dataflow second opinion; "
            "not auto-installed because it is a heavyweight external "
            "platform"
        ),
    )
    shfmt = executable("shfmt")
    guarded.add_row(
        "shfmt",
        "[green]READY[/]" if shfmt else "[dim]QUALITY[/]",
        (
            "shell formatter only; ShellCheck owns shell correctness "
            "and shfmt does not affect correctness health"
        ),
    )
    asv = executable("asv")
    guarded.add_row(
        "asv",
        "[green]READY[/]" if asv else "[dim]ALTERNATIVE[/]",
        (
            "long-horizon performance benchmark alternative; pytest-benchmark "
            "is the default regression ring"
        ),
    )
    xdoc = executable("xdoctest")
    guarded.add_row(
        "xdoctest",
        "[green]READY[/]" if xdoc else "[dim]ALTERNATIVE[/]",
        "alternative executable-doc engine; pytest --doctest-modules is the default",
    )
    console.print(guarded)

    capability_table = Table(
        title="Repository Capabilities",
        box=box.ROUNDED,
        expand=True,
    )
    capability_table.add_column("CAPABILITY", min_width=24)
    capability_table.add_column("STATE", width=12)
    capability_table.add_column("EVIDENCE", ratio=3)
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

    generated = load_generated_targets(cfg.root)
    atheris_targets = [t for t in generated if t.kind == "atheris" and t.runnable]
    schema_targets = [t for t in generated if t.kind == "schemathesis" and t.runnable]
    schema_candidates = [t for t in generated if t.kind == "schemathesis-candidate"]
    explicit_atheris = list(cfg.raw.get("atheris", {}).get("targets", []))
    explicit_schema = list(cfg.raw.get("schemathesis", {}).get("targets", []))

    coverage = Table(title="Repository-Specific Coverage", box=box.ROUNDED, expand=True)
    coverage.add_column("DEFENSE", min_width=34)
    coverage.add_column("CONFIG", width=18)
    coverage.add_column("DETAIL", ratio=2)

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
    configured_custom = list(cfg.raw.get("custom", {}).get("checks", []))
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
    generated_checks = []
    for target in targets:
        if (
            target.kind.startswith("custom-")
            and target.runnable
            and target.command
            and target.confidence == "high"
        ):
            generated_checks.append(
                {
                    "name": target.name,
                    "category": target.kind.removeprefix("custom-"),
                    "profile": "deep",
                    "command": list(target.command),
                    "timeout": int((target.metadata or {}).get("timeout", 3600)),
                    "generated": True,
                    "confidence": target.confidence,
                },
            )
    existing_checks = [
        x for x in cfg.raw.get("custom", {}).get("checks", []) if not x.get("generated")
    ]
    cfg.raw.setdefault("custom", {})["checks"] = [*existing_checks, *generated_checks]
    manifest_path = cfg.root / ".bughunt" / "configs" / "manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
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
    started = time.perf_counter()
    raw_limit = int(cfg.raw.get("execution", {}).get("raw_output_limit_kb", 512)) * 1024

    if auto_discover and cfg.raw.get("autodiscovery", {}).get("enabled", True):
        auto_configure(cfg, quiet=True)

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
        while not stop_refresh.is_set():
            live.update(progress.render(), refresh=True)
            try:
                await asyncio.wait_for(stop_refresh.wait(), timeout=0.5)
            except TimeoutError:
                pass

    results: list[Result] = []
    with Live(
        progress.render(),
        console=console,
        refresh_per_second=4,
        transient=False,
    ) as live:
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
                result = await runner(cfg, profile, raw_limit, progress)
                # Internal subprocesses never count as finished defenses. Record
                # exactly one logical result here, regardless of how many phases ran.
                progress.running.pop("codeql-db", None)
                progress.running.pop("mutmut-results", None)
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

    canonicalize_findings(cfg.root, results)
    if "type-disagreement" in effective_tools:
        disagreement = type_disagreement_result(results)
        if disagreement is not None:
            results = [r for r in results if r.name != "type-disagreement"] + [
                disagreement,
            ]
    by_name = {result.name: result for result in results}
    pysa_result = by_name.get("pysa")
    pyrefly_result = by_name.get("pyrefly")
    if (
        pysa_result
        and pyrefly_result
        and pyrefly_result.status in {Status.FINDINGS, Status.ERROR}
    ):
        dependency_note = (
            f"Pysa type-provider coverage degraded: Pyrefly is "
            f"{pyrefly_result.status.value.lower()}"
        ) + (f" with {pyrefly_result.count} finding(s)" if pyrefly_result.count else "")
        pysa_result.note = (
            f"{pysa_result.note}; {dependency_note}"
            if pysa_result.note
            else dependency_note
        )
        # A clean taint result cannot be called coverage-clean while its current
        # type-information provider is known not to check cleanly.
        if pysa_result.status == Status.PASS:
            pysa_result.status = Status.ERROR
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
    parser = argparse.ArgumentParser(
        prog="bughunt",
        description=(
            "Run independent bug-finding defenses and compile one agent-ready report."
        ),
    )
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="repository root")
    parser.add_argument("--config", type=Path, help="path to bughunt.toml")

    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="run a bug-hunting profile")
    run_p.add_argument(
        "profile_positional",
        nargs="?",
        choices=("fast", "pr", "deep", "all"),
        help="profile (also accepted as --profile)",
    )
    run_p.add_argument("--profile", choices=("fast", "pr", "deep", "all"), default=None)
    run_p.add_argument(
        "--skip",
        action="append",
        default=[],
        metavar="DEFENSE",
        help="skip a defense while keeping the selected profile (repeatable)",
    )
    run_p.add_argument(
        "--skip-mutmut",
        action="store_true",
        help="skip mutation testing",
    )
    run_p.add_argument(
        "--no-auto-config",
        action="store_true",
        help="do not refresh strict configs or auto-discovered targets",
    )

    for alias, help_text in (
        ("quick", "run the fast feedback profile"),
        ("pr", "run the pull-request profile"),
        ("deep", "run the deep profile"),
    ):
        alias_p = sub.add_parser(alias, help=help_text)
        alias_p.add_argument("--no-auto-config", action="store_true")

    # trace:v1 id=impl.src-bughunt-cli-main.add-all-options work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
    def add_all_options(target: argparse.ArgumentParser) -> None:
        target.add_argument(
            "--install-missing",
            action=argparse.BooleanOptionalAction,
            default=True,
            help="install missing analyzers before running (default: true)",
        )
        target.add_argument(
            "--skip",
            action="append",
            default=[],
            metavar="DEFENSE",
            help="skip a defense while keeping all other all-profile defenses",
        )
        target.add_argument(
            "--skip-mutmut",
            action="store_true",
            help="skip mutation testing (same as --skip mutmut)",
        )
        target.add_argument("--no-auto-config", action="store_true")

    all_p = sub.add_parser(
        "all",
        help="bootstrap, auto-configure, and run every available defense",
    )
    add_all_options(all_p)

    full_p = sub.add_parser(
        "full",
        help="alias for `all`: bootstrap, configure, and run everything",
    )
    add_all_options(full_p)

    skipmutmut_p = sub.add_parser(
        "skipmutmut",
        help="run the all profile but explicitly skip mutation testing",
    )
    add_all_options(skipmutmut_p)

    install_p = sub.add_parser(
        "install",
        help="auto-install the analysis stack using uv (plus CodeQL/Watchman on macOS)",
    )
    install_p.add_argument("--dry-run", action="store_true")
    install_p.add_argument(
        "--only",
        action="append",
        metavar="COMPONENT",
        help="install/repair only this component (repeatable; e.g. --only atheris)",
    )

    config_p = sub.add_parser(
        "configure",
        help="discover and generate safe deep-analysis targets",
    )
    config_p.add_argument("--auto", action="store_true", default=True)

    sub.add_parser("rules", help="list the shipped BugHunt-native default rule pack")
    sub.add_parser("doctor", help="show available defenses and missing configuration")

    args = parser.parse_args(argv)
    root = args.root.resolve()
    cfg = load_config(root, args.config)

    if args.command == "rules":
        return show_default_rules()

    if args.command == "doctor":
        return doctor(cfg)

    if args.command == "configure":
        auto_configure(cfg)
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

    excluded = set(getattr(args, "skip", []) or [])
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
        }
    )
    unknown_skips = sorted(excluded - known_defenses)
    if unknown_skips:
        parser.error("unknown defense(s) for --skip: " + ", ".join(unknown_skips))

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
        auto_configure(cfg, quiet=True)

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
    return exit_code_for(cfg, scan_results)


if __name__ == "__main__":
    raise SystemExit(main())
