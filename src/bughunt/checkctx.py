# Copyright (c) 2026 Carter LaSalle
"""Check-construction context shared by check builder sections."""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, Callable
from collections.abc import Sequence

from .models import Check, Finding, Result, Status
from .parsers import text_findings
from .technology import (
    ENGINE_CAPABILITY,
    ENGINE_CATEGORY,
    TechnologyInventory,
    engine_applicable,
)

if TYPE_CHECKING:
    from .config import Config
    from .discovery import DiscoveredTarget

PYTHON_ONLY_TOOLS = {
    "compile",
    "ruff",
    "basedpyright",
    "mypy",
    "ty",
    "pyrefly",
    "pylint",
    "pylint-tests",
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
    "semantic",
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


# trace:v1 id=impl.src-bughunt-checkctx.check-build-cx work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
@dataclass
class CheckBuildCx:
    """Everything check-builder sections need from the build_checks preamble."""

    cfg: Config
    profile: str
    root: Path
    timeout: int
    wanted: list[str]
    excluded: set[str]
    py: list[str]
    src: list[str]
    tests: list[str]
    config_dir: Path
    technology: TechnologyInventory
    target_py: str
    pytest: str | None
    hypothesis_plugin: Path | None
    repro_seed: int
    test_timeout: int
    pytest_env: dict[str, str]
    pytest_cmd: list[str] | None
    checks: list[Check] = field(default_factory=list)
    skipped: list[Result] = field(default_factory=list)
    generated_targets: list[DiscoveredTarget] = field(default_factory=list)
    category_by_tool: dict[str, str] = field(default_factory=dict)

    # trace:v1 id=impl.src-bughunt-cli-build-checks.add work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
    def add(
        self,
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
        env_scrub: tuple[str, ...] | None = None,
        timeout_is_success: bool = False,
    ) -> None:
        if name not in self.wanted:
            return
        if name in PYTHON_ONLY_TOOLS and not self.technology.has("python"):
            self.skipped.append(
                Result(
                    name=name,
                    category=category,
                    status=Status.NA,
                    note="not applicable: no first-party Python capability detected",
                ),
            )
            return
        if command is None:
            self.skipped.append(
                Result(
                    name=name,
                    category=category,
                    status=Status.SKIPPED,
                    note=reason or "not configured",
                ),
            )
            return
        self.checks.append(
            Check(
                name=name,
                category=category,
                command=list(command),
                parser=(partial(text_findings, name) if parser is None else parser),
                timeout=check_timeout or self.timeout,
                cwd=self.root,
                findings_exit_codes=findings_exit_codes
                if findings_exit_codes is not None
                else {1},
                skip_exit_codes=skip_exit_codes
                if skip_exit_codes is not None
                else set(),
                empty_scope_markers=empty_scope_markers or (),
                env=env,
                env_scrub=env_scrub or (),
                timeout_is_success=timeout_is_success,
            ),
        )

    # trace:v1 id=impl.src-bughunt-cli-build-checks.add-technology work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
    def add_technology(
        self,
        engine: str,
        command: Sequence[str] | None,
        parser_fn: Callable[[str, str, int], list[Finding]] | None = None,
        *,
        reason: str | None = None,
        findings_exit_codes: set[int] | None = None,
        empty_scope_markers: tuple[str, ...] | None = None,
        name: str | None = None,
        check_timeout: int | None = None,
        env: dict[str, str] | None = None,
    ) -> None:
        if engine not in self.wanted:
            return
        category = ENGINE_CATEGORY[engine]
        logical = name or engine
        if not engine_applicable(self.technology, engine):
            # Only emit the base logical result once for engines which may have
            # multiple per-file checks (oasdiff etc.).
            if not any(
                x.name == engine and x.status == Status.NA for x in self.skipped
            ):
                cap = ENGINE_CAPABILITY[engine]
                self.skipped.append(
                    Result(
                        engine,
                        category,
                        Status.NA,
                        note=f"not applicable: no {cap} capability detected",
                    ),
                )
            return
        if command is None:
            self.skipped.append(
                Result(
                    logical,
                    category,
                    Status.SKIPPED,
                    note=reason or f"{engine} not installed/configured",
                ),
            )
            return
        self.checks.append(
            Check(
                logical,
                category,
                list(command),
                partial(text_findings, logical) if parser_fn is None else parser_fn,
                check_timeout or self.timeout,
                self.root,
                findings_exit_codes=findings_exit_codes
                if findings_exit_codes is not None
                else {1},
                empty_scope_markers=empty_scope_markers or (),
                env=env,
            ),
        )
