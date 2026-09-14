# Copyright (c) 2026 Carter LaSalle
"""Shared finding/result models: the narrow contract between orchestrator,
analyzer adapters, and output parsers."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


# trace:v1 id=impl.src-bughunt-cli.status work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
class Status(str, Enum):
    PASS = "PASS"  # nosec B105 - status enum member, not a credential
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
    accepted: bool = False
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

    # trace:v1 id=impl.src-bughunt-cli.finding.finding-id work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    @property
    def finding_id(self) -> str:
        return f"BH-{self.fingerprint.upper()}"


# trace:v1 id=impl.src-bughunt-cli.debt-ledger work=WORK-BUG-06107X2Q satisfies=REQ-BUG-SY8DHSTC
@dataclass(slots=True)
class DebtEntry:
    """One accepted finding-debt record from debt.toml.

    Accepted findings stay visible in the report's debt section but leave
    the fix queue, top signals, hotspots, and risk map, so known debt
    cannot habituate reviewers into missing new findings. Growth beyond
    the recorded count surfaces in `debt review`.
    """

    signal: str
    paths: list[str]
    count: int
    reason: str


# trace:v1 id=impl.src-bughunt-cli.result work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
@dataclass(slots=True)
class Result:
    name: str
    category: str
    status: Status
    duration_s: float = 0.0
    exit_code: int | None = None
    findings: list[Finding] = field(default_factory=list)
    command: list[str] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    note: str | None = None
    artifacts: list[str] = field(default_factory=list)

    # trace:v1 id=impl.src-bughunt-cli.result.count work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
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
    # Names removed from the child environment after merging os.environ with
    # env. Needed when presence alone changes tool behavior (e.g. Hypothesis
    # loads its derandomized "ci" profile whenever CI-like vars exist).
    env_scrub: tuple[str, ...] = ()
    configured: bool = True
    findings_exit_codes: set[int] = field(default_factory=lambda: {1})
    skip_exit_codes: set[int] = field(default_factory=set)
    # Banner substrings proving the tool ran but had nothing in scope (as
    # opposed to erroring). When the exit code is a findings code yet the
    # parser yields nothing and a marker is present, the result is SKIPPED
    # ("nothing in scope") instead of a synthetic FINDINGS entry.
    empty_scope_markers: tuple[str, ...] = ()
    record_progress: bool = True
    timeout_is_success: bool = False
