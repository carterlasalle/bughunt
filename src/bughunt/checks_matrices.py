# Copyright (c) 2026 Carter LaSalle
"""Environment matrix and contract check builders."""

from __future__ import annotations

import sys
from functools import partial
from typing import Any
from .checkctx import CheckBuildCx
from .probes import atheris_available, generated_config
from .technology import target_executable, target_has_module
from .parsers import parse_bughunt_helper, text_findings
from .models import Check, Result, Status


# trace:v1 id=impl.src-bughunt-checks-matrices.-build-matrix-checks work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _build_matrix_checks(cx: CheckBuildCx) -> None:
    if "bugcorpus" in cx.wanted:
        if not (cx.root / ".bugcorpus").is_dir():
            cx.skipped.append(
                Result(
                    "bugcorpus",
                    "historical-bugs",
                    Status.NA,
                    note="not applicable: no .bugcorpus corpus in this repository",
                ),
            )
        else:
            cx.add(
                "bugcorpus",
                "historical-bugs",
                [
                    sys.executable,
                    "-m",
                    "bughunt.bugcorpus_adapter",
                    str(cx.root),
                    cx.profile,
                ],
                lambda o, e, c: parse_bughunt_helper("bugcorpus", o, e, c),
                findings_exit_codes={1},
            )

        # System IR is consumed as a real ring through system_ir_adapter: the
        # installed CLI's index/export/drift/invariant contracts, normalized
        # without reinterpretation. No SCC workspace means N/A.
        if "system-ir" in cx.wanted:
            if not (cx.root / ".scc").is_dir():
                cx.skipped.append(
                    Result(
                        "system-ir",
                        "structural-graph",
                        Status.NA,
                        note="not applicable: no .scc workspace in this repository",
                    ),
                )
            else:
                cx.add(
                    "system-ir",
                    "structural-graph",
                    [sys.executable, "-m", "bughunt.system_ir_adapter", str(cx.root)],
                    lambda o, e, c: parse_bughunt_helper("system-ir", o, e, c),
                    findings_exit_codes={1},
                )

        # TraceLayer is consumed as a real ring through tracelayer_adapter:
        # changed-scope verification diagnostics plus repository health
        # (broken refs, blocking stale traces). No .trace workspace means N/A.
        if "tracelayer" in cx.wanted:
            if not (cx.root / ".trace").is_dir():
                cx.skipped.append(
                    Result(
                        "tracelayer",
                        "direct-verification",
                        Status.NA,
                        note="not applicable: no .trace workspace in this repository",
                    ),
                )
            else:
                cx.add(
                    "tracelayer",
                    "direct-verification",
                    [sys.executable, "-m", "bughunt.tracelayer_adapter", str(cx.root)],
                    findings_exit_codes={1},
                )

        # Verification gaps are computed from the cached System IR through
        # verify_gaps: transitive-only coverage and hollow public stubs.
        # No SCC workspace means N/A.
        if "verify-gaps" in cx.wanted:
            if not (cx.root / ".scc").is_dir():
                cx.skipped.append(
                    Result(
                        "verify-gaps",
                        "direct-verification",
                        Status.NA,
                        note="not applicable: no .scc workspace in this repository",
                    ),
                )
            else:
                cx.add(
                    "verify-gaps",
                    "direct-verification",
                    [sys.executable, "-m", "bughunt.verify_gaps", str(cx.root)],
                    lambda o, e, c: parse_bughunt_helper("verify-gaps", o, e, c),
                    findings_exit_codes={1},
                )

        # Protocol correctness (magic methods, generators, assert misuse)
        # runs as a pure-AST native check over first-party sources.
        if "protocol" in cx.wanted:
            cx.add(
                "protocol",
                "protocol-correctness",
                [
                    sys.executable,
                    "-m",
                    "bughunt.protocol_scan",
                    str(cx.root),
                    *cx.cfg.source_paths,
                ],
                lambda o, e, c: parse_bughunt_helper("protocol", o, e, c),
                findings_exit_codes={1},
            )
    if "schemathesis" in cx.wanted:
        explicit = list(cx.cfg.raw.get("schemathesis", {}).get("targets", []))
        auto = [
            t
            for t in cx.generated_targets
            if t.kind == "schemathesis" and t.runnable and t.command
        ]
        added = 0
        st = target_executable(cx.root, "st", "schemathesis")
        schemathesis_ready = bool(st) or target_has_module(
            cx._target_py, "schemathesis"
        )
        for target in explicit:
            if not st:
                continue
            name = f"schemathesis:{target.get('name', 'api')}"
            schema = str(target["schema"])
            st_cfg = generated_config(cx.root, "schemathesis.toml")
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
            cx.checks.append(
                Check(
                    name,
                    "api-fuzz",
                    cmd,
                    partial(text_findings, name),
                    int(target.get("timeout", cx.timeout)),
                    cx.root,
                ),
            )
            added += 1
        for target in auto:
            if not schemathesis_ready:
                continue
            name = f"schemathesis:auto:{target.name}"
            cx.checks.append(
                Check(
                    name,
                    "api-fuzz",
                    list(target.command or []),
                    partial(text_findings, name),
                    cx.timeout,
                    cx.root,
                ),
            )
            added += 1
        if not added:
            candidates = sum(
                t.kind == "schemathesis-candidate" for t in cx.generated_targets
            )
            if (explicit or auto) and not schemathesis_ready:
                reason = "Schemathesis target exists but the engine is not installed"
            else:
                reason = "no safe runnable API target discovered/configured"
                if candidates:
                    reason += f" ({candidates} schema candidate(s) need a local URL)"
            cx.skipped.append(
                Result("schemathesis", "api-fuzz", Status.SKIPPED, note=reason),
            )
    if "atheris" in cx.wanted and not cx.technology.has("python"):
        cx.skipped.append(
            Result(
                "atheris",
                "coverage-fuzz",
                Status.NA,
                note="not applicable: no first-party Python capability detected",
            ),
        )
    elif "atheris" in cx.wanted:
        explicit = list(cx.cfg.raw.get("atheris", {}).get("targets", []))
        auto = [
            t
            for t in cx.generated_targets
            if t.kind == "atheris" and t.runnable and t.command
        ]
        added = 0
        atheris_ready = atheris_available(cx.root)
        for target in explicit:
            name = f"atheris:{target.get('name', 'fuzzer')}"
            cmd = [str(x) for x in target["command"]]
            cx.checks.append(
                Check(
                    name,
                    "coverage-fuzz",
                    cmd,
                    partial(text_findings, name),
                    int(target.get("timeout", cx.timeout)),
                    cx.root,
                ),
            )
            added += 1
        for target in auto:
            if not atheris_ready:
                continue
            name = f"atheris:auto:{target.name}"
            cx.checks.append(
                Check(
                    name,
                    "coverage-fuzz",
                    list(target.command or []),
                    partial(text_findings, name),
                    cx.timeout,
                    cx.root,
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
            cx.skipped.append(
                Result("atheris", "coverage-fuzz", Status.SKIPPED, note=reason),
            )
    if "custom" in cx.wanted:
        explicit_custom = list(cx.cfg.raw.get("custom", {}).get("checks", []))
        generated_custom = [
            {
                "name": target.name,
                "category": target.kind.removeprefix("custom-"),
                "profile": "deep",
                "command": list(target.command or []),
                "timeout": int((target.metadata or {}).get("timeout", cx.timeout)),
                "generated": True,
                "confidence": target.confidence,
            }
            for target in cx.generated_targets
            if target.kind.startswith("custom-")
            and target.runnable
            and target.command
            and target.confidence == "high"
        ]
        merged_custom: list[dict[str, Any]] = []
        seen_custom: set[tuple[str, tuple[str, ...]]] = set()
        for item in [*explicit_custom, *generated_custom]:
            raw_command = item.get("command", [])
            if not isinstance(raw_command, list):
                continue
            command = tuple(str(x) for x in raw_command)
            key = (str(item.get("name", "custom")), command)
            if not command or key in seen_custom:
                continue
            seen_custom.add(key)
            merged_custom.append(item)
        if not merged_custom:
            cx.skipped.append(
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
                if rank[cx.profile] < rank.get(required, 2):
                    continue
                name = f"custom:{item['name']}"
                cx.checks.append(
                    Check(
                        name,
                        str(item.get("category", "custom")),
                        [str(x) for x in item["command"]],
                        partial(text_findings, name),
                        int(item.get("timeout", cx.timeout)),
                        cx.root,
                    ),
                )
