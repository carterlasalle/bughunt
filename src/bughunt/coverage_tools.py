from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class CoverageGap:
    code: str
    path: str
    line: int | None
    message: str
    severity: str = "warning"


def coverage_config(source_paths: list[str]) -> str:
    source = "\n    ".join(source_paths) if source_paths else "."
    return (
        f"[run]\nbranch = true\nparallel = false\nsource =\n    {source}\n"
        "omit =\n    */.venv/*\n    */.bughunt/*\n    */site-packages/*\n"
        "    */tests/*\n    */test_*\n\n[report]\nshow_missing = true\n"
        "skip_covered = false\nprecision = 2\n\n[json]\npretty_print = true\n"
        "show_contexts = true\n"
    )


def _ranges(lines: list[int]) -> list[tuple[int, int]]:
    if not lines:
        return []
    lines = sorted(set(lines))
    out: list[tuple[int, int]] = []
    start = prev = lines[0]
    for line in lines[1:]:
        if line == prev + 1:
            prev = line
            continue
        out.append((start, prev))
        start = prev = line
    out.append((start, prev))
    return out


# trace:v1 id=impl.src-bughunt-coverage_tools.parse-coverage-json work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def parse_coverage_json(
    path: Path,
    *,
    line_group_limit: int = 50,
) -> tuple[list[CoverageGap], dict[str, Any]]:
    data = json.loads(path.read_text())
    findings: list[CoverageGap] = []
    totals = data.get("totals", {}) if isinstance(data, dict) else {}
    files = data.get("files", {}) if isinstance(data, dict) else {}
    for filename, payload in files.items():
        if not isinstance(payload, dict):
            continue
        missing_lines = [
            int(x) for x in payload.get("missing_lines", []) if isinstance(x, int)
        ]
        missing_branches = payload.get("missing_branches", []) or []
        for start, end in _ranges(missing_lines)[:line_group_limit]:
            span = f"{start}" if start == end else f"{start}-{end}"
            count = end - start + 1
            severity = "error" if count >= 25 else "warning"
            findings.append(
                CoverageGap(
                    "BHCOV001",
                    str(filename),
                    start,
                    f"{count} executable line(s) are never exercised by the test suite "
                    f"(missing range {span})",
                    severity,
                ),
            )
        for branch in missing_branches[:line_group_limit]:
            if isinstance(branch, list) and len(branch) >= 2:
                src, dst = branch[0], branch[1]
                findings.append(
                    CoverageGap(
                        "BHCOV002",
                        str(filename),
                        int(src) if isinstance(src, int) else None,
                        f"branch edge {src} -> {dst} is never exercised; uncovered "
                        "exception/decision arms are latent-bug risk",
                        "warning",
                    ),
                )
    summary = {
        "percent_covered": totals.get("percent_covered"),
        "covered_lines": totals.get("covered_lines"),
        "missing_lines": totals.get("missing_lines"),
        "num_branches": totals.get("num_branches"),
        "missing_branches": totals.get("missing_branches"),
    }
    return findings, summary
