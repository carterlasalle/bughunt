# Copyright (c) 2026 Carter LaSalle
"""Tool-output parsers: every analyzer's machine output becomes Findings.

Pure functions of (stdout, stderr, exit_code). No orchestration lives here.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .models import Finding


# trace:v1 id=impl.src-bughunt-cli.text-findings work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def text_findings(tool: str, stdout: str, stderr: str, exit_code: int) -> list[Finding]:
    if exit_code == 0:
        return []
    lines = (stdout + "\n" + stderr).splitlines()
    findings: list[Finding] = []
    patterns = [
        re.compile(
            r"^(?P<path>.+?):(?P<line>\d+):(?P<col>\d+):\s*"
            + r"(?:(?P<severity>error|warning|note):\s*)?(?P<msg>.+)$",
            re.IGNORECASE,
        ),
        re.compile(
            r"^(?P<path>.+?):(?P<line>\d+):\s*"
            + r"(?:(?P<severity>error|warning|note):\s*)?(?P<msg>.+)$",
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
def parse_pylint(
    stdout: str,
    stderr: str,
    exit_code: int,
    tool: str = "pylint",
) -> list[Finding]:
    """Parse Pylint JSON2, ranking convention/refactor/info below bug diagnostics."""
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return text_findings(tool, stdout, stderr, exit_code)
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
                tool=tool,
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
    return out or (text_findings(tool, stdout, stderr, exit_code) if exit_code else [])


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
    combined = stdout + "\n" + stderr
    if "No module named 'pkg_resources'" in combined or (
        "No module named pkg_resources" in combined
    ):
        return [
            Finding(
                tool="semgrep",
                message=(
                    "semgrep cannot start: it imports pkg_resources, which "
                    "setuptools>=81 removed. Pin setuptools<81 in dev "
                    "dependencies or await an upstream semgrep fix; "
                    "treating as unavailable, not as a clean scan"
                ),
                severity="error",
            ),
        ]
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
            # Malformed payload carries no data; skipped
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


# trace:v1 id=impl.src-bughunt-cli.parse-bandit work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
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


# trace:v1 id=impl.src-bughunt-cli.-severity work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
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
            # Malformed payload carries no data; skipped
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
            # Malformed payload carries no data; skipped
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
    import xml.etree.ElementTree as ET  # nosec B405 - own tool output

    try:
        root = ET.fromstring(stderr.strip())  # Cppcheck XML is own tool output
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
    out.extend(
        Finding(tool="phpstan", message=str(message), severity="error")
        for message in data.get("errors", [])
        if isinstance(data, dict)
    )
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
            # Malformed payload carries no data; skipped
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
