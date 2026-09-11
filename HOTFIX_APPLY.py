from __future__ import annotations

import re
from pathlib import Path

VERSION = "0.6.0"

DEV_DEPS = [
    "pytest>=8.0", "ruff", "basedpyright", "mypy", "ty", "pyrefly", "pylint",
    "vulture", "bandit", "deptry", "import-linter", "ast-grep-cli", "semgrep",
    "deal[all]", "crosshair-tool", "hypothesis[cli]", "mutmut", "schemathesis",
    "radon", "lizard", "complexipy", "coverage", "typeguard", "pytest-randomly",
    "pytest-timeout", "pytest-socket", "pytest-xdist", "pytest-run-parallel",
    "blockbuster>=1.5,<1.6", "hypofuzz", "nox", "griffe", "pydoclint",
    "validate-pyproject[all]", "twine", "check-manifest", "pytest-benchmark",
    "pytest-memray", "pyanalyze", "refurb", "xdoctest", "check-jsonschema",
    "time-machine", "freezegun", "vcrpy", "pact-python", "py-spy", "uvicorn",
]

PR_TOOLS = [
    "coverage", "seam", "evidence", "packaging", "runtime-types", "doctest",
    "pydoclint", "refurb", "actionlint", "shellcheck", "dotenv-linter", "oasdiff",
    "buf", "sqlfluff", "squawk", "hadolint", "tflint", "golangci-lint", "clippy",
    "cppcheck", "phpstan", "oxlint", "eslint", "react-doctor", "tsc", "knip",
    "madge", "publint", "taplo", "yamllint", "check-jsonschema", "alembic-check",
    "django-migrations",
]
DEEP_TOOLS = [
    *PR_TOOLS, "pytest-random", "pytest-no-network", "pytest-xdist",
    "pytest-async-blocking", "hypofuzz", "griffe", "importtime", "type-disagreement",
    "clang-tidy", "infer", "pact-contracts",
]
ALL_TOOLS = [
    *DEEP_TOOLS, "pytest-parallel", "python-matrix", "timezone-matrix", "memray",
    "benchmark", "pyanalyze", "version-diff", "ghostwriter", "pynguin",
]

SECTIONS = {
    "coverage": '''[coverage]\nbranch = true\n''',
    "tests": '''[tests]\ntimeout_seconds = 300\nrepro_seed = 1\nrandomized = true\n''',
    "hypofuzz": '''[hypofuzz]\ndeep_seconds = 120\nall_seconds = 300\nworkers = 2\n''',
    "performance": '''[performance]\nimport_ms_warn = 1000\nbenchmark_regression_percent = 10\nmemray = true\n''',
    "execution_imports": '''[execution_imports]\nallow_importing_analyzers = false\n''',
}


def _base_name(spec: str) -> str:
    return re.split(r"[<>=!~\[]", spec, maxsplit=1)[0].strip().lower().replace("_", "-")


def patch_project(path: Path) -> None:
    text = path.read_text()
    project = re.search(r"(?ms)^\[project\]\s*$.*?(?=^\[|\Z)", text)
    if project is None:
        raise SystemExit("[project] table not found in pyproject.toml")
    block = project.group(0)
    block, count = re.subn(r'(?m)^version\s*=\s*"[^"]+"\s*$', f'version = "{VERSION}"', block, count=1)
    if count != 1:
        raise SystemExit("project version field not found")
    text = text[: project.start()] + block + text[project.end() :]

    # Ensure Hypothesis CLI extras are present when an older release had plain hypothesis.
    text = re.sub(r'(?m)^\s*"hypothesis"\s*,?\s*$', '    "hypothesis[cli]",', text)

    dep_match = re.search(r"(?ms)^\[dependency-groups\]\s*$.*?^dev\s*=\s*\[(.*?)^\]", text)
    if dep_match is None:
        text = text.rstrip() + "\n\n[dependency-groups]\ndev = [\n" + "".join(f'    "{d}",\n' for d in DEV_DEPS) + "]\n"
    else:
        body = dep_match.group(1)
        present = {_base_name(m.group(1)) for m in re.finditer(r'"([^"]+)"', body)}
        missing = [d for d in DEV_DEPS if _base_name(d) not in present]
        if missing:
            insertion = "".join(f'    "{d}",\n' for d in missing)
            text = text[: dep_match.end(1)] + insertion + text[dep_match.end(1) :]

    # Coverage gaps are separate findings; mutation should spend budget on reachable behavior.
    if "[tool.mutmut]" in text and "# BEGIN BUGHUNT MANAGED MUTMUT CONFIG" in text:
        text = re.sub(r"(?m)^mutate_only_covered_lines\s*=\s*false\s*$", "mutate_only_covered_lines = true", text)
    path.write_text(text)


def patch_profile(text: str, profile: str, additions: list[str]) -> str:
    section = re.search(rf"(?ms)^\[profiles\.{re.escape(profile)}\]\s*$.*?(?=^\[|\Z)", text)
    if section is None:
        return text
    block = section.group(0)
    tools = re.search(r"(?s)(tools\s*=\s*\[)(.*?)(\])", block)
    if tools is None:
        return text
    present = set(re.findall(r'"([^"]+)"', tools.group(2)))
    missing = [tool for tool in additions if tool not in present]
    if not missing:
        return text
    body = tools.group(2)
    if "\n" in body:
        if body and not body.endswith("\n"):
            body += "\n"
        body += "".join(f'  "{tool}",\n' for tool in missing)
    else:
        values = re.findall(r'"([^"]+)"', body) + missing
        body = ", ".join(f'"{value}"' for value in values)
    new_block = block[: tools.start(2)] + body + block[tools.end(2) :]
    return text[: section.start()] + new_block + text[section.end() :]


def patch_bughunt(path: Path) -> None:
    if not path.exists():
        return
    text = path.read_text()
    text = patch_profile(text, "pr", PR_TOOLS)
    text = patch_profile(text, "deep", DEEP_TOOLS)
    text = patch_profile(text, "all", ALL_TOOLS)
    for name, block in SECTIONS.items():
        if not re.search(rf"(?m)^\[{re.escape(name)}\]\s*$", text):
            text = text.rstrip() + "\n\n" + block.strip() + "\n"
    # Keep the correctness-first Semgrep baseline if an old BugHunt default remains.
    text = re.sub(
        r'(?m)^configs\s*=\s*\[\s*"p/default"\s*,\s*"p/security-audit"\s*,\s*"p/secrets"\s*\]\s*$',
        'configs = ["p/default"]',
        text,
        count=1,
    )
    path.write_text(text)


root = Path.cwd()
project = root / "pyproject.toml"
if not project.exists():
    raise SystemExit("pyproject.toml not found; run this from the BugHunt checkout root")
patch_project(project)
patch_bughunt(root / "bughunt.toml")
print(f"Patched BugHunt checkout to {VERSION}; preserved unrelated project/config content.")
print("Run: uv sync && uv run bughunt configure --auto && uv run bughunt doctor")
