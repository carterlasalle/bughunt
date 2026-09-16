# Copyright (c) 2026 Carter LaSalle
"""Doctor engine-row builders."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from rich.table import Table

from .default_rules import DEFAULT_RULES
from .probes import (
    ast_grep_executable,
    atheris_available,
    executable,
    pysa_executable,
    python_module_available,
    target_executable,
)
from .technology import (
    ENGINE_CAPABILITY,
    TECH_DEEP_TOOLS,
    TechnologyInventory,
    engine_applicable,
    llvm_executable,
    project_executable,
    target_has_module,
    target_python,
)

if TYPE_CHECKING:
    from .cli import Config

    # trace:v1 id=impl.src-bughunt-cli-doctor.cli-row work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC


def cli_row(
    rows: list[tuple[str, str, str]],
    has_python: bool,
    root: Path,
    label: str,
    *names: str,
    python_only: bool = False,
) -> None:
    if python_only and not has_python:
        rows.append(
            (label, "N/A", "no first-party Python capability detected"),
        )
        return
    path = target_executable(root, *names)
    rows.append(
        (label, "READY" if path else "MISSING", path or "not on PATH"),
    )


# trace:v1 id=impl.src-bughunt-doctor-engines.doctor-engine-rows work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def doctor_engine_rows(
    cfg: Config, technology: TechnologyInventory
) -> list[tuple[str, str, str]]:
    """Engine readiness rows."""
    has_python = technology.has("python")
    rows: list[tuple[str, str, str]] = []

    cli_row(rows, has_python, cfg.root, "ruff", "ruff", python_only=True)
    cli_row(
        rows, has_python, cfg.root, "basedpyright", "basedpyright", python_only=True
    )
    cli_row(rows, has_python, cfg.root, "mypy", "mypy", python_only=True)
    cli_row(rows, has_python, cfg.root, "ty", "ty", python_only=True)
    cli_row(rows, has_python, cfg.root, "pyrefly", "pyrefly", python_only=True)
    cli_row(rows, has_python, cfg.root, "pylint", "pylint", python_only=True)
    rows.append(
        ("BugHunt policy pack", "READY", "built-in repository policy scanner"),
    )
    rows.append(
        (
            "BugHunt complexity",
            "READY",
            "built-in cyclomatic/LOC/ABC/asset budget scanner",
        ),
    )
    from .tracelayer_adapter import _cli as _trace_cli

    if not (cfg.root / ".trace").is_dir():
        rows.append(("TraceLayer", "N/A", "no .trace workspace in this repo"))
    elif _trace_cli() is None:
        rows.append(
            ("TraceLayer", "MISSING", "trace CLI not on PATH"),
        )
    else:
        rows.append(
            ("TraceLayer", "READY", "verification evidence available"),
        )
    rows.append(
        (
            "BugHunt default rules",
            "READY",
            f"{len(DEFAULT_RULES)} shipped rules; inspect with `uv run bughunt rules`",
        ),
    )
    from .system_ir_adapter import _cli as _scc_cli

    if not (cfg.root / ".scc").is_dir():
        rows.append(
            ("System IR", "N/A", "no .scc workspace in this repo; run scc init")
        )
    elif _scc_cli() is None:
        rows.append(
            ("System IR", "MISSING", "scc CLI not on PATH"),
        )
    else:
        rows.append(
            ("System IR", "READY", "scc graph available for structural findings"),
        )
    from .bugcorpus_adapter import _cli as _bugcorpus_cli

    corpus_dir = cfg.root / ".bugcorpus"
    if not corpus_dir.is_dir():
        rows.append(("BugCorpus", "N/A", "no .bugcorpus corpus in this repo"))
    elif _bugcorpus_cli() is None:
        rows.append(
            ("BugCorpus", "MISSING", "corpus present but bugcorpus CLI not on PATH"),
        )
    else:
        from .bugcorpus_adapter import verify as _bugcorpus_verify

        ok, _ = _bugcorpus_verify(cfg.root)
        rows.append(
            (
                "BugCorpus",
                "READY" if ok else "ERROR",
                "corpus verify passed" if ok else "corpus verify failed; see scan",
            ),
        )
    cli_row(rows, has_python, cfg.root, "complexipy", "complexipy", python_only=True)
    cli_row(rows, has_python, cfg.root, "radon", "radon", python_only=True)
    cli_row(rows, has_python, cfg.root, "lizard", "lizard")
    cli_row(rows, has_python, cfg.root, "vulture", "vulture", python_only=True)
    cli_row(rows, has_python, cfg.root, "bandit", "bandit", python_only=True)
    cli_row(rows, has_python, cfg.root, "deptry", "deptry", python_only=True)
    cli_row(
        rows, has_python, cfg.root, "import-linter", "lint-imports", python_only=True
    )
    ag = ast_grep_executable(cfg.root)
    rows.append(("ast-grep", "READY" if ag else "MISSING", ag or "not on PATH"))
    cli_row(rows, has_python, cfg.root, "semgrep", "semgrep")
    cli_row(rows, has_python, cfg.root, "CodeQL", "codeql", python_only=True)

    pyre = pysa_executable(cfg.root) if has_python else None
    if not has_python:
        rows.append(
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
            probe = subprocess.run(  # noqa: S603 - audited: argv list, no shell
                probe_cmd,
                cwd=cfg.root,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            rows.append(
                ("Pysa runner", "BROKEN", f"{pyre}: probe failed: {exc}"),
            )
        else:
            if probe.returncode == 0:
                runtime_kind = (
                    "private compatibility runtime" if private else "project runtime"
                )
                detail = f"{runtime_kind}: {pyre}"
                rows.append(("Pysa runner", "READY", detail))
            else:
                tail = (probe.stderr or probe.stdout).strip().splitlines()
                detail = (
                    tail[-1] if tail else "CLI probe failed"
                ) + "; run `uv run bughunt install --only pysa`"
                rows.append(("Pysa runner", "BROKEN", detail))
    else:
        rows.append(
            ("Pysa runner", "MISSING", "run `uv run bughunt install --only pysa`"),
        )

    rows.append(
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
    cli_row(rows, has_python, cfg.root, "CrossHair", "crosshair", python_only=True)
    cli_row(rows, has_python, cfg.root, "pytest", "pytest", python_only=True)
    rows.append(
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
    _target_py = target_python(cfg.root)
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
        ready = target_has_module(_target_py, module)
        rows.append(
            (
                label,
                "N/A" if not has_python else ("READY" if ready else "MISSING"),
                "no first-party Python capability detected"
                if not has_python
                else (
                    "Python module importable in target environment"
                    if ready
                    else "Python module not importable in target environment"
                ),
            ),
        )
    rows.append(
        (
            "HypoFuzz",
            "N/A"
            if not has_python
            else (
                "READY"
                if target_has_module(_target_py, "hypofuzz")
                and target_executable(cfg.root, "hypothesis")
                else "MISSING"
            ),
            "no first-party Python capability detected"
            if not has_python
            else (
                "hypofuzz module + Hypothesis CLI available in target environment"
                if target_has_module(_target_py, "hypofuzz")
                and target_executable(cfg.root, "hypothesis")
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
        cli_row(rows, has_python, cfg.root, label, *names, python_only=True)
    rows.append(
        (
            "BugHunt seam/contract drift",
            "READY" if has_python else "N/A",
            "built-in BHSEAM/BHDB/BHTIME scanner"
            if has_python
            else "no first-party Python capability detected",
        ),
    )
    rows.append(
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
    cli_row(rows, has_python, cfg.root, "mutmut", "mutmut", python_only=True)
    cli_row(rows, has_python, cfg.root, "Schemathesis", "st", "schemathesis")
    a_ready = atheris_available(cfg.root) if has_python else False
    rows.append(
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
            rows.append((engine, "N/A", f"no {capability} capability detected"))
            continue
        if engine == "clippy":
            cargo = project_executable(cfg.root, "cargo")
            path = cargo or None
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
        rows.append(
            (
                engine,
                "READY" if path else "MISSING",
                path or f"applicable ({capability}) but not installed",
            ),
        )

    return rows

    # trace:v1 id=impl.src-bughunt-cli-doctor.helper-module work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC


def helper_module(
    guarded: Table,
    has_python: bool,
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


# trace:v1 id=impl.src-bughunt-doctor-engines.doctor-guarded-rows work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def doctor_guarded_rows(
    cfg: Config, technology: TechnologyInventory, guarded: Table
) -> None:
    """Guarded-helper rows appended to the guarded table."""
    has_python = technology.has("python")

    helper_module(
        guarded,
        has_python,
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
        guarded,
        has_python,
        "freezegun",
        "freezegun",
        (
            "alternative time-control helper; not required when "
            "time-machine or equivalent evidence exists"
        ),
        install_name="freezegun",
    )
    helper_module(
        guarded,
        has_python,
        "VCR.py",
        "vcr",
        "recorded external-payload corpus helper for BHSEAM006",
        install_name="vcrpy",
    )
    helper_module(
        guarded,
        has_python,
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
        guarded,
        has_python,
        "nplusone",
        "nplusone",
        "optional ORM runtime N+1 detector; BugHunt also ships static BHDB001",
        install_name="nplusone",
    )
    helper_module(
        guarded,
        has_python,
        "icontract-hypothesis",
        "icontract_hypothesis",
        (
            "contract-derived property generation; guarded because "
            "compatibility varies with current Hypothesis/Python"
        ),
        install_name="icontract-hypothesis",
    )
    helper_module(
        guarded,
        has_python,
        "Slipcover",
        "slipcover",
        (
            "optional fast coverage engine; coverage.py branch "
            "coverage remains the canonical portable baseline"
        ),
        install_name="slipcover",
    )
    helper_module(
        guarded,
        has_python,
        "beartype",
        "beartype",
        (
            "alternative runtime type checker; Typeguard is the "
            "canonical pytest verification layer"
        ),
        install_name="beartype",
    )
    helper_module(
        guarded,
        has_python,
        "sqlglot",
        "sqlglot",
        (
            "optional SQL parser second opinion; SQLFluff is the "
            "configured correctness scanner"
        ),
        install_name="sqlglot",
    )
    pynguin = target_executable(cfg.root, "pynguin")
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
    asv = target_executable(cfg.root, "asv")
    guarded.add_row(
        "asv",
        "[green]READY[/]" if asv else "[dim]ALTERNATIVE[/]",
        (
            "long-horizon performance benchmark alternative; pytest-benchmark "
            "is the default regression ring"
        ),
    )
    xdoc = target_executable(cfg.root, "xdoctest")
    guarded.add_row(
        "xdoctest",
        "[green]READY[/]" if xdoc else "[dim]ALTERNATIVE[/]",
        "alternative executable-doc engine; pytest --doctest-modules is the default",
    )
