from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .technology import (
    applicable_technology_engines,
    discover_technologies,
    project_executable,
    target_python,
)


@dataclass(slots=True)
class InstallResult:
    name: str
    status: str
    command: list[str]
    note: str


# Project dev dependencies are intentional: analyzers/type checkers get better
# answers when they can see the target project's exact Python environment.
# Atheris is handled separately because current PyPI artifacts do not cover
# macOS/arm64 even though upstream supports macOS source builds.
PY_PACKAGES: list[tuple[str, str]] = [
    ("ruff", "ruff"),
    ("basedpyright", "basedpyright"),
    ("mypy", "mypy"),
    ("ty", "ty"),
    ("pyrefly", "pyrefly"),
    ("pylint", "pylint"),
    ("vulture", "vulture"),
    ("bandit", "bandit"),
    ("deptry", "deptry"),
    ("import-linter", "import-linter"),
    ("ast-grep-cli", "ast-grep-cli"),
    ("semgrep", "semgrep"),
    # Deal's supported CLI is `python -m deal`; [all] installs its optional
    # analysis/testing helpers as well.
    ("deal", "deal[all]"),
    ("crosshair-tool", "crosshair-tool"),
    ("pytest", "pytest"),
    ("hypothesis", "hypothesis[cli]"),
    ("mutmut", "mutmut"),
    ("schemathesis", "schemathesis"),
    ("radon", "radon"),
    ("lizard", "lizard"),
    ("complexipy", "complexipy"),
    ("coverage", "coverage"),
    ("typeguard", "typeguard"),
    ("pytest-randomly", "pytest-randomly"),
    ("pytest-timeout", "pytest-timeout"),
    ("pytest-socket", "pytest-socket"),
    ("pytest-xdist", "pytest-xdist"),
    ("pytest-run-parallel", "pytest-run-parallel"),
    ("blockbuster", "blockbuster>=1.5,<1.6"),
    ("hypofuzz", "hypofuzz"),
    ("nox", "nox"),
    ("griffe", "griffe"),
    ("pydoclint", "pydoclint"),
    ("validate-pyproject", "validate-pyproject[all]"),
    ("twine", "twine"),
    ("check-manifest", "check-manifest"),
    ("pytest-benchmark", "pytest-benchmark"),
    ("pytest-memray", "pytest-memray"),
    ("pyanalyze", "pyanalyze"),
    ("refurb", "refurb"),
    ("xdoctest", "xdoctest"),
    ("check-jsonschema", "check-jsonschema"),
    ("time-machine", "time-machine"),
    ("freezegun", "freezegun"),
    ("vcrpy", "vcrpy"),
    ("pact-python", "pact-python"),
    ("uvicorn", "uvicorn"),
    ("py-spy", "py-spy"),
]

# Valuable but guarded/advisory helpers. They are never installed by a normal
# `bughunt all` because some execute imports or are primarily advisory. Users can
# explicitly request them with `bughunt install --only NAME`.
OPTIONAL_PY_PACKAGES: list[tuple[str, str]] = [
    ("pynguin", "pynguin"),
    ("wemake-python-styleguide", "wemake-python-styleguide"),
    ("icontract-hypothesis", "icontract-hypothesis"),
    ("nplusone", "nplusone"),
    ("openapi-core", "openapi-core"),
    ("slipcover", "slipcover"),
    ("beartype", "beartype"),
    ("asv", "asv"),
    ("sqlglot", "sqlglot"),
]


def _tail(stdout: str, stderr: str, lines: int = 6) -> str:
    material = (stderr or stdout).strip().splitlines()
    return "\n".join(material[-lines:]) if material else "no output"


def _run(
    cmd: list[str],
    cwd: Path,
    emit: Callable[[str], None],
    *,
    env: dict[str, str] | None = None,
) -> InstallResult:
    emit("$ " + " ".join(cmd))
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            text=True,
            capture_output=True,
            check=False,
            env={**os.environ, **(env or {})},
        )
    except OSError as exc:
        return InstallResult(cmd[-1] if cmd else "command", "ERROR", cmd, str(exc))
    note = _tail(proc.stdout, proc.stderr)
    return InstallResult(
        cmd[-1] if cmd else "command",
        "PASS" if proc.returncode == 0 else "ERROR",
        cmd,
        note,
    )


# trace:v1 id=impl.src-bughunt-installers.-python-importable work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _python_importable(
    root: Path,
    module: str,
    *,
    extra_path: Path | None = None,
) -> bool:
    env = dict(os.environ)
    if extra_path is not None:
        current = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = str(extra_path) + (os.pathsep + current if current else "")
    try:
        proc = subprocess.run(
            [target_python(root), "-c", f"import {module}"],
            cwd=root,
            text=True,
            capture_output=True,
            check=False,
            timeout=45,
            env=env,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


def _brew_prefix(brew: str, formula: str, root: Path) -> str | None:
    try:
        proc = subprocess.run(
            [brew, "--prefix", formula],
            cwd=root,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    value = proc.stdout.strip()
    return value or None


# trace:v1 id=impl.src-bughunt-installers.-install-atheris work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _install_atheris(
    root: Path,
    uv: str,
    *,
    dry_run: bool,
    emit: Callable[[str], None],
) -> list[InstallResult]:
    """Install Atheris into a BugHunt-private runtime directory.

    Keeping Atheris outside project dependencies matters on macOS/arm64: the
    current PyPI release cannot resolve there, and a git source dependency
    would force every clean `uv sync` to reproduce the LLVM source build.
    """
    runtime = root / ".bughunt" / "runtime" / "atheris"
    if _python_importable(root, "atheris"):
        return [
            InstallResult(
                "atheris",
                "PASS",
                [],
                "already importable in the project environment",
            ),
        ]
    if _python_importable(root, "atheris", extra_path=runtime):
        return [
            InstallResult(
                "atheris",
                "PASS",
                [],
                f"BugHunt-private runtime ready at {runtime}",
            ),
        ]

    runtime.parent.mkdir(parents=True, exist_ok=True)
    results: list[InstallResult] = []

    # Linux can normally use the upstream wheel directly, but still install it
    # into BugHunt's private runtime so it does not perturb the project's lock.
    if platform.system() != "Darwin":
        cmd = [
            uv,
            "pip",
            "install",
            "--python",
            sys.executable,
            "--target",
            str(runtime),
            "atheris",
        ]
        if dry_run:
            return [
                InstallResult(
                    "atheris",
                    "DRY-RUN",
                    cmd,
                    f"would install private Atheris runtime at {runtime}",
                ),
            ]
        result = _run(cmd, root, emit)
        result.name = "atheris"
        if result.status == "PASS" and not _python_importable(
            root,
            "atheris",
            extra_path=runtime,
        ):
            result.status = "ERROR"
            result.note = (
                f"installation completed but import verification from {runtime} failed"
            )
        elif result.status == "PASS":
            result.note = (
                f"private Atheris runtime installed and import-verified at {runtime}"
            )
        return [result]

    # On macOS, upstream documents a source build against a non-Apple Clang
    # because Apple Clang does not ship libFuzzer. Homebrew LLVM is our first
    # automatic source-build provider.
    brew = shutil.which("brew")
    if not brew:
        return [
            InstallResult(
                "atheris",
                "ERROR",
                [],
                "macOS Atheris needs LLVM/libFuzzer for a source build, but Homebrew is not available",
            ),
        ]

    prefix = _brew_prefix(brew, "llvm", root)
    if prefix is None:
        cmd = [brew, "install", "llvm"]
        if dry_run:
            results.append(
                InstallResult(
                    "llvm-for-atheris",
                    "DRY-RUN",
                    cmd,
                    "would install non-Apple LLVM/libFuzzer required by Atheris on macOS",
                ),
            )
            prefix = str(Path(brew).parent.parent / "opt" / "llvm")
        else:
            llvm_result = _run(cmd, root, emit)
            llvm_result.name = "llvm-for-atheris"
            results.append(llvm_result)
            if llvm_result.status != "PASS":
                results.append(
                    InstallResult(
                        "atheris",
                        "ERROR",
                        [],
                        "cannot build Atheris until non-Apple LLVM/libFuzzer is available",
                    ),
                )
                return results
            prefix = _brew_prefix(brew, "llvm", root)

    if not prefix:
        results.append(
            InstallResult(
                "atheris",
                "ERROR",
                [],
                "could not resolve Homebrew LLVM prefix",
            ),
        )
        return results

    clang = Path(prefix) / "bin" / "clang"
    if not dry_run and not clang.exists():
        results.append(
            InstallResult(
                "atheris",
                "ERROR",
                [],
                f"Homebrew LLVM clang not found at {clang}",
            ),
        )
        return results

    # Current Atheris 3.1.0 PyPI artifacts contain Linux x86_64 wheels but no
    # macOS/arm64 wheel or sdist, so build the current upstream source tree.
    cmd = [
        uv,
        "pip",
        "install",
        "--python",
        sys.executable,
        "--target",
        str(runtime),
        "git+https://github.com/google/atheris.git",
    ]
    if dry_run:
        results.append(
            InstallResult(
                "atheris",
                "DRY-RUN",
                cmd,
                f"would source-build private Atheris runtime with CLANG_BIN={clang}",
            ),
        )
        return results

    result = _run(cmd, root, emit, env={"CLANG_BIN": str(clang)})
    result.name = "atheris"
    if result.status == "PASS":
        if _python_importable(root, "atheris", extra_path=runtime):
            result.note = f"source build succeeded with {clang}; private runtime import verification passed"
        else:
            result.status = "ERROR"
            result.note = (
                f"source build succeeded but import verification from {runtime} failed"
            )
    else:
        result.note += (
            "\nBugHunt attempted the upstream macOS source-build path using "
            f"CLANG_BIN={clang}."
        )
    results.append(result)
    return results


def _pysa_runtime_python(runtime: Path) -> Path:
    return runtime / "bin" / "python"


def _pysa_runtime_pyre(runtime: Path) -> Path:
    return runtime / "bin" / "pyre"


# trace:v1 id=impl.src-bughunt-installers.-install-pysa-runtime work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _install_pysa_runtime(
    root: Path,
    uv: str,
    *,
    dry_run: bool,
    emit: Callable[[str], None],
) -> list[InstallResult]:
    """Install Pysa/Pyre in an isolated compatibility environment.

    The historical pyre-check CLI is sensitive to Click API changes. Isolating
    it also prevents Pysa's dependencies from constraining Semgrep/Schemathesis
    or the application under test.
    """
    runtime = root / ".bughunt" / "runtime" / "pysa-venv"
    pyre = _pysa_runtime_pyre(runtime)
    python = _pysa_runtime_python(runtime)
    results: list[InstallResult] = []

    verify_cmd = [str(pyre), "--version=none", "--noninteractive", "--help"]
    if pyre.exists() and python.exists():
        if dry_run:
            return [
                InstallResult(
                    "pysa",
                    "PASS",
                    [],
                    f"private Pysa runtime already exists at {runtime}",
                ),
            ]
        check = _run(verify_cmd, root, lambda _line: None)
        if check.status == "PASS":
            return [
                InstallResult(
                    "pysa",
                    "PASS",
                    [],
                    f"private compatibility runtime ready at {runtime}",
                ),
            ]

    runtime.parent.mkdir(parents=True, exist_ok=True)
    # Prefer Python 3.12 for the compatibility runtime. The target repo keeps its
    # own Python; Pysa analyzes source and does not need to share that interpreter.
    venv_cmd = [uv, "venv", "--python", "3.12", "--clear", str(runtime)]
    install_cmd = [
        uv,
        "pip",
        "install",
        "--python",
        str(python),
        "pyre-check",
        "click<8.2",
        "pyrefly",
    ]
    if dry_run:
        return [
            InstallResult(
                "pysa-runtime",
                "DRY-RUN",
                venv_cmd,
                f"would create isolated Python 3.12 runtime at {runtime}",
            ),
            InstallResult(
                "pysa",
                "DRY-RUN",
                install_cmd,
                "would install pyre-check with Click<8.2 compatibility pin",
            ),
        ]

    vr = _run(venv_cmd, root, emit)
    vr.name = "pysa-runtime"
    results.append(vr)
    if vr.status != "PASS":
        return results
    ir = _run(install_cmd, root, emit)
    ir.name = "pysa"
    results.append(ir)
    if ir.status != "PASS":
        return results
    verify = _run(verify_cmd, root, emit)
    verify.name = "pysa-verify"
    if verify.status == "PASS":
        verify.note = f"private Pysa CLI compatibility verification passed at {pyre}"
    results.append(verify)
    return results


PROJECT_EXECUTABLES: dict[str, tuple[str, ...]] = {
    "ruff": ("ruff",),
    "basedpyright": ("basedpyright",),
    "mypy": ("mypy",),
    "ty": ("ty",),
    "pyrefly": ("pyrefly",),
    "pylint": ("pylint",),
    "vulture": ("vulture",),
    "bandit": ("bandit",),
    "deptry": ("deptry",),
    "import-linter": ("lint-imports",),
    "ast-grep-cli": ("ast-grep",),
    "semgrep": ("semgrep",),
    "crosshair-tool": ("crosshair",),
    "pytest": ("pytest",),
    "mutmut": ("mutmut",),
    "schemathesis": ("st", "schemathesis"),
    "radon": ("radon",),
    "lizard": ("lizard",),
    "complexipy": ("complexipy",),
    "coverage": ("coverage",),
    "pytest-randomly": ("pytest",),
    "pytest-timeout": ("pytest",),
    "pytest-socket": ("pytest",),
    "pytest-xdist": ("pytest",),
    "pytest-run-parallel": ("pytest",),
    "hypofuzz": ("hypothesis",),
    "nox": ("nox",),
    "griffe": ("griffe",),
    "pydoclint": ("pydoclint",),
    "validate-pyproject": ("validate-pyproject",),
    "twine": ("twine",),
    "check-manifest": ("check-manifest",),
    "pyanalyze": ("pyanalyze",),
    "refurb": ("refurb",),
    "xdoctest": ("xdoctest",),
    "check-jsonschema": ("check-jsonschema",),
    "py-spy": ("py-spy",),
    "pynguin": ("pynguin",),
    "asv": ("asv",),
}

PROJECT_MODULES: dict[str, str] = {
    "deal": "deal",
    "hypothesis": "hypothesis",
    "hypofuzz": "hypofuzz",
    "typeguard": "typeguard",
    "blockbuster": "blockbuster",
    "pytest-benchmark": "pytest_benchmark",
    "pytest-memray": "pytest_memray",
    "time-machine": "time_machine",
    "freezegun": "freezegun",
    "vcrpy": "vcr",
    "pact-python": "pact",
    "wemake-python-styleguide": "wemake_python_styleguide",
    "icontract-hypothesis": "icontract_hypothesis",
    "nplusone": "nplusone",
    "openapi-core": "openapi_core",
    "slipcover": "slipcover",
    "beartype": "beartype",
    "sqlglot": "sqlglot",
    "uvicorn": "uvicorn",
}


def _inside_project_environment(path: str) -> bool:
    try:
        resolved = Path(path).resolve()
        prefix = Path(sys.prefix).resolve()
        return resolved == prefix or prefix in resolved.parents
    except (OSError, RuntimeError):
        return False


def _project_component_ready(root: Path, name: str) -> bool:
    module = PROJECT_MODULES.get(name)
    if module and _python_importable(root, module):
        return True
    for executable_name in PROJECT_EXECUTABLES.get(name, ()):
        path = shutil.which(executable_name)
        if path and _inside_project_environment(path):
            return True
    return False


# trace:v1 id=impl.src-bughunt-installers.-install-cmd work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _install_cmd(
    name: str,
    cmd: list[str],
    root: Path,
    *,
    dry_run: bool,
    emit: Callable[[str], None],
    note: str,
) -> InstallResult:
    if dry_run:
        return InstallResult(name, "DRY-RUN", cmd, note)
    result = _run(cmd, root, emit)
    result.name = name
    if result.status == "PASS":
        result.note = note.replace("would ", "")
    return result


# trace:v1 id=impl.src-bughunt-installers.-package-manager work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _package_manager(root: Path) -> tuple[str, list[str]] | None:
    choices = [
        ("bun", ["add", "-d"]),
        ("pnpm", ["add", "-D"]),
        ("yarn", ["add", "-D"]),
        ("npm", ["install", "--save-dev"]),
    ]
    preferred: list[str] = []
    if (root / "bun.lock").exists() or (root / "bun.lockb").exists():
        preferred.append("bun")
    if (root / "pnpm-lock.yaml").exists():
        preferred.append("pnpm")
    if (root / "yarn.lock").exists():
        preferred.append("yarn")
    if (root / "package-lock.json").exists():
        preferred.append("npm")
    for want in [*preferred, "bun", "pnpm", "yarn", "npm"]:
        for name, args in choices:
            if name == want and shutil.which(name):
                return shutil.which(name) or name, args
    return None


# trace:v1 id=impl.src-bughunt-installers.-clippy-ready work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _clippy_ready(root: Path) -> bool:
    cargo = project_executable(root, "cargo")
    if not cargo:
        return False
    try:
        return (
            subprocess.run(
                [cargo, "clippy", "--version"],
                cwd=root,
                text=True,
                capture_output=True,
                timeout=15,
                check=False,
            ).returncode
            == 0
        )
    except (OSError, subprocess.SubprocessError):
        return False


# trace:v1 id=impl.src-bughunt-installers.install-technology-tools work=WORK-BUG-4ABH9VEY satisfies=REQ-BUG-KZG483AX implements=PLAN-BUG-560GXA79
def _install_technology_tools(
    root: Path,
    uv: str,
    *,
    dry_run: bool,
    emit: Callable[[str], None],
    only: set[str] | None,
    exclude: set[str],
) -> list[InstallResult]:
    inventory = discover_technologies(root, persist=True)
    applicable = applicable_technology_engines(inventory)
    if inventory.has("github-actions"):
        # actionlint invokes ShellCheck for embedded run: scripts when present.
        applicable.add("shellcheck")
    # Explicit --only is an intentional user request and may preinstall a tool
    # before the corresponding files are added to the repository.
    selected = (set(only) if only is not None else applicable) - exclude
    results: list[InstallResult] = []
    brew = shutil.which("brew")

    brew_formulae = {
        "actionlint": ["actionlint"],
        "shellcheck": ["shellcheck"],
        "dotenv-linter": ["dotenv-linter"],
        "oasdiff": ["oasdiff"],
        "buf": ["buf"],
        "hadolint": ["hadolint"],
        "tflint": ["terraform-linters/tap/tflint"],
        "golangci-lint": ["golangci-lint"],
        "cppcheck": ["cppcheck"],
        "taplo": ["tamasfe/taplo/taplo"],
        "yamllint": ["yamllint"],
    }
    for name, formula in brew_formulae.items():
        if name not in selected:
            continue
        if project_executable(root, name):
            results.append(InstallResult(name, "PASS", [], "already installed"))
        elif platform.system() == "Darwin" and brew:
            results.append(
                _install_cmd(
                    name,
                    [brew, "install", *formula],
                    root,
                    dry_run=dry_run,
                    emit=emit,
                    note=f"would install {name} via Homebrew",
                ),
            )
        else:
            results.append(
                InstallResult(
                    name,
                    "SKIPPED",
                    [],
                    f"{name} is applicable but automatic installation is currently supported on macOS/Homebrew only",
                ),
            )

    for name, package in (
        ("sqlfluff", "sqlfluff"),
        ("squawk", "squawk-cli"),
        ("check-jsonschema", "check-jsonschema"),
    ):
        if name not in selected:
            continue
        if project_executable(root, name):
            results.append(InstallResult(name, "PASS", [], "already installed"))
            continue
        cmd = (
            [uv, "add", "--dev", package]
            if (root / "pyproject.toml").exists()
            else [uv, "tool", "install", package]
        )
        results.append(
            _install_cmd(
                name,
                cmd,
                root,
                dry_run=dry_run,
                emit=emit,
                note=f"would install {package} with uv",
            ),
        )

    if "clippy" in selected:
        if _clippy_ready(root):
            results.append(
                InstallResult(
                    "clippy", "PASS", [], "cargo clippy is already available"
                ),
            )
        elif shutil.which("rustup"):
            results.append(
                _install_cmd(
                    "clippy",
                    [shutil.which("rustup") or "rustup", "component", "add", "clippy"],
                    root,
                    dry_run=dry_run,
                    emit=emit,
                    note="would install the Clippy rustup component",
                ),
            )
        elif platform.system() == "Darwin" and brew:
            results.append(
                _install_cmd(
                    "clippy",
                    [brew, "install", "rust"],
                    root,
                    dry_run=dry_run,
                    emit=emit,
                    note="would install Rust/Clippy via Homebrew",
                ),
            )
        else:
            results.append(
                InstallResult(
                    "clippy",
                    "SKIPPED",
                    [],
                    "Rust detected but no rustup/Homebrew Clippy installer is available",
                ),
            )

    if "clang-tidy" in selected:
        if project_executable(root, "clang-tidy", "run-clang-tidy"):
            results.append(
                InstallResult(
                    "clang-tidy",
                    "PASS",
                    [],
                    "clang-tidy tooling already installed",
                ),
            )
        elif platform.system() == "Darwin" and brew:
            results.append(
                _install_cmd(
                    "clang-tidy",
                    [brew, "install", "llvm"],
                    root,
                    dry_run=dry_run,
                    emit=emit,
                    note="would install LLVM clang-tidy/run-clang-tidy via Homebrew",
                ),
            )
        else:
            results.append(
                InstallResult(
                    "clang-tidy",
                    "SKIPPED",
                    [],
                    "C/C++ compilation database detected but automatic LLVM installation is unavailable",
                ),
            )

    if "infer" in selected:
        if project_executable(root, "infer"):
            results.append(
                InstallResult("infer", "PASS", [], "Infer already installed"),
            )
        else:
            # Don't invent an unofficial installer. Infer remains useful when
            # already provisioned by CI/dev tooling.
            results.append(
                InstallResult(
                    "infer",
                    "SKIPPED",
                    [],
                    "Infer is applicable but BugHunt has no verified portable automatic installer; install Infer separately",
                ),
            )

    js_selected = selected & {
        "oxlint",
        "eslint",
        "react-doctor",
        "tsc",
        "knip",
        "madge",
        "publint",
    }
    missing_js = [
        name for name in sorted(js_selected) if not project_executable(root, name)
    ]
    if missing_js:
        pm = _package_manager(root)
        if pm:
            exe, args = pm
            packages: list[str] = []
            typescript_added = False
            if "oxlint" in missing_js:
                packages.append("oxlint")
            if "eslint" in missing_js:
                packages.extend(["eslint", "@eslint/js"])
                if inventory.has("typescript"):
                    # typescript-eslint v8 rejects TypeScript >= 7
                    # (typescript-eslint#10940); cap the major while v8
                    # is the resolved line so the generated type-aware
                    # config does not crash eslint at startup.
                    packages.extend(["typescript@<7", "typescript-eslint"])
                    typescript_added = True
            if "react-doctor" in missing_js:
                packages.append("react-doctor")
            if "tsc" in missing_js and not typescript_added:
                packages.append("typescript")
            if "knip" in missing_js:
                packages.append("knip")
            if "madge" in missing_js:
                packages.append("madge")
            if "publint" in missing_js:
                packages.append("publint")
            result = _install_cmd(
                "js-correctness-tools",
                [exe, *args, *packages],
                root,
                dry_run=dry_run,
                emit=emit,
                note="would install applicable JavaScript/TypeScript correctness tools as dev dependencies",
            )
            results.append(result)
            if not dry_run and result.status == "PASS":
                # A zero exit does not prove the binaries landed (partial
                # installs, wrong prefix); say exactly what is still missing.
                still = sorted(
                    {name for name in missing_js if not project_executable(root, name)},
                )
                if still:
                    result.status = "ERROR"
                    result.note = (
                        f"installer exited 0 but still unresolvable: {', '.join(still)}"
                    )
        else:
            for name in missing_js:
                results.append(
                    InstallResult(
                        name,
                        "SKIPPED",
                        [],
                        "JavaScript/TypeScript detected but no npm/pnpm/yarn/bun package manager is available",
                    ),
                )
    for name in js_selected - set(missing_js):
        results.append(
            InstallResult(name, "PASS", [], "already installed in project/ PATH"),
        )

    if "phpstan" in selected:
        if project_executable(root, "phpstan"):
            results.append(
                InstallResult("phpstan", "PASS", [], "PHPStan already installed"),
            )
        elif shutil.which("composer"):
            results.append(
                _install_cmd(
                    "phpstan",
                    [
                        shutil.which("composer") or "composer",
                        "require",
                        "--dev",
                        "phpstan/phpstan",
                    ],
                    root,
                    dry_run=dry_run,
                    emit=emit,
                    note="would install PHPStan as a Composer dev dependency",
                ),
            )
        else:
            results.append(
                InstallResult(
                    "phpstan",
                    "SKIPPED",
                    [],
                    "PHP detected but Composer is unavailable",
                ),
            )
    return results


# trace:v1 id=impl.src-bughunt-installers.install-all work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def install_all(
    root: Path,
    *,
    dry_run: bool = False,
    emit: Callable[[str], None] = print,
    only: set[str] | None = None,
    exclude: set[str] | None = None,
) -> list[InstallResult]:
    uv = shutil.which("uv")
    if not uv:
        return [
            InstallResult(
                "uv",
                "ERROR",
                [],
                "uv is required; BugHunt does not fall back to pip/Poetry",
            ),
        ]

    results: list[InstallResult] = []
    exclude = set(exclude or ())
    inventory = discover_technologies(root, persist=True)
    python_components = (
        {name for name, _ in PY_PACKAGES}
        | {name for name, _ in OPTIONAL_PY_PACKAGES}
        | {"atheris", "pysa", "pyre", "pyre-check", "codeql", "watchman"}
    )
    python_needed = inventory.has("python") or (
        only is not None and bool(python_components & only)
    )
    project = root / "pyproject.toml"
    if project.exists():
        # Install independently so one platform/version-specific package cannot
        # prevent the rest of the analysis stack from being installed.
        for name, package_spec in PY_PACKAGES:
            if not python_needed:
                continue
            if name in exclude or (only is not None and name not in only):
                continue
            if _project_component_ready(root, name):
                results.append(
                    InstallResult(
                        name,
                        "PASS",
                        [],
                        "already available in the target project's uv environment",
                    ),
                )
                continue
            cmd = [uv, "add", "--dev", package_spec]
            if dry_run:
                results.append(
                    InstallResult(
                        name,
                        "DRY-RUN",
                        cmd,
                        "would add as a project dev dependency",
                    ),
                )
            else:
                result = _run(cmd, root, emit)
                result.name = name
                results.append(result)
        if (
            python_needed
            and "atheris" not in exclude
            and (only is None or "atheris" in only)
        ):
            results.extend(_install_atheris(root, uv, dry_run=dry_run, emit=emit))
    else:
        for name, package_spec in PY_PACKAGES:
            if not python_needed:
                continue
            if name in exclude or (only is not None and name not in only):
                continue
            cmd = [uv, "tool", "install", package_spec]
            if dry_run:
                results.append(
                    InstallResult(
                        name,
                        "DRY-RUN",
                        cmd,
                        "would install isolated uv tool",
                    ),
                )
            else:
                result = _run(cmd, root, emit)
                result.name = name
                results.append(result)
        if (
            python_needed
            and "atheris" not in exclude
            and (only is None or "atheris" in only)
        ):
            results.append(
                InstallResult(
                    "atheris",
                    "SKIPPED",
                    [],
                    "automatic Atheris harness execution needs a uv project environment; initialize/add BugHunt to the target project first",
                ),
            )

    # Guarded/advisory Python helpers install only on an explicit --only
    # request. This keeps the default bug profile focused and avoids importing
    # project code merely because a test generator happens to be available.
    if python_needed and only is not None:
        optional_map = dict(OPTIONAL_PY_PACKAGES)
        for name in sorted(set(only) & set(optional_map) - exclude):
            package_spec = optional_map[name]
            if _project_component_ready(root, name):
                results.append(
                    InstallResult(
                        name,
                        "PASS",
                        [],
                        "already available in the target project environment",
                    ),
                )
                continue
            cmd = (
                [uv, "add", "--dev", package_spec]
                if project.exists()
                else [uv, "tool", "install", package_spec]
            )
            if dry_run:
                results.append(
                    InstallResult(
                        name,
                        "DRY-RUN",
                        cmd,
                        "guarded/advisory helper; explicit installation requested",
                    ),
                )
            else:
                result = _run(cmd, root, emit)
                result.name = name
                results.append(result)

    # Framework-aware Pylint plugins improve inference/checking only when the
    # framework actually exists in the repository. They are normal dev
    # dependencies because Pylint loads them during the same analysis process.
    if python_needed and project.exists() and only is None:
        framework_plugins: list[tuple[str, str, str]] = []
        if inventory.has("django"):
            framework_plugins.append(
                ("pylint-django", "pylint-django", "pylint_django"),
            )
        if inventory.has("odoo"):
            framework_plugins.append(("pylint-odoo", "pylint-odoo", "pylint_odoo"))
        for name, package_spec, module in framework_plugins:
            if name in exclude:
                continue
            if _python_importable(root, module):
                results.append(
                    InstallResult(
                        name,
                        "PASS",
                        [],
                        "framework-aware Pylint plugin already importable",
                    ),
                )
                continue
            cmd = [uv, "add", "--dev", package_spec]
            if dry_run:
                results.append(
                    InstallResult(
                        name,
                        "DRY-RUN",
                        cmd,
                        "would add framework-aware Pylint plugin",
                    ),
                )
            else:
                result = _run(cmd, root, emit)
                result.name = name
                results.append(result)

    # Pysa gets a private compatibility runtime rather than sharing the target
    # project's Click/dependency graph. `pyre-check` is currently its distribution
    # vehicle even though the active Pysa project is maintained separately.
    if (
        python_needed
        and "pysa" not in exclude
        and "pyre" not in exclude
        and "pyre-check" not in exclude
        and (only is None or bool({"pysa", "pyre", "pyre-check"} & only))
    ):
        results.extend(_install_pysa_runtime(root, uv, dry_run=dry_run, emit=emit))

    # CodeQL is an external binary. On macOS use the maintained Homebrew cask.
    if (
        not python_needed
        and (only is None or "codeql" not in only)
        or "codeql" in exclude
        or only is not None
        and "codeql" not in only
    ):
        pass
    elif shutil.which("codeql"):
        results.append(InstallResult("codeql", "PASS", [], "already installed"))
    elif platform.system() == "Darwin" and shutil.which("brew"):
        cmd = [shutil.which("brew") or "brew", "install", "--cask", "codeql"]
        if dry_run:
            results.append(
                InstallResult(
                    "codeql",
                    "DRY-RUN",
                    cmd,
                    "would install GitHub CodeQL CLI via Homebrew cask",
                ),
            )
        else:
            result = _run(cmd, root, emit)
            result.name = "codeql"
            results.append(result)
    else:
        results.append(
            InstallResult(
                "codeql",
                "SKIPPED",
                [],
                "external CodeQL installer is only automated on macOS/Homebrew in v1; Python defenses still install automatically",
            ),
        )

    # Pyre/Pysa benefits from Watchman for some workflows. Batch Pysa can run
    # without it, so this remains best-effort.
    if (
        python_needed
        and (only is None or "watchman" in only)
        and platform.system() == "Darwin"
        and shutil.which("brew")
        and not shutil.which("watchman")
    ):
        cmd = [shutil.which("brew") or "brew", "install", "watchman"]
        if dry_run:
            results.append(
                InstallResult(
                    "watchman",
                    "DRY-RUN",
                    cmd,
                    "optional Pyre/Pysa support dependency",
                ),
            )
        else:
            result = _run(cmd, root, emit)
            result.name = "watchman"
            results.append(result)

    results.extend(
        _install_technology_tools(
            root,
            uv,
            dry_run=dry_run,
            emit=emit,
            only=only,
            exclude=exclude,
        ),
    )
    return results
