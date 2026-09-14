# Copyright (c) 2026 Carter LaSalle
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path

IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "vendor",
    "build",
    "dist",
    ".tox",
    ".nox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".pyre",
    "site-packages",
    "__pypackages__",
    "mutants",
    ".bughunt",
    "target",
    ".terraform",
    ".next",
    "coverage",
    "htmlcov",
}


@dataclass(slots=True)
class Capability:
    id: str
    detected: bool
    evidence: list[str] = field(default_factory=list)
    detail: str = ""


# trace:v1 id=impl.src-bughunt-technology.technologyinventory work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
@dataclass(slots=True)
class TechnologyInventory:
    root: Path
    capabilities: dict[str, Capability]
    files: dict[str, list[str]]
    git_baseline: str | None = None

    def has(self, capability: str) -> bool:
        item = self.capabilities.get(capability)
        return bool(item and item.detected)

    def evidence(self, capability: str) -> list[str]:
        item = self.capabilities.get(capability)
        return list(item.evidence) if item else []

    # trace:v1 id=impl.src-bughunt-technology-technologyinventory.to-json work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
    def to_json(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "git_baseline": self.git_baseline,
            "capabilities": {
                key: asdict(value) for key, value in self.capabilities.items()
            },
            "files": self.files,
        }


ENGINE_CAPABILITY: dict[str, str] = {
    "actionlint": "github-actions",
    "shellcheck": "shell",
    "dotenv-linter": "dotenv",
    "oasdiff": "openapi",
    "buf": "protobuf",
    "sqlfluff": "sql",
    "squawk": "postgres-migrations",
    "hadolint": "docker",
    "tflint": "terraform",
    "golangci-lint": "go",
    "clippy": "rust",
    "clang-tidy": "cpp-compile-db",
    "cppcheck": "cpp",
    "infer": "cpp-compile-db",
    "phpstan": "php",
    "oxlint": "javascript-typescript",
    "eslint": "javascript-typescript",
    "react-doctor": "react",
    "tsc": "typescript",
    "knip": "javascript-typescript",
    "madge": "javascript-typescript",
    "publint": "javascript-typescript",
    "taplo": "toml",
    "yamllint": "yaml",
    "check-jsonschema": "schema-ref",
    "alembic-check": "alembic",
    "django-migrations": "django",
    "pact-contracts": "pact",
}

ENGINE_CATEGORY: dict[str, str] = {
    "actionlint": "ci-correctness",
    "shellcheck": "shell-correctness",
    "dotenv-linter": "config-correctness",
    "oasdiff": "api-compatibility",
    "buf": "schema-compatibility",
    "sqlfluff": "sql-correctness",
    "squawk": "migration-correctness",
    "hadolint": "container-correctness",
    "tflint": "terraform-correctness",
    "golangci-lint": "go-correctness",
    "clippy": "rust-correctness",
    "clang-tidy": "cpp-correctness",
    "cppcheck": "cpp-correctness",
    "infer": "whole-program-native",
    "phpstan": "php-types",
    "oxlint": "js-ts-correctness",
    "eslint": "js-ts-correctness",
    "react-doctor": "react-correctness",
    "tsc": "ts-types",
    "knip": "js-ts-dead-contract",
    "madge": "js-ts-architecture",
    "publint": "package-correctness",
    "taplo": "config-correctness",
    "yamllint": "config-correctness",
    "check-jsonschema": "schema-correctness",
    "alembic-check": "migration-drift",
    "django-migrations": "migration-drift",
    "pact-contracts": "service-contract",
}


# trace:v1 id=impl.src-bughunt-technology.-iter-files work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _iter_files(root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        base = Path(dirpath)
        for name in filenames:
            path = base / name
            try:
                if path.is_file():
                    yield path
            except OSError:
                # One bad file never fails a scan; skipped
                continue


# trace:v1 id=impl.src-bughunt-technology.-rel work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _rel(root: Path, path: Path) -> str:
    try:
        return (
            path.resolve(strict=False)
            .relative_to(root.resolve(strict=False))
            .as_posix()
        )
    except ValueError:
        return path.as_posix()


def _read_small(path: Path, limit: int = 65536) -> str:
    try:
        return path.read_text(errors="replace")[:limit]
    except OSError:
        return ""


# trace:v1 id=impl.src-bughunt-technology.-package-dependencies work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _package_dependencies(root: Path) -> set[str]:
    deps: set[str] = set()
    pkg = root / "package.json"
    if pkg.exists():
        try:
            data = json.loads(pkg.read_text())
            for section in (
                "dependencies",
                "devDependencies",
                "peerDependencies",
                "optionalDependencies",
            ):
                values = data.get(section, {})
                if isinstance(values, dict):
                    deps.update(str(k).lower() for k in values)
        except (OSError, json.JSONDecodeError, TypeError):
            # Unreadable or malformed input carries no data
            pass
    return deps


# trace:v1 id=impl.src-bughunt-technology.-git-baseline work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _git_baseline(root: Path) -> str | None:
    """Pick a stable local baseline without network access.

    Prefer merge-base with an existing remote/main-ish ref, then the first parent.
    Returning a commit SHA makes downstream compatibility checks deterministic.
    """
    if not (root / ".git").exists() or not shutil.which("git"):
        return None
    refs = ["origin/main", "origin/master", "main", "master"]
    for ref in refs:
        try:
            verify = subprocess.run(  # noqa: S603 - audited: argv list, no shell
                [  # noqa: S607 - PATH-resolved executable
                    "git",
                    "rev-parse",
                    "--verify",
                    "--quiet",
                    ref,
                ],
                cwd=root,
                text=True,
                capture_output=True,
                timeout=8,
                check=False,
            )
            if verify.returncode != 0:
                continue
            merge = subprocess.run(  # noqa: S603 - audited: argv list, no shell
                [  # noqa: S607 - PATH-resolved executable
                    "git",
                    "merge-base",
                    "HEAD",
                    ref,
                ],
                cwd=root,
                text=True,
                capture_output=True,
                timeout=8,
                check=False,
            )
            sha = merge.stdout.strip()
            if merge.returncode == 0 and sha:
                # If HEAD already *is* main/master, compare against the parent
                # rather than declaring HEAD its own compatibility baseline.
                # On a feature branch, the merge-base remains the right PR-like
                # baseline.
                head = subprocess.run(
                    [  # noqa: S607 - PATH-resolved executable
                        "git",
                        "rev-parse",
                        "HEAD",
                    ],
                    cwd=root,
                    text=True,
                    capture_output=True,
                    timeout=8,
                    check=False,
                ).stdout.strip()
                if sha != head:
                    return sha
        except (OSError, subprocess.SubprocessError):
            break
    try:
        parent = subprocess.run(
            [  # noqa: S607 - PATH-resolved executable
                "git",
                "rev-parse",
                "--verify",
                "HEAD^",
            ],
            cwd=root,
            text=True,
            capture_output=True,
            timeout=8,
            check=False,
        )
        return (
            parent.stdout.strip()
            if parent.returncode == 0 and parent.stdout.strip()
            else None
        )
    except (OSError, subprocess.SubprocessError):
        return None


# trace:v1 id=impl.src-bughunt-technology.git-path-exists work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def git_path_exists(root: Path, ref: str | None, path: str) -> bool:
    if not ref or not shutil.which("git"):
        return False
    try:
        proc = subprocess.run(  # noqa: S603 - audited: argv list, no shell
            [  # noqa: S607 - PATH-resolved executable
                "git",
                "cat-file",
                "-e",
                f"{ref}:{path}",
            ],
            cwd=root,
            text=True,
            capture_output=True,
            timeout=8,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


# trace:v1 id=impl.src-bughunt-technology.infer-sql-dialect work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def infer_sql_dialect(root: Path, sql_files: list[str]) -> str:
    corpus = "\n".join(
        _read_small(root / name, 8192) for name in sql_files[:30]
    ).lower()
    project = "\n".join(
        _read_small(root / name, 65536)
        for name in (
            "pyproject.toml",
            "requirements.txt",
            "package.json",
            "go.mod",
            "composer.json",
        )
        if (root / name).exists()
    ).lower()
    combined = corpus + "\n" + project
    if any(
        token in combined
        for token in (
            "postgres",
            "psycopg",
            "asyncpg",
            "::jsonb",
            "returning ",
            "serial",
        )
    ):
        return "postgres"
    if any(
        token in combined
        for token in (
            "mysql",
            "pymysql",
            "mysqlclient",
            "auto_increment",
            "engine=innodb",
        )
    ):
        return "mysql"
    if any(token in combined for token in ("sqlite", "aiosqlite", "sqlite3")):
        return "sqlite"
    if any(token in combined for token in ("bigquery", "google.cloud.bigquery")):
        return "bigquery"
    if "snowflake" in combined:
        return "snowflake"
    if "duckdb" in combined:
        return "duckdb"
    return "ansi"


# trace:v1 id=impl.src-bughunt-technology.discover-technologies work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def discover_technologies(root: Path, *, persist: bool = True) -> TechnologyInventory:
    root = root.resolve()
    buckets: dict[str, list[str]] = {
        "python": [],
        "github-actions": [],
        "shell": [],
        "dotenv": [],
        "openapi": [],
        "protobuf": [],
        "sql": [],
        "postgres-migrations": [],
        "docker": [],
        "terraform": [],
        "go": [],
        "rust": [],
        "cpp": [],
        "cpp-compile-db": [],
        "php": [],
        "javascript-typescript": [],
        "react": [],
        "typescript": [],
        "toml": [],
        "yaml": [],
        "schema-ref": [],
        "alembic": [],
        "django": [],
        "odoo": [],
        "benchmark-tests": [],
        "asyncio": [],
        "pact": [],
    }
    files = list(_iter_files(root))
    npm_deps = _package_dependencies(root)

    sql_paths: list[Path] = []
    js_paths: list[Path] = []
    for path in files:
        rel = _rel(root, path)
        low = rel.lower()
        name = path.name
        suffix = path.suffix.lower()

        if suffix in {".py", ".pyi", ".pyw"}:
            buckets["python"].append(rel)

        if low.startswith(".github/workflows/") and suffix in {".yml", ".yaml"}:
            buckets["github-actions"].append(rel)
        if suffix in {".sh", ".bash", ".zsh", ".ksh"}:
            buckets["shell"].append(rel)
        elif suffix == "" and path.stat().st_size < 1_000_000:
            first = _read_small(path, 256).splitlines()[:1]
            if first and re.search(r"^#!.*\b(?:ba|z|k)?sh\b", first[0]):
                buckets["shell"].append(rel)

        if name == ".env" or name == ".env.example" or name.startswith(".env."):
            buckets["dotenv"].append(rel)
        elif suffix in {
            ".py",
            ".js",
            ".jsx",
            ".mjs",
            ".cjs",
            ".ts",
            ".tsx",
            ".mts",
            ".cts",
        }:
            env_text = _read_small(path, 32768)
            if re.search(
                r"(?:os\.(?:getenv|environ)|process\.env|Deno\.env|getenv\s*\()",
                env_text,
            ):
                buckets["dotenv"].append(f"{rel} (environment access)")

        if suffix in {".yaml", ".yml", ".json"} and any(
            token in name.lower() for token in ("openapi", "swagger")
        ):
            text = _read_small(path, 32768).lower()
            if re.search(
                r"(?:^|[\n{,])\s*[\"']?(?:openapi|swagger)[\"']?\s*[:=]",
                text,
            ):
                buckets["openapi"].append(rel)

        if suffix == ".proto" or name in {"buf.yaml", "buf.work.yaml"}:
            buckets["protobuf"].append(rel)
        if suffix == ".sql":
            sql_paths.append(path)
            buckets["sql"].append(rel)
        if (
            name == "Dockerfile"
            or name.startswith("Dockerfile.")
            or low.endswith("/dockerfile")
        ):
            buckets["docker"].append(rel)
        if suffix == ".tf" or name in {".terraform.lock.hcl", ".tflint.hcl"}:
            buckets["terraform"].append(rel)
        if suffix == ".go" or name == "go.mod":
            buckets["go"].append(rel)
        if suffix == ".rs" or name in {"Cargo.toml", "Cargo.lock"}:
            buckets["rust"].append(rel)
        if suffix in {
            ".c",
            ".cc",
            ".cpp",
            ".cxx",
            ".h",
            ".hh",
            ".hpp",
            ".hxx",
            ".m",
            ".mm",
        }:
            buckets["cpp"].append(rel)
        if name == "compile_commands.json":
            buckets["cpp-compile-db"].append(rel)
        if suffix == ".php" or name == "composer.json":
            buckets["php"].append(rel)
        if (
            suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
            or name == "package.json"
        ):
            js_paths.append(path)
            buckets["javascript-typescript"].append(rel)
        if suffix in {".ts", ".tsx", ".mts", ".cts"} or (
            name.startswith("tsconfig") and name.endswith(".json")
        ):
            buckets["typescript"].append(rel)
        if suffix == ".toml" or name in {"Cargo.toml", "pyproject.toml"}:
            buckets["toml"].append(rel)
        if suffix in {".yaml", ".yml"}:
            buckets["yaml"].append(rel)
        if suffix in {".json", ".yaml", ".yml"}:
            sample = _read_small(path, 32768)
            if "$schema" in sample or "yaml-language-server: $schema=" in sample:
                buckets["schema-ref"].append(rel)
        if (
            name == "alembic.ini"
            or low.endswith("/alembic/env.py")
            or "/alembic/versions/" in low
        ):
            buckets["alembic"].append(rel)
        if name == "manage.py" or ("django" in low and suffix == ".py"):
            buckets["django"].append(rel)
        if suffix == ".py":
            sample = _read_small(path, 65536).lower()
            if "benchmark" in sample and (
                "def test_" in sample or "@pytest.mark.benchmark" in sample
            ):
                buckets["benchmark-tests"].append(rel)
            if "async def " in sample or "asyncio" in sample:
                buckets["asyncio"].append(rel)
        if "pact" in low and (suffix == ".json" or suffix == ".py"):
            buckets["pact"].append(rel)

    # SQL migration classification is intentionally evidence-based. Squawk is
    # PostgreSQL-specific, so do not run it on every random SQL file.
    if sql_paths:
        dialect = infer_sql_dialect(
            root,
            [p.relative_to(root).as_posix() for p in sql_paths],
        )
        if dialect == "postgres":
            for path in sql_paths:
                rel = _rel(root, path)
                parts = {part.lower() for part in path.parts}
                if parts & {
                    "migration",
                    "migrations",
                    "versions",
                    "alembic",
                } or re.search(
                    r"(?:^|/)(?:v?\d{4,}|\d+[_-].*)\.sql$",
                    rel,
                    re.IGNORECASE,
                ):
                    buckets["postgres-migrations"].append(rel)

    if "react" in npm_deps or "react-dom" in npm_deps or "next" in npm_deps:
        buckets["react"] = [
            p.relative_to(root).as_posix()
            for p in js_paths
            if p.suffix.lower() in {".jsx", ".tsx"}
        ][:50]
        if not buckets["react"]:
            buckets["react"] = ["package.json"]
    pyproject_text = _read_small(root / "pyproject.toml", 131072).lower()
    req_text = _read_small(root / "requirements.txt", 131072).lower()
    pydeps = pyproject_text + "\n" + req_text
    if "django" in pydeps and not buckets["django"]:
        buckets["django"] = [
            "pyproject.toml"
            if (root / "pyproject.toml").exists()
            else "requirements.txt",
        ]
    if "alembic" in pydeps and not buckets["alembic"]:
        buckets["alembic"] = [
            "pyproject.toml"
            if (root / "pyproject.toml").exists()
            else "requirements.txt",
        ]
    if "pact-python" in pydeps and not buckets["pact"]:
        buckets["pact"] = ["pyproject.toml"]
    if (
        re.search(r"(?m)(?:^|[^a-z0-9_-])odoo(?:[^a-z0-9_-]|$)", pydeps)
        and not buckets["odoo"]
    ):
        buckets["odoo"] = [
            "pyproject.toml"
            if (root / "pyproject.toml").exists()
            else "requirements.txt",
        ]

    details = {
        "python": "Python source/stubs",
        "github-actions": "GitHub Actions workflows",
        "shell": "shell scripts or shell entrypoints",
        "dotenv": "environment files",
        "openapi": "OpenAPI/Swagger specifications",
        "protobuf": "Protocol Buffer schemas/workspace",
        "sql": "SQL source",
        "postgres-migrations": "PostgreSQL migration SQL",
        "docker": "Dockerfiles",
        "terraform": "Terraform configuration",
        "go": "Go source/module",
        "rust": "Rust crate/source",
        "cpp": "C/C++/Objective-C source",
        "cpp-compile-db": "C/C++ compilation database",
        "php": "PHP source/project",
        "javascript-typescript": "JavaScript/TypeScript project/source",
        "react": "React project",
        "typescript": "TypeScript source/configuration",
        "toml": "TOML configuration",
        "yaml": "YAML configuration",
        "schema-ref": "configuration file with explicit schema reference",
        "alembic": "Alembic migration configuration/history",
        "django": "Django project",
        "odoo": "Odoo project",
        "benchmark-tests": "pytest benchmark tests",
        "asyncio": "asyncio/async Python code",
        "pact": "Pact contract artifacts/dependency",
    }
    capabilities = {
        key: Capability(
            key,
            bool(value),
            sorted(dict.fromkeys(value))[:100],
            details[key],
        )
        for key, value in buckets.items()
    }
    inv = TechnologyInventory(
        root,
        capabilities,
        {k: sorted(dict.fromkeys(v)) for k, v in buckets.items()},
        _git_baseline(root),
    )
    if persist:
        out = root / ".bughunt" / "generated" / "capabilities.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        _ = out.write_text(json.dumps(inv.to_json(), indent=2) + "\n")
    return inv


# trace:v1 id=impl.src-bughunt-technology.load-technology-inventory work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def load_technology_inventory(root: Path) -> TechnologyInventory:
    path = root / ".bughunt" / "generated" / "capabilities.json"
    if not path.exists():
        return discover_technologies(root)
    try:
        data = json.loads(path.read_text())
        caps = {
            key: Capability(
                id=str(value.get("id", key)),
                detected=bool(value.get("detected", False)),
                evidence=[str(x) for x in value.get("evidence", [])],
                detail=str(value.get("detail", "")),
            )
            for key, value in dict(data.get("capabilities", {})).items()
        }
        files = {
            str(k): [str(x) for x in v] for k, v in dict(data.get("files", {})).items()
        }
        return TechnologyInventory(
            root.resolve(),
            caps,
            files,
            data.get("git_baseline"),
        )
    except (OSError, json.JSONDecodeError, TypeError, AttributeError):
        return discover_technologies(root)


# trace:v1 id=impl.src-bughunt-technology.project-executable work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def project_executable(root: Path, *names: str) -> str | None:
    """Resolve repo-local tooling before global PATH.

    This keeps JS/PHP and uv-project tools tied to the repository that is
    actually being analyzed instead of accidentally using an unrelated global
    installation.
    """
    candidates: list[Path] = []
    for name in names:
        candidates.extend(
            [
                root / ".venv" / "bin" / name,
                root / "node_modules" / ".bin" / name,
                root / "vendor" / "bin" / name,
            ],
        )
    for candidate in candidates:
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None


# trace:v1 id=impl.src-bughunt-technology.target-python work=WORK-BUG-4ABH9VEY satisfies=REQ-BUG-KZG483AX implements=PLAN-BUG-560GXA79
def target_python(root: Path) -> str:
    """Interpreter for target-repo execution: its `.venv` first, else ours.

    Defenses that run the target's own tests must resolve modules and console
    scripts from the target environment. Falling back to `sys.executable`
    preserves the old behavior for repositories without a virtualenv.
    """
    venv = root / ".venv" / ("Scripts" if os.name == "nt" else "bin") / "python"
    if venv.is_file() and os.access(venv, os.X_OK):
        return str(venv)
    return sys.executable


# trace:v1 id=impl.src-bughunt-technology.target-executable work=WORK-BUG-4ABH9VEY satisfies=REQ-BUG-KZG483AX implements=PLAN-BUG-560GXA79
def target_executable(root: Path, *names: str) -> str | None:
    """Console-script twin of target_python: `.venv/bin/<name>` wins over PATH."""
    bindir = root / ".venv" / ("Scripts" if os.name == "nt" else "bin")
    for name in names:
        cand = bindir / name
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
    return project_executable(root, *names)


# trace:v1 id=impl.src-bughunt-technology.target-has-module work=WORK-BUG-4ABH9VEY satisfies=REQ-BUG-KZG483AX implements=PLAN-BUG-560GXA79
def target_has_module(python: str, name: str) -> bool:
    """Check importlib against a specific interpreter without importing anything."""
    try:
        proc = subprocess.run(  # noqa: S603 - audited: argv list, no shell
            [
                python,
                "-c",
                (
                    "import importlib.util,sys;"
                    "sys.exit(0 if importlib.util.find_spec(sys.argv[1]) else 1)"
                ),
                name,
            ],
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


# trace:v1 id=impl.src-bughunt-technology.llvm-executable work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def llvm_executable(root: Path, name: str) -> str | None:
    found = project_executable(root, name)
    if found:
        return found
    brew = shutil.which("brew")
    if brew:
        try:
            proc = subprocess.run(  # noqa: S603 - audited: argv list, no shell
                [brew, "--prefix", "llvm"],
                cwd=root,
                text=True,
                capture_output=True,
                timeout=8,
                check=False,
            )
            candidate = Path(proc.stdout.strip()) / "bin" / name
            if proc.returncode == 0 and candidate.exists():
                return str(candidate)
        except (OSError, subprocess.SubprocessError):
            # Probe teardown failure is not a finding
            pass
    return None


def engine_applicable(inventory: TechnologyInventory, engine: str) -> bool:
    capability = ENGINE_CAPABILITY.get(engine)
    return inventory.has(capability) if capability else True


# trace:v1 id=impl.src-bughunt-technology.applicable-technology-engines work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def applicable_technology_engines(inventory: TechnologyInventory) -> set[str]:
    return {
        engine for engine in ENGINE_CAPABILITY if engine_applicable(inventory, engine)
    }
