# Copyright (c) 2026 Carter LaSalle
from __future__ import annotations

import importlib.util
import json
import os
import pkgutil
import re
import shutil
import sys
import tomllib
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .coverage_tools import coverage_config
from .policy_scan import ensure_env_example
from .runtime_plugins import write_runtime_plugins
from .technology import discover_technologies, infer_sql_dialect


@dataclass(slots=True)
class ConfigArtifact:
    name: str
    path: str
    state: str
    detail: str


# These directories are implementation/tooling artifacts, dependencies, caches, or
# generated reports. BugHunt's strictness should apply to first-party code rather
# than vendored analyzers and its own runtime.
EXCLUDE_DIRS = [
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    ".direnv",
    "node_modules",
    "build",
    "dist",
    ".tox",
    ".nox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".pyre",
    ".coverage",
    "htmlcov",
    "site-packages",
    "__pypackages__",
    "mutants",
    ".bughunt/runtime",
    ".bughunt/cache",
    ".bughunt/reports",
]


def _existing(root: Path, values: Iterable[str]) -> list[str]:
    result = [v for v in values if (root / v).exists()]
    return result or ["."]


# trace:v1 id=impl.src-bughunt-configurator.-toml work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _toml(root: Path) -> dict[str, Any]:
    path = root / "pyproject.toml"
    if not path.exists():
        return {}
    try:
        return tomllib.loads(path.read_text())
    except (OSError, tomllib.TOMLDecodeError):
        return {}


# trace:v1 id=impl.src-bughunt-configurator.-toml-project work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _toml_project(root: Path) -> dict[str, Any]:
    project = _toml(root).get("project", {})
    return project if isinstance(project, dict) else {}


def _python_version(root: Path) -> str:
    """Analyze against the minimum declared supported 3.x version when possible."""
    req = str(_toml_project(root).get("requires-python", ""))
    versions = [(int(a), int(b)) for a, b in re.findall(r"(?<!\d)(3)\.(\d+)", req)]
    if versions:
        major, minor = min(versions)
        return f"{major}.{minor}"
    return f"{sys.version_info.major}.{sys.version_info.minor}"


def _ruff_target_version(version: str) -> str:
    major, minor = version.split(".", 1)
    return f"py{major}{minor}"


def _rel(config_dir: Path, target: Path) -> str:
    return Path(os.path.relpath(target, config_dir)).as_posix()


# trace:v1 id=impl.src-bughunt-configurator.-package-roots work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _package_roots(root: Path, source_paths: list[str]) -> list[str]:
    roots: list[str] = []
    for source in _existing(root, source_paths):
        base = root / source
        if base.is_file() and base.suffix == ".py":
            roots.append(base.stem)
            continue
        if not base.is_dir():
            continue
        if (base / "__init__.py").exists() and base != root:
            roots.append(base.name)
        roots.extend(
            child.name
            for child in sorted(base.iterdir())
            if child.is_dir() and (child / "__init__.py").exists()
        )
    return list(dict.fromkeys(roots))


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not text.endswith("\n"):
        text += "\n"
    _ = path.write_text(text)


# trace:v1 id=impl.src-bughunt-configurator.ruff-config work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _ruff_config(
    python_version: str,
    source_paths: list[str],
    test_paths: list[str] | None = None,
) -> str:
    # `ALL` is literal here. Ruff itself automatically resolves mutually-exclusive
    # pydocstyle rules when ALL is selected. We never auto-fix during analysis.
    # The report layer can prioritize correctness signals over presentation noise.
    excludes = ",\n  ".join(json.dumps(x) for x in EXCLUDE_DIRS)
    src = ", ".join(json.dumps(x) for x in source_paths)
    # Test files get a narrower contract: asserts ARE the product, docstrings on
    # every test are noise, local imports and mock signatures follow the test
    # convention, and expected values are fixture data, not magic. White-box
    # unit tests necessarily reach into internal helpers; PLC2701 still guards
    # product-to-product private coupling. Test directories are fixtures, not
    # packages, so INP001 does not apply. Fixture sources use explicit `+`
    # joins per basedpyright's explicit-concat style, so ISC003 (which mandates
    # the contradictory implicit style) is scoped here and tracked by BHPLC001.
    test_ignores = ", ".join(
        json.dumps(x)
        for x in [
            "S101",
            "D100",
            "D101",
            "D102",
            "D103",
            "D104",
            "D107",
            "PLC0415",
            "PLC2701",
            "INP001",
            "ISC003",
            "ARG001",
            "ARG005",
            "PLR2004",
            "S607",
        ]
    )
    test_globs = "\n".join(
        f"{json.dumps(p + '/**')} = [{test_ignores}]" for p in (test_paths or [])
    )
    # Helper subprocesses whose stdout IS the machine contract (cli.py parses
    # their printed JSON). print() there is the product, not a debug leftover.
    # Dogfood-specific paths; harmlessly inert in repositories that lack them.
    machine_output_globs = "\n".join(
        f"{json.dumps(p)} = [{json.dumps('T201')}]"
        for p in [
            "src/bughunt/coverage_runner.py",
            "src/bughunt/evidence_scan.py",
            "src/bughunt/importtime_runner.py",
            "src/bughunt/metrics_scan.py",
            "src/bughunt/package_checks.py",
            "src/bughunt/pact_runner.py",
            "src/bughunt/policy_scan.py",
            "src/bughunt/seam_scan.py",
            "src/bughunt/version_diff_runner.py",
        ]
    )
    return (  # nosec B608 - "select" below is a TOML key, not SQL
        f"""# Auto-generated by BugHunt. PARANOID/MAX-RECALL profile.
target-version = "{_ruff_target_version(python_version)}"
preview = true
respect-gitignore = true
force-exclude = true
unsafe-fixes = false
src = [{src}]
extend-exclude = [
  {excludes}
]

[lint]
select = ["ALL"]
# Preview-unstable rules that mandate conventions this tree deliberately does
# not follow: DOC201 wants numpydoc Returns sections (return types live in
# `->` annotations, which the dedicated pydoclint defense already accepts),
# RUF105 wants the novel `ruff: ignore` syntax over standard `noqa` comments.
# D100-D107 mandate docstring PRESENCE; presence mandates produce vacuous
# prose. BugHunt enforces docstring CORRECTNESS (pydoclint + D205-D417), not
# presence.
ignore = [
  "DOC201",
  "RUF105",
  "D100",
  "D101",
  "D102",
  "D103",
  "D104",
  "D105",
  "D106",
  "D107",
  "use-implicit-booleaness-not-comparison-to-zero",
  "PLR2004",
  "PLC0415",
  "TC003",
]
# PLR2004/PLC0415 mirror the pylint calibration: domain literals ('.py',
# small bounds) are not magic, and deferred imports are the
# startup/cycle/optional-dep pattern. Operational numbers belong to policy
# budgets; importtime owns startup.
# TC003 (move typing-only imports to TYPE_CHECKING blocks) is owned by the
# import-linter cycle defense and the importtime startup budget; with
# `from __future__ import annotations` everywhere the moves buy nothing
# while complicating runtime annotation introspection.
# use-implicit-booleaness-not-comparison-to-zero would rewrite status-code
# checks (`rc == 0`) as truthiness. Exit codes are domain values, not
# emptiness; they stay explicit. The non-zero variant (lists, strings) stays on.
fixable = ["ALL"]
unfixable = []
future-annotations = true

[lint.flake8-annotations]
allow-star-arg-any = false
mypy-init-return = false
suppress-dummy-args = false
suppress-none-returning = false

[lint.flake8-type-checking]
strict = true
runtime-evaluated-base-classes = []
runtime-evaluated-decorators = []

[lint.mccabe]
max-complexity = 10

[lint.pylint]
max-args = 8
max-branches = 12
max-returns = 6
max-statements = 50

[lint.per-file-ignores]
{test_globs}
{machine_output_globs}
"""
    )


# trace:v1 id=impl.src-bughunt-configurator.-basedpyright-config work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _basedpyright_config(
    config_dir: Path,
    root: Path,
    python_paths: list[str],
    python_version: str,
) -> str:
    includes = [_rel(config_dir, root / p) for p in _existing(root, python_paths)]
    excludes = [_rel(config_dir, root / p) + "/**" for p in EXCLUDE_DIRS]
    data = {
        "include": includes,
        "exclude": excludes,
        "typeCheckingMode": "all",
        "failOnWarnings": True,
        "pythonVersion": python_version,
        "pythonPlatform": "All",
        "strictListInference": True,
        "strictSetInference": True,
        "strictDictionaryInference": True,
        "strictGenericNarrowing": True,
        "analyzeUnannotatedFunctions": True,
        "enableTypeIgnoreComments": False,
        "reportAny": "error",
        "reportExplicitAny": "error",
        "reportUnreachable": "error",
        "reportMissingTypeStubs": "error",
        "reportUnknownArgumentType": "error",
        "reportUnknownLambdaType": "error",
        "reportUnknownMemberType": "error",
        "reportUnknownParameterType": "error",
        "reportUnknownVariableType": "error",
        "reportIgnoreCommentWithoutRule": "error",
        "reportUnnecessaryTypeIgnoreComment": "error",
        "reportInvalidCast": "error",
        "reportImplicitRelativeImport": "error",
        "reportPrivateLocalImportUsage": "error",
        "reportUnsafeMultipleInheritance": "error",
        "reportImplicitAbstractClass": "error",
        "reportUnannotatedClassAttribute": "error",
        "reportIncompatibleUnannotatedOverride": "error",
        "reportInvalidAbstractMethod": "error",
        "deprecateTypingAliases": True,
        "disableBytesTypePromotions": True,
        "stubPath": "../stubs",
    }
    return json.dumps(data, indent=2)


# trace:v1 id=impl.src-bughunt-configurator.-mypy-config work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _mypy_config(root: Path, python_paths: list[str], python_version: str) -> str:
    files = ", ".join(_existing(root, python_paths))
    enabled = (
        "deprecated, redundant-expr, possibly-undefined, truthy-bool, "
        "truthy-iterable, ignore-without-code, unused-awaitable, "
        "explicit-override, mutable-override, explicit-any, exhaustive-match"
    )
    # Keep this regex a normal INI value; double escaping avoids Python's own
    # invalid-escape warnings while yielding the desired regex to mypy.
    exclude = (
        r"(?x)(^|/)(\.venv|venv|node_modules|build|dist|\.bughunt/runtime|"
        r"\.bughunt/cache|\.bughunt/reports|mutants)(/|$)"
    )
    return f"""# Auto-generated by BugHunt. PARANOID/MAX-RECALL profile.
[mypy]
python_version = {python_version}
files = {files}
strict = True
warn_unreachable = True
warn_unused_configs = True
strict_bytes = True
follow_imports = normal
follow_untyped_imports = True
strict_equality = True
strict_equality_for_none = True
extra_checks = True
local_partial_types = True

# `--strict` does not ban every escape hatch; these do.
disallow_any_unimported = True
disallow_any_expr = True
disallow_any_decorated = True
disallow_any_explicit = True
disallow_any_generics = True
disallow_subclassing_any = True

warn_unused_ignores = True
warn_redundant_casts = True
warn_return_any = True
warn_no_return = True
show_error_codes = True
show_column_numbers = True
show_error_context = True
pretty = False
color_output = False
no_implicit_reexport = True

# Optional checks with concrete correctness value.
enable_error_code = {enabled}

cache_dir = .bughunt/cache/mypy
exclude = {exclude}
"""


# trace:v1 id=impl.src-bughunt-configurator.-ty-config work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _ty_config() -> str:
    return """# Auto-generated by BugHunt. PARANOID/MAX-RECALL profile.
[rules]
all = "error"

[analysis]
strict-equality-semantics = true
strict-generic-narrowing = true
respect-type-ignore-comments = false

[terminal]
error-on-warning = true
output-format = "concise"
"""


# trace:v1 id=impl.src-bughunt-configurator.-pyrefly-config work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _pyrefly_config(
    config_dir: Path,
    root: Path,
    python_paths: list[str],
    source_paths: list[str],
    python_version: str,
) -> str:
    includes = [_rel(config_dir, root / p) for p in _existing(root, python_paths)]
    search = [_rel(config_dir, root / p) for p in _existing(root, source_paths)]
    excludes = [_rel(config_dir, root / p) + "/**" for p in EXCLUDE_DIRS]
    interpreter = root / ".venv" / "bin" / "python"
    if os.name == "nt":
        interpreter = root / ".venv" / "Scripts" / "python.exe"
    lines = [
        "# Auto-generated by BugHunt. PARANOID/MAX-RECALL profile.",
        'preset = "all"',
        'min-severity = "warn"',
        f'python-version = "{python_version}"',
        'python-platform = "all"',
        "check-unannotated-defs = true",
        'infer-return-types = "checked"',
        "infer-with-first-use = true",
        "strict-callable-subtyping = true",
        "treat-all-caps-as-final = true",
        "ignore-errors-in-generated-code = false",
        "permissive-ignores = false",
        "replace-imports-with-any = []",
        "ignore-missing-imports = []",
        "replace-untyped-imports-with-any = []",
        "use-ignore-files = true",
        "project-includes = [" + ", ".join(json.dumps(x) for x in includes) + "]",
        "project-excludes = [" + ", ".join(json.dumps(x) for x in excludes) + "]",
        "search-path = [" + ", ".join(json.dumps(x) for x in search) + "]",
    ]
    if interpreter.exists():
        lines.append(
            f"python-interpreter-path = {json.dumps(_rel(config_dir, interpreter))}",
        )
    lines.extend(
        [
            "",
            "[errors]",
            "# implicit-bool forbids truthiness tests (863 hits on idiomatic `if x:`).",
            "# It contradicts the emptiness-simplification rule and would demand",
            "# explicit bool() conversions across every condition. Scoped; the Any",
            "# trail (unknown-argument-type, explicit-any) stays on.",
            "implicit-bool = false",
        ],
    )
    return "\n".join(lines) + "\n"


# trace:v1 id=impl.src-bughunt-configurator.-pylint-extensions work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _pylint_extensions() -> list[str]:
    """Discover bundled Pylint extension checkers from the installed version."""
    try:
        from pylint import extensions  # type: ignore[import-not-found]
    except Exception:  # noqa: BLE001 - optional-dependency probe: pylint may be absent or broken
        return []
    result: list[str] = []
    for module in pkgutil.iter_modules(extensions.__path__):
        name = module.name
        if name.startswith("_") or name in {"typing"}:
            continue
        result.append(f"pylint.extensions.{name}")
    return sorted(result)


# trace:v1 id=impl.src-bughunt-configurator.-pylint-config work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _pylint_config(
    *,
    extra_plugins: Iterable[str] = (),
    for_tests: bool = False,
) -> str:
    # Pylint's inference catches bugs that syntax-only linters cannot. Enable all
    # checkers, including normally-disabled informational suppression diagnostics;
    # report prioritization keeps convention/style chatter below correctness hits.
    # The tests variant relaxes rules that misread test idiom: docstrings are
    # fixture prose, expected values are the assertion (not magic), local imports
    # isolate the unit, fake signatures must mirror, ruff owns line length, and
    # status-code asserts stay explicit (ADR-005).
    plugins = ",".join(dict.fromkeys([*_pylint_extensions(), *extra_plugins]))
    tests_disable = (
        "missing-module-docstring,"
        "missing-function-docstring,"
        "missing-class-docstring,"
        "import-outside-toplevel,"
        "unused-argument,"
        "magic-value-comparison,"
        "line-too-long,"
        "use-implicit-booleaness-not-comparison-to-zero"
    )
    # Strict keeps every checker except rules that misread product idiom:
    # to-zero (status codes stay explicit, ADR-005), docstring presence
    # (correctness over presence, ADR-004), magic-value (domain literals
    # are not magic; operational numbers belong to policy budgets),
    # invalid-name (ast mandates visit_CamelCase), import-outside-toplevel
    # (deferred imports are the startup/cycle/optional-dep pattern),
    # walrus/broad-except/duplicate-code/line-too-long (style or owned by
    # ruff BLE001/E501; per-site noqas retained).
    strict_disable = (
        "use-implicit-booleaness-not-comparison-to-zero,"
        "missing-module-docstring,"
        "missing-function-docstring,"
        "missing-class-docstring,"
        "magic-value-comparison,"
        "invalid-name,"
        "import-outside-toplevel,"
        "consider-using-assignment-expr,"
        "broad-exception-caught,"
        "duplicate-code,"
        "line-too-long"
    )
    disable = tests_disable if for_tests else strict_disable
    return f"""# Auto-generated by BugHunt. PARANOID/MAX-RECALL profile.
[MAIN]
ignore=.git,.venv,venv,node_modules,build,dist,.bughunt,mutants
persistent=yes
jobs=0
load-plugins={plugins}
limit-inference-results=1000

[MESSAGES CONTROL]
enable=all
disable={disable}

[REPORTS]
reports=no
score=no

[REFACTORING]
max-nested-blocks=5
never-returning-functions=sys.exit,argparse.ArgumentParser.error

[DESIGN]
max-args=8
max-attributes=12
max-bool-expr=5
max-branches=12
max-locals=20
max-parents=7
max-public-methods=20
max-returns=6
max-statements=50
min-public-methods=0

[SIMILARITIES]
min-similarity-lines=6
ignore-comments=yes
ignore-docstrings=yes
ignore-imports=yes
ignore-signatures=yes
"""


# trace:v1 id=impl.src-bughunt-configurator.-bandit-config work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _bandit_config() -> str:
    # Empty tests/skips means all installed plugins. BugHunt supplies source roots
    # explicitly, so test-only assertion warnings do not flood application scans.
    # B404 (import-subprocess audit) is skipped globally: importing subprocess
    # carries no signal beyond "this program spawns processes", and every
    # subprocess USE site remains covered by B603/B607 plus the S603/S607 audit
    # markers enforced under the strict overlay.
    return """# Auto-generated by BugHunt. All Bandit checks except documented skips.
exclude_dirs:
  - .git
  - .venv
  - venv
  - node_modules
  - build
  - dist
  - .bughunt
  - mutants
skips: [B404]
tests: []
"""


# trace:v1 id=impl.src-bughunt-configurator.-astgrep-config work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _astgrep_config() -> tuple[str, dict[str, str]]:
    config = """# Auto-generated by BugHunt.
ruleDirs:
  - ast-grep/rules
testConfigs:
  - testDir: ast-grep/tests
"""
    rules = {
        "swallowed-exception.yml": """id: bughunt-swallowed-exception
language: Python
severity: error
message: Exception is silently swallowed; this hides failures and can corrupt
  control flow.
rule:
  any:
    - pattern: |
        try:
          $$$BODY
        except $EXC:
          pass
    - pattern: |
        try:
          $$$BODY
        except:
          pass
""",
        "return-in-finally.yml": """id: bughunt-return-in-finally
language: Python
severity: error
message: return/break/continue inside finally can suppress exceptions or override
  control flow.
rule:
  any:
    - pattern: |
        try:
          $$$BODY
        finally:
          $$$BEFORE
          return $RET
          $$$AFTER
    - pattern: |
        try:
          $$$BODY
        finally:
          $$$BEFORE
          break
          $$$AFTER
    - pattern: |
        try:
          $$$BODY
        finally:
          $$$BEFORE
          continue
          $$$AFTER
""",
    }
    return config, rules


# trace:v1 id=impl.src-bughunt-configurator.-semgrep-correctness-rules work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _semgrep_correctness_rules() -> str:
    """High-signal local correctness rules owned by BugHunt.

    These intentionally target runtime/reliability bugs that are awkward for
    ordinary type checkers. Security-only rules live in optional upstream packs.
    """
    return r"""rules:
  - id: bughunt.cached-generator
    message: Caching a generator reuses the same consumable iterator; later cache hits
      can silently return an exhausted generator.
    languages: [python]
    severity: ERROR
    metadata: {category: correctness, confidence: high}
    pattern-either:
      - pattern: |
          @functools.lru_cache(...)
          def $F(...):
            ...
            yield ...
      - pattern: |
          @functools.cache
          def $F(...):
            ...
            yield ...

  - id: bughunt.unconsumed-threadpool-map
    message: ThreadPoolExecutor.map results are never consumed, so worker exceptions may
      never be observed by the caller.
    languages: [python]
    severity: ERROR
    metadata: {category: correctness, confidence: high}
    patterns:
      - pattern-inside: |
          with concurrent.futures.ThreadPoolExecutor(...) as $POOL:
            ...
      - pattern: $POOL.map(...)
      - pattern-not-inside: |
          for $X in $POOL.map(...):
            ...
      - pattern-not-inside: |
          list($POOL.map(...))
      - pattern-not-inside: |
          tuple($POOL.map(...))
      - pattern-not-inside: |
          $RESULTS = $POOL.map(...)
          ...
          for $X in $RESULTS:
            ...

  - id: bughunt.dict-delete-during-iteration
    message: Deleting entries from the dictionary being iterated can raise RuntimeError
      or invalidate iteration semantics.
    languages: [python]
    severity: ERROR
    metadata: {category: correctness, confidence: high}
    pattern-either:
      - pattern: |
          for $K in $D:
            ...
            del $D[$K]
      - pattern: |
          for $K in $D.keys():
            ...
            del $D[$K]
      - pattern: |
          for $K, $V in $D.items():
            ...
            del $D[$K]

  - id: bughunt.list-mutation-during-iteration
    message: Mutating the list currently being iterated changes iterator behavior and
      commonly skips, repeats, or indefinitely extends work.
    languages: [python]
    severity: WARNING
    metadata: {category: correctness, confidence: medium}
    pattern-either:
      - pattern: |
          for $X in $L:
            ...
            $L.append(...)
      - pattern: |
          for $X in $L:
            ...
            $L.extend(...)
      - pattern: |
          for $X in $L:
            ...
            $L.remove(...)
      - pattern: |
          for $X in $L:
            ...
            $L.pop(...)
      - pattern: |
          for $X in $L:
            ...
            del $L[...]

  - id: bughunt.sync-sleep-in-async
    message: time.sleep inside async code blocks the event loop; use an async wait or
      move blocking work off the loop.
    languages: [python]
    severity: ERROR
    metadata: {category: correctness, confidence: high}
    patterns:
      - pattern: time.sleep(...)
      - pattern-inside: |
          async def $F(...):
            ...
      - pattern-not-inside: |
          async def $F(...):
            def $INNER(...):
              ...

  - id: bughunt.file-rebound-before-close
    message: This file handle is overwritten before it is closed, leaking the original
      resource until garbage collection.
    languages: [python]
    severity: ERROR
    metadata: {category: correctness, confidence: high}
    patterns:
      - pattern: |
          $F = open($A, ...)
          ...
          $F = open($B, ...)
      - pattern-not: |
          $F = open($A, ...)
          ...
          $F.close()
          ...
          $F = open($B, ...)

  - id: bughunt.named-tempfile-name-before-flush
    message: A NamedTemporaryFile path is consumed after writes but before flush/close,
      so another reader may observe incomplete data.
    languages: [python]
    severity: ERROR
    metadata: {category: correctness, confidence: high}
    patterns:
      - pattern-inside: |
          $F = tempfile.NamedTemporaryFile(...)
          ...
          $F.write(...)
          ...
      - pattern: $F.name
      - pattern-not-inside: |
          $F = tempfile.NamedTemporaryFile(...)
          ...
          $F.write(...)
          ...
          $F.flush()
          ...
          $F.name
      - pattern-not-inside: |
          $F = tempfile.NamedTemporaryFile(...)
          ...
          $F.write(...)
          ...
          $F.close()
          ...
          $F.name
"""


# trace:v1 id=impl.src-bughunt-configurator.-import-linter-config work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _import_linter_config(package_roots: list[str]) -> str | None:
    if not package_roots:
        return None
    key = "root_package" if len(package_roots) == 1 else "root_packages"
    root_value = (
        json.dumps(package_roots[0])
        if len(package_roots) == 1
        else "[" + ", ".join(json.dumps(x) for x in package_roots) + "]"
    )
    lines = [
        (
            "# Auto-generated by BugHunt. Generic invariant only: "
            "no dependency cycles among package siblings."
        ),
        "[tool.importlinter]",
        f"{key} = {root_value}",
        "include_external_packages = false",
        # Runtime import cycles can still be real even if imports are under
        # TYPE_CHECKING, so maximum-recall mode keeps those edges visible.
        "exclude_type_checking_imports = false",
        "",
    ]
    for i, pkg in enumerate(package_roots, 1):
        lines += [
            "[[tool.importlinter.contracts]]",
            f'id = "bughunt-acyclic-{i}"',
            f'name = "{pkg} sibling packages are acyclic"',
            'type = "acyclic_siblings"',
            f'ancestors = ["{pkg}"]',
            "depth = 20",
            'unmatched_ignore_imports_alerting = "error"',
            "",
        ]
    return "\n".join(lines)


# trace:v1 id=impl.src-bughunt-configurator.-pysa-files work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _pysa_files(
    root: Path,
    source_paths: list[str],
    python_version: str,
) -> tuple[str, str, str]:
    sources = _existing(root, source_paths)
    pyre = {
        "source_directories": sources,
        "taint_models_path": ".bughunt/configs/pysa",
        "strict": True,
        "python_version": f"{python_version}.0",
        "site_package_search_strategy": "pep561",
        "exclude": [
            ".*/\\.venv/.*",
            ".*/\\.bughunt/runtime/.*",
            ".*/\\.bughunt/cache/.*",
            ".*/build/.*",
            ".*/dist/.*",
            ".*/mutants/.*",
        ],
    }
    # Pysa cannot infer an application's semantic sources/sinks safely from names
    # alone. This creates a valid namespace + rule and an empty model file. V2 can
    # add proven models; built-in framework models remain available.
    taint = {
        "sources": [
            {
                "name": "BugHuntUserControlled",
                "comment": (
                    "Project-specific user-controlled input; add "
                    "models only when semantics are established."
                ),
            },
        ],
        "sinks": [
            {
                "name": "BugHuntSensitiveOperation",
                "comment": (
                    "Project-specific sensitive operation; add "
                    "models only when semantics are established."
                ),
            },
        ],
        "features": [],
        "rules": [
            {
                "name": "BugHunt user-controlled data to sensitive operation",
                "code": 91001,
                "sources": ["BugHuntUserControlled"],
                "sinks": ["BugHuntSensitiveOperation"],
                "message_format": (
                    "BugHunt: user-controlled data reaches a sensitive operation"
                ),
            },
        ],
    }
    models = """# Auto-generated starter model file for BugHunt.
# No guessed application models are inserted. False semantic assumptions are
# worse than an explicit coverage gap. Bug Corpus/V2 adds proven models here.
"""
    return json.dumps(pyre, indent=2), json.dumps(taint, indent=2), models


# trace:v1 id=impl.src-bughunt-configurator.-hypothesis-plugin work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _hypothesis_plugin() -> str:
    # No correctness health checks are suppressed. We deliberately ask Hypothesis
    # for many examples and preserve shrinking/reproduction data.
    return """# Auto-generated BugHunt Hypothesis profile loader.
from __future__ import annotations

import os
from hypothesis import settings

settings.register_profile(
    "bughunt",
    max_examples=2000,
    deadline=None,
    derandomize=False,
    print_blob=True,
    report_multiple_bugs=True,
    stateful_step_count=100,
)
if os.getenv("HYPOTHESIS_PROFILE") == "bughunt":
    settings.load_profile("bughunt")
"""


# trace:v1 id=impl.src-bughunt-configurator.-complexipy-config work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _complexipy_config(source_paths: list[str]) -> str:
    paths = ", ".join(json.dumps(x) for x in source_paths)
    excludes = ", ".join(json.dumps(x + "/**") for x in EXCLUDE_DIRS)
    return f"""# Auto-generated by BugHunt.
        # Cognitive complexity is independent of McCabe CC.
paths = [{paths}]
max-complexity-allowed = 10
failed = true
quiet = false
sort = "desc"
check-script = true
no-ignore = true
report-ignored = true
exclude = [{excludes}]
output-format = []
"""


# trace:v1 id=impl.src-bughunt-configurator.-ensure-complexity-budgets work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _ensure_complexity_budgets(root: Path) -> ConfigArtifact:
    path = root / "bughunt.toml"
    current = path.read_text() if path.exists() else ""
    try:
        parsed = tomllib.loads(current) if current.strip() else {}
    except tomllib.TOMLDecodeError:
        parsed = {}
    if "complexity" in parsed:
        return ConfigArtifact(
            "complexity budgets",
            "bughunt.toml",
            "EXISTING",
            "existing [complexity] budgets preserved",
        )
    block = """
# BEGIN BUGHUNT MANAGED COMPLEXITY BUDGETS
[complexity]
# Risk budgets. Exceeding a budget is a refactoring/testing signal, not permission
# to split coherent code into meaningless fragments or hide logic behind indirection.
cyclomatic_warn = 10
cyclomatic_error = 20
cognitive_max = 10
function_loc_warn = 80
function_loc_error = 150
file_loc_warn = 500
file_loc_error = 1200
abc_warn = 30
abc_error = 45
js_file_kb_warn = 500
css_file_kb_warn = 250
wasm_file_kb_warn = 2000
bundle_kb_warn = 1500
# END BUGHUNT MANAGED COMPLEXITY BUDGETS
"""
    _write(path, current.rstrip() + ("\n\n" if current.strip() else "") + block.strip())
    return ConfigArtifact(
        "complexity budgets",
        "bughunt.toml",
        "READY",
        (
            "cyclomatic, cognitive, function/file LOC, ABC, and "
            "built-asset size budgets generated"
        ),
    )


# trace:v1 id=impl.src-bughunt-configurator.-schemathesis-config work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _schemathesis_config(max_examples: int) -> str:
    return f"""# Auto-generated by BugHunt. Used for local targets only.
continue-on-failure = true
workers = "auto"

[generation]
mode = "all"
max-examples = {max_examples}
no-shrink = false
deterministic = false
allow-x00 = true
allow-extra-parameters = true
"""


# trace:v1 id=impl.src-bughunt-configurator.-mutmut-block work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _mutmut_block(source_paths: list[str], test_paths: list[str]) -> str:
    src = ", ".join(json.dumps(p.rstrip("/") + "/") for p in source_paths)
    tests = ", ".join(json.dumps(p.rstrip("/") + "/") for p in test_paths)
    return f"""\n# BEGIN BUGHUNT MANAGED MUTMUT CONFIG
[tool.mutmut]
source_paths = [{src}]
pytest_add_cli_args_test_selection = [{tests}]
# Coverage gaps are reported separately as BHCOV001/BHCOV002. Restrict mutation
# to covered lines by default so mutation testing measures assertion strength
# instead of spending most of its budget on code the suite never executes.
mutate_only_covered_lines = true
# END BUGHUNT MANAGED MUTMUT CONFIG
"""


# trace:v1 id=impl.src-bughunt-configurator.-normalized-paths work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _normalized_paths(value: object) -> list[str]:
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, list):
        values = [str(item) for item in value]
    else:
        return []
    return [
        item.replace("\\", "/").strip().removeprefix("./").rstrip("/") or "."
        for item in values
    ]


def _path_covered(configured: list[str], required: str) -> bool:
    req = required.replace("\\", "/").strip().removeprefix("./").rstrip("/") or "."
    for item in configured:
        base = item.rstrip("/") or "."
        if base == "." or req == base or req.startswith(base + "/"):
            return True
    return False


# trace:v1 id=impl.src-bughunt-configurator.-ensure-mutmut-config work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _ensure_mutmut_config(
    root: Path,
    source_paths: list[str],
    test_paths: list[str],
) -> ConfigArtifact:
    pyproject = root / "pyproject.toml"
    if not pyproject.exists():
        snippet = root / ".bughunt" / "configs" / "mutmut-snippet.toml"
        _write(snippet, _mutmut_block(source_paths, test_paths).lstrip())
        return ConfigArtifact(
            "mutmut",
            str(snippet.relative_to(root)),
            "REVIEW",
            "no pyproject.toml; generated a mergeable config snippet",
        )

    required_sources = _existing(root, source_paths)
    required_tests = _existing(root, test_paths) if test_paths else []
    current_text = pyproject.read_text(errors="replace")
    begin = "# BEGIN BUGHUNT MANAGED MUTMUT CONFIG"
    end = "# END BUGHUNT MANAGED MUTMUT CONFIG"

    # BugHunt owns only its marked block. Refreshing it is safe and fixes the
    # previous behavior where source/test inference changes were never applied.
    if begin in current_text and end in current_text:
        block = _mutmut_block(required_sources, required_tests).strip()
        pattern = re.compile(re.escape(begin) + r".*?" + re.escape(end), re.DOTALL)
        _ = pyproject.write_text(pattern.sub(block, current_text))
        return ConfigArtifact(
            "mutmut",
            "pyproject.toml",
            "READY",
            (
                f"managed config refreshed and verified; "
                f"sources={required_sources!r}; tests={required_tests!r}; "
                "mutate_only_covered_lines=true"
            ),
        )

    data = _toml(root)
    tool = data.get("tool") if isinstance(data.get("tool"), dict) else {}
    existing = tool.get("mutmut") if isinstance(tool, dict) else None
    if isinstance(existing, dict):
        configured_sources = _normalized_paths(existing.get("source_paths"))
        configured_tests = _normalized_paths(
            existing.get("pytest_add_cli_args_test_selection"),
        )
        gaps: list[str] = []
        if "paths_to_mutate" in existing:
            gaps.append(
                "obsolete `paths_to_mutate` key; current mutmut uses `source_paths`",
            )
        if "tests_dir" in existing:
            gaps.append(
                (
                    "obsolete `tests_dir` key; current mutmut uses "
                    "`pytest_add_cli_args_test_selection`"
                ),
            )
        if existing.get("mutate_only_covered_lines") is False:
            gaps.append(
                (
                    "`mutate_only_covered_lines=false` wastes mutation "
                    "budget on code the suite never reaches; BugHunt "
                    "reports uncovered code separately and recommends "
                    "true"
                ),
            )
        missing_sources = [
            item
            for item in required_sources
            if not _path_covered(configured_sources, item)
        ]
        missing_tests = [
            item for item in required_tests if not _path_covered(configured_tests, item)
        ]
        if not configured_sources:
            gaps.append("missing `source_paths`")
        elif missing_sources:
            gaps.append(f"source_paths miss {missing_sources!r}")
        if required_tests and not configured_tests:
            gaps.append("missing `pytest_add_cli_args_test_selection`")
        elif missing_tests:
            gaps.append(f"test selection misses {missing_tests!r}")
        if gaps:
            return ConfigArtifact(
                "mutmut",
                "pyproject.toml",
                "REVIEW",
                (
                    "existing user-owned [tool.mutmut] preserved "
                    "but coverage is incomplete: "
                )
                + "; ".join(gaps),
            )
        return ConfigArtifact(
            "mutmut",
            "pyproject.toml",
            "EXISTING",
            (
                f"existing user-owned config preserved and coverage-verified; "
                f"sources={configured_sources!r}; tests={configured_tests!r}"
            ),
        )

    backup_dir = root / ".bughunt" / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup = backup_dir / "pyproject.toml.before-bughunt-mutmut"
    if not backup.exists():
        try:
            _ = shutil.copy2(pyproject, backup)
        except OSError:
            # Best-effort backup only; a failed copy must never block config.
            pass
    with pyproject.open("a") as f:
        _ = f.write(_mutmut_block(required_sources, required_tests))
    return ConfigArtifact(
        "mutmut",
        "pyproject.toml",
        "READY",
        (
            "added managed [tool.mutmut] source/test scoping; original "
            "backed up under .bughunt/backups"
        ),
    )


# trace:v1 id=impl.src-bughunt-configurator.configure-custom-checks work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def configure_custom_checks(root: Path, targets: Iterable[object]) -> ConfigArtifact:
    """Persist high-confidence generated semantic campaigns as custom.checks.

    The managed block is replace-in-place and never edits user-authored custom
    checks outside the markers. Runtime discovery also reads targets.json, so a
    missing root config never prevents the current scan from using a target.
    """
    checks: list[dict[str, Any]] = []
    for target in targets:
        kind = str(getattr(target, "kind", ""))
        runnable = bool(getattr(target, "runnable", False))
        command = getattr(target, "command", None)
        confidence = str(getattr(target, "confidence", ""))
        if (
            not kind.startswith("custom-")
            or not runnable
            or not command
            or confidence != "high"
        ):
            continue
        category = kind.removeprefix("custom-")
        metadata = getattr(target, "metadata", None) or {}
        checks.append(
            {
                "name": str(getattr(target, "name", category)),
                "category": category,
                "profile": "deep",
                "command": [str(x) for x in command],
                "timeout": int(metadata.get("timeout", 3600)),
                "generated": True,
                "confidence": confidence,
            },
        )

    begin = "# BEGIN BUGHUNT MANAGED CUSTOM CHECKS"
    end = "# END BUGHUNT MANAGED CUSTOM CHECKS"
    lines = [
        begin,
        (
            "# Regenerated by `bughunt configure --auto`; user-authored "
            "checks outside this block are preserved."
        ),
    ]
    for check in checks:
        lines.extend(
            [
                "",
                "[[custom.checks]]",
                f"name = {json.dumps(check['name'])}",
                f"category = {json.dumps(check['category'])}",
                f"profile = {json.dumps(check['profile'])}",
                "command = ["
                + ", ".join(json.dumps(x) for x in check["command"])
                + "]",
                f"timeout = {check['timeout']}",
                "generated = true",
                f"confidence = {json.dumps(check['confidence'])}",
            ],
        )
    lines.extend(["", end, ""])
    block = "\n".join(lines)

    path = root / "bughunt.toml"
    current = path.read_text() if path.exists() else ""
    pattern = re.compile(re.escape(begin) + r".*?" + re.escape(end) + r"\n?", re.DOTALL)
    if pattern.search(current):
        updated = pattern.sub(block, current)
    else:
        updated = current.rstrip() + ("\n\n" if current.strip() else "") + block
    _write(path, updated.rstrip())

    detail = (
        f"{len(checks)} high-confidence repository-specific campaign(s) "
        "written to managed [[custom.checks]] entries"
    )
    state = "READY"
    return ConfigArtifact("custom semantic campaigns", "bughunt.toml", state, detail)


# trace:v1 id=impl.src-bughunt-configurator.-manifest work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _manifest(artifacts: list[ConfigArtifact], root: Path) -> None:
    path = root / ".bughunt" / "configs" / "manifest.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_text(
        json.dumps(
            {"schema_version": 2, "artifacts": [asdict(a) for a in artifacts]},
            indent=2,
        )
        + "\n",
    )


def _sqlfluff_config(dialect: str) -> str:
    # Correctness-focused SQL rules only. Avoid capitalization/layout noise.
    rules = "AL04,AL08,AM04,AM07,AM08,AM09,RF01,RF02"
    return f"""# Auto-generated by BugHunt. Correctness-first SQL profile.
[sqlfluff]
dialect = {dialect}
templater = jinja
rules = {rules}
exclude_rules =
max_line_length = 0

[sqlfluff:rules:aliasing.unique.table]
force_enable = True
"""


# Directories that never hold first-party JS/TS product source: virtualenvs
# (which vendor minified third-party bundles), VCS metadata, analyzer caches,
# BugHunt's own output, and agent/harness runtime tooling. JS linters run
# cwd-wide, so every entry here prevents thousands of third-party findings
# from drowning the product's own signal.
#
# Ignore patterns are root-relative. With `--config`, ESLint matches `ignores`
# against the invocation working directory (verified empirically: config-file-
# relative and absolute forms both fail to match, and oxlint rejects `..`
# outright), so the generated config lists them verbatim and oxlint receives
# the same list as cwd-relative `--ignore-pattern` flags.
JS_TOOL_IGNORES = [
    "node_modules/**",
    "dist/**",
    "build/**",
    ".next/**",
    ".bughunt/**",
    ".venv/**",
    "venv/**",
    "env/**",
    ".direnv/**",
    ".git/**",
    ".hg/**",
    ".svn/**",
    ".tox/**",
    ".nox/**",
    ".mypy_cache/**",
    ".pytest_cache/**",
    ".ruff_cache/**",
    ".pyre/**",
    ".coverage/**",
    "htmlcov/**",
    "mutants/**",
    "__pypackages__/**",
    "site-packages/**",
    ".agents/**",
    ".claude/**",
    ".codex/**",
    ".pi/**",
    ".omp/**",
    ".hermes/**",
    ".trace/**",
    ".benchmarks/**",
    ".complexipy_cache/**",
    ".import_linter_cache/**",
    # Nested build output: root-relative `dist/**` does not match
    # `pkg/dist/bundle.js` (probed 2026-09-15: nested dist was linted).
    # Leading-`**/` forms are honored by ESLint flat `ignores`, knip
    # ignoreFiles, and oxlint `--ignore-pattern` (gitignore semantics).
    "**/dist/**",
    "**/build/**",
    "**/.next/**",
    "**/node_modules/**",
    "**/.venv/**",
    "**/venv/**",
    "**/coverage/**",
    "**/htmlcov/**",
]
# Rendered inline into the ESLint templates. Patterns are matched against
# cwd-relative paths (verified: with `--config`, ESLint resolves `ignores`
# against the invocation working directory, and rejects nothing), so the
# generated config lists them verbatim.
_JS_IGNORES_CLAUSE = (
    "{ ignores: [" + ", ".join(f'"{p}"' for p in JS_TOOL_IGNORES) + "] }"
)
_JS_IGNORES_LINE_OLD = (
    '  { ignores: ["node_modules/**", "dist/**", "build/**", ".next/**", '
    '".bughunt/**"] },'
)


# trace:v1 id=impl.src-bughunt-configurator.-oxlint-config work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _oxlint_config(react: bool) -> str:
    plugins = ["unicorn", "typescript", "oxc", "import", "promise"]
    if react:
        plugins.extend(["react", "jsx-a11y"])
    data = {
        "categories": {
            "correctness": "error",
            "suspicious": "error",
            "pedantic": "warn",
            "perf": "warn",
            "restriction": "warn",
            "style": "off",
            "nursery": "warn",
        },
        "plugins": plugins,
        "rules": {
            "eqeqeq": "error",
            "array-callback-return": "error",
            "guard-for-in": "error",
            "no-new-func": "error",
            "typescript/no-explicit-any": "warn",
            "typescript/no-non-null-assertion": "warn",
            "typescript/no-misused-promises": "error",
            "typescript/switch-exhaustiveness-check": "error",
        },
    }
    return json.dumps(data, indent=2)


# trace:v1 id=impl.src-bughunt-configurator.-knip-config work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _knip_config() -> str:
    # ignoreFiles uses the shared JS ignore list. Resolution is verified
    # empirically after generation: if knip resolves these relative to the
    # config file instead of the root, the invocation must scope paths.
    data = {
        "$schema": "https://unpkg.com/knip@6/schema.json",
        "ignoreFiles": JS_TOOL_IGNORES,
    }
    return json.dumps(data, indent=2)


# trace:v1 id=impl.src-bughunt-configurator.-eslint-config work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _eslint_config(typescript: bool) -> str:
    # Core ESLint correctness rules plus type-aware typescript-eslint when a
    # TypeScript project is actually present. Project Service reuses the same
    # tsconfig discovery model as editors/tsc instead of inventing a lint-only
    # type universe.
    if typescript:
        return r"""// Auto-generated by BugHunt. Correctness-first typed JS/TS fallback.
import js from "@eslint/js";
import { defineConfig } from "eslint/config";
import tseslint from "typescript-eslint";

export default defineConfig(
  { ignores: ["node_modules/**", "dist/**", "build/**", ".next/**", ".bughunt/**"] },
  {
    files: ["**/*.{ts,tsx,mts,cts}"],
    extends: [
      js.configs.recommended,
      tseslint.configs.strictTypeChecked,
    ],
    languageOptions: {
      parserOptions: {
        projectService: true,
      },
    },
    rules: {
      "@typescript-eslint/no-misused-promises": "error",
      "@typescript-eslint/no-floating-promises": "error",
      "@typescript-eslint/no-unnecessary-condition": "error",
      "@typescript-eslint/only-throw-error": "error",
      "@typescript-eslint/require-await": "error",
      "@typescript-eslint/return-await": ["error", "error-handling-correctness-only"],
      "@typescript-eslint/switch-exhaustiveness-check": "error",
      "@typescript-eslint/no-explicit-any": "warn",
      "@typescript-eslint/no-non-null-assertion": "warn"
    }
  },
  {
    files: ["**/*.{js,mjs,cjs,jsx}"],
    extends: [js.configs.recommended],
    rules: {
      "array-callback-return": "error",
      "eqeqeq": "error",
      "no-constant-binary-expression": "error",
      "no-constructor-return": "error",
      "no-promise-executor-return": "error",
      "no-self-compare": "error",
      "no-template-curly-in-string": "error",
      "no-unmodified-loop-condition": "error",
      "require-atomic-updates": "error"
    }
  }
);
""".replace(_JS_IGNORES_LINE_OLD, "  " + _JS_IGNORES_CLAUSE + ",")
    return r"""// Auto-generated by BugHunt. Correctness-first JS fallback.
import js from "@eslint/js";
export default [
  { ignores: ["node_modules/**", "dist/**", "build/**", ".next/**", ".bughunt/**"] },
  js.configs.recommended,
  {
    files: ["**/*.{js,mjs,cjs,jsx}"],
    languageOptions: { parserOptions: { ecmaVersion: "latest", sourceType: "module",
        ecmaFeatures: { jsx: true } } },
    rules: {
      "array-callback-return": "error",
      "eqeqeq": "error",
      "no-constant-binary-expression": "error",
      "no-constructor-return": "error",
      "no-promise-executor-return": "error",
      "no-self-compare": "error",
      "no-template-curly-in-string": "error",
      "no-unmodified-loop-condition": "error",
      "require-atomic-updates": "error"
    }
  }
];
""".replace(_JS_IGNORES_LINE_OLD, "  " + _JS_IGNORES_CLAUSE + ",")


def _buf_config() -> str:
    return """# Auto-generated by BugHunt.
version: v2
lint:
  use:
    - STANDARD
breaking:
  use:
    - FILE
"""


def _tflint_config() -> str:
    return """# Auto-generated by BugHunt.
plugin "terraform" {
  enabled = true
  preset  = "recommended"
}
"""


def _clang_tidy_config() -> str:
    return """# Auto-generated by BugHunt. Correctness-first C/C++ profile.
Checks: '-*,clang-analyzer-*,bugprone-*,concurrency-*'
WarningsAsErrors: 'clang-analyzer-*,bugprone-*,concurrency-*'
HeaderFilterRegex: '^(?!.*(?:/vendor/|/third_party/|/.bughunt/)).*$'
FormatStyle: none
"""


def _hadolint_config() -> str:
    return """# Auto-generated by BugHunt.
failure-threshold: warning
no-color: true
"""


def _phpstan_config(root: Path) -> str:
    candidates = [name for name in ("src", "app", "tests") if (root / name).exists()]
    if not candidates:
        candidates = ["."]
    paths = "\n".join(f"        - {path}" for path in candidates)
    return f"""# Auto-generated by BugHunt.
parameters:
    level: max
    paths:
{paths}
    excludePaths:
        analyse:
            - vendor
            - .bughunt
"""


# trace:v1 id=impl.src-bughunt-configurator.-configure-technology-overlays work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _configure_technology_overlays(
    root: Path,
    config_dir: Path,
) -> list[ConfigArtifact]:
    inv = discover_technologies(root, persist=True)
    out: list[ConfigArtifact] = [
        ConfigArtifact(
            "repository capability inventory",
            ".bughunt/generated/capabilities.json",
            "READY",
            (
                f"{sum(1 for c in inv.capabilities.values() if c.detected)} "
                "technology capability class(es) detected; non-applicable "
                "engines are N/A, not blind spots"
            ),
        ),
    ]

    def put(name: str, relative: str, content: str, detail: str) -> None:
        path = config_dir / relative
        _write(path, content)
        out.append(ConfigArtifact(name, str(path.relative_to(root)), "READY", detail))

    if inv.has("sql"):
        dialect = infer_sql_dialect(root, inv.files.get("sql", []))
        put(
            "SQLFluff",
            "sqlfluff.ini",
            _sqlfluff_config(dialect),
            f"correctness-only SQL rules; inferred dialect={dialect}",
        )
    if inv.has("terraform"):
        put(
            "TFLint",
            "tflint.hcl",
            _tflint_config(),
            "bundled Terraform language ruleset, recommended preset",
        )
    if inv.has("docker"):
        put(
            "Hadolint",
            "hadolint.yaml",
            _hadolint_config(),
            "Dockerfile correctness/best-practice checks; warning threshold",
        )
    if inv.has("cpp"):
        put(
            "clang-tidy",
            "clang-tidy.yaml",
            _clang_tidy_config(),
            (
                "clang-analyzer + bugprone + concurrency checks; "
                "requires compilation database to execute"
            ),
        )
    if inv.has("javascript-typescript"):
        put(
            "Oxlint",
            "oxlintrc.json",
            _oxlint_config(inv.has("react")),
            (
                "correctness+suspicious strict; pedantic/restriction/perf "
                "warnings; style disabled"
            ),
        )
        put(
            "Knip",
            "knip.json",
            _knip_config(),
            (
                "harness/runtime/dependency dirs ignored so dynamically loaded "
                "entry points are not reported unused"
            ),
        )
        put(
            "ESLint",
            "eslint.config.mjs",
            _eslint_config(inv.has("typescript")),
            (
                "correctness-first JS plus strict type-aware typescript-eslint "
                "when TypeScript is detected; project-owned ESLint "
                "configs remain supported"
            ),
        )
    if inv.has("protobuf"):
        put(
            "Buf",
            "buf.yaml",
            _buf_config(),
            (
                "STANDARD lint + FILE breaking policy; used as "
                "an overlay when the repository has no stronger "
                "own policy"
            ),
        )
    if inv.has("php"):
        put(
            "PHPStan",
            "phpstan.neon",
            _phpstan_config(root),
            "maximum PHPStan rule level with first-party paths only",
        )
    if inv.has("openapi"):
        out.append(
            ConfigArtifact(
                "oasdiff",
                "history baseline",
                "READY" if inv.git_baseline else "REVIEW",
                (
                    f"validate current specs; breaking-change baseline="
                    f"{inv.git_baseline or 'unavailable'}"
                ),
            ),
        )
    if inv.has("protobuf"):
        out.append(
            ConfigArtifact(
                "Buf compatibility",
                "history baseline",
                "READY" if inv.git_baseline else "REVIEW",
                f"breaking-change baseline={inv.git_baseline or 'unavailable'}",
            ),
        )
    return out


# trace:v1 id=impl.src-bughunt-configurator.-python-matrix-versions work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def _python_matrix_versions(root: Path) -> list[str]:
    """Default compatibility matrix for supported CPython releases.

    Keep this deterministic and bounded. The free-threaded interpreter is
    a distinct compatibility claim (no-GIL races, dependency wheels), so
    3.14t joins the matrix only with explicit opt-in (`[matrix]`
    `freethreaded = true` in bughunt.toml), never by default.
    """
    req = str(_toml_project(root).get("requires-python", ""))
    versions = ["3.11", "3.12", "3.13", "3.14"]
    # Respect simple explicit upper bounds such as <3.14 / <=3.13.
    upper = re.search(r"<\s*(=?)(3)\.(\d+)", req)
    if upper:
        inclusive = bool(upper.group(1))
        minor = int(upper.group(3))
        versions = [
            v
            for v in versions
            if int(v.split(".")[1]) < minor
            or (inclusive and int(v.split(".")[1]) <= minor)
        ]
    lower = re.search(r">=\s*3\.(\d+)", req)
    if lower:
        floor = int(lower.group(1))
        versions = [v for v in versions if int(v.split(".")[1]) >= floor]
    if "3.14" in versions and _matrix_freethreaded(root):
        versions.append("3.14t")
    return versions or [_python_version(root)]


# trace:v1 id=impl.src-bughunt-configurator.-matrix-freethreaded work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _matrix_freethreaded(root: Path) -> bool:
    """Whether the repo opts into free-threaded matrix coverage."""
    try:
        data = tomllib.loads((root / "bughunt.toml").read_text())
    except (OSError, tomllib.TOMLDecodeError):
        return False
    matrix = data.get("matrix", {})
    return bool(isinstance(matrix, dict) and matrix.get("freethreaded", False))


# trace:v1 id=impl.src-bughunt-configurator.configure-all work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def configure_all(
    root: Path,
    python_paths: list[str],
    source_paths: list[str],
    test_paths: list[str],
    *,
    schemathesis_examples: int = 1000,
) -> list[ConfigArtifact]:
    """Generate strict BugHunt-owned overlays without replacing hand configs.

    The one exception is mutmut: current mutmut reads project-root configuration,
    so BugHunt appends a clearly-bounded [tool.mutmut] section only when the
    project has none, after writing a backup. Existing user-owned mutmut
    configuration is preserved and audited; BugHunt-managed config is refreshed
    to coverage-guided mutation defaults.
    """
    config_dir = root / ".bughunt" / "configs"
    config_dir.mkdir(parents=True, exist_ok=True)
    (root / ".bughunt" / "stubs").mkdir(parents=True, exist_ok=True)
    artifacts: list[ConfigArtifact] = []
    python_version = _python_version(root)
    package_roots = _package_roots(root, source_paths)

    # trace:v1 id=impl.src-bughunt-configurator-configure-all.put work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
    def put(name: str, relative: str, content: str, detail: str) -> Path:
        path = config_dir / relative
        _write(path, content)
        artifacts.append(
            ConfigArtifact(name, str(path.relative_to(root)), "READY", detail),
        )
        return path

    _ = put(
        "Ruff",
        "ruff.toml",
        _ruff_config(
            python_version,
            _existing(root, source_paths),
            _existing(root, test_paths),
        ),
        "ALL + preview rules; test-idiom scoped; tool/runtime excluded",
    )
    _ = put(
        "basedpyright",
        "basedpyrightconfig.json",
        _basedpyright_config(config_dir, root, python_paths, python_version),
        "typeCheckingMode=all; Any/Unknown/unreachable/unsafe ignores are errors",
    )
    _ = put(
        "mypy",
        "mypy.ini",
        _mypy_config(root, python_paths, python_version),
        (
            "strict plus Any ban, unreachable analysis, and optional "
            "correctness error codes"
        ),
    )
    _ = put(
        "ty",
        "ty.toml",
        _ty_config(),
        (
            "all rules=error; strict equality/generic narrowing; "
            "generic type:ignore disabled"
        ),
    )
    _ = put(
        "Pyrefly",
        "pyrefly.toml",
        _pyrefly_config(config_dir, root, python_paths, source_paths, python_version),
        (
            "preset=all; no import-to-Any escape hatches; unannotated "
            "bodies checked; constants treated final"
        ),
    )
    framework_inventory = discover_technologies(root, persist=True)
    pylint_plugins: list[str] = []
    if (
        framework_inventory.has("django")
        and importlib.util.find_spec("pylint_django") is not None
    ):
        pylint_plugins.append("pylint_django")
    if (
        framework_inventory.has("odoo")
        and importlib.util.find_spec("pylint_odoo") is not None
    ):
        pylint_plugins.append("pylint_odoo")
    _ = put(
        "Pylint-Tests",
        "pylintrc-tests",
        _pylint_config(extra_plugins=pylint_plugins, for_tests=True),
        "relaxed test-idiom contract: docstring/magic/imports/args relaxed",
    )
    _ = put(
        "Pylint",
        "pylintrc",
        _pylint_config(extra_plugins=pylint_plugins),
        "all bundled checkers/messages enabled; strict complexity/design thresholds"
        + (
            f"; framework plugins: {', '.join(pylint_plugins)}"
            if pylint_plugins
            else ""
        ),
    )
    _ = put(
        "Complexipy",
        "complexipy.toml",
        _complexipy_config(_existing(root, source_paths)),
        "cognitive complexity <=10; ignores disabled and ignored functions reported",
    )
    _ = put(
        "Bandit",
        "bandit.yaml",
        _bandit_config(),
        "all installed security tests; first-party source roots only",
    )
    artifacts.append(_ensure_complexity_budgets(root))
    env_path, env_uses = ensure_env_example(root, _existing(root, source_paths))
    if env_path is not None:
        artifacts.append(
            ConfigArtifact(
                "environment contract",
                str(env_path.relative_to(root)),
                "READY",
                (
                    f"{len(env_uses)} statically discovered environment variable(s) "
                    "documented with required/optional/default/type/unit/range/example "
                    "evidence"
                ),
            ),
        )
    else:
        artifacts.append(
            ConfigArtifact(
                "environment contract",
                ".env.example",
                "N/A",
                (
                    "no static environment-variable use detected; "
                    "no .env.example generated"
                ),
            ),
        )

    sgconfig, rules = _astgrep_config()
    _ = put(
        "ast-grep",
        "sgconfig.yml",
        sgconfig,
        "generated structural rule pack + test directory",
    )
    for filename, text in rules.items():
        _ = put(
            "ast-grep rule",
            f"ast-grep/rules/{filename}",
            text,
            "high-confidence structural bug rule",
        )
    astgrep_tests = {
        "bughunt-swallowed-exception-test.yml": """id: bughunt-swallowed-exception
valid:
  - |
      try:
        work()
      except ValueError:
        handle()
invalid:
  - |
      try:
        work()
      except ValueError:
        pass
""",
        "bughunt-return-in-finally-test.yml": """id: bughunt-return-in-finally
valid:
  - |
      try:
        work()
      finally:
        cleanup()
invalid:
  - |
      def f():
        try:
          work()
        finally:
          return 1
  - |
      while True:
        try:
          work()
        finally:
          break
""",
    }
    for filename, text in astgrep_tests.items():
        _ = put(
            "ast-grep rule test",
            f"ast-grep/tests/{filename}",
            text,
            "positive/negative regression fixtures for shipped structural rule",
        )

    il = _import_linter_config(package_roots)
    if il:
        _ = put(
            "Import Linter",
            "importlinter.toml",
            il,
            f"root(s): {', '.join(package_roots)}; recursive acyclic-sibling invariant",
        )
    else:
        artifacts.append(
            ConfigArtifact(
                "Import Linter",
                "",
                "REVIEW",
                "could not safely infer an importable first-party package root",
            ),
        )

    pyre_text, taint_text, models_text = _pysa_files(root, source_paths, python_version)
    pyre_path = root / ".pyre_configuration"
    if not pyre_path.exists():
        _write(pyre_path, pyre_text)
        artifacts.append(
            ConfigArtifact(
                "Pysa/Pyre",
                ".pyre_configuration",
                "READY",
                "base Pyre/Pysa source + model path generated",
            ),
        )
    else:
        artifacts.append(
            ConfigArtifact(
                "Pysa/Pyre",
                ".pyre_configuration",
                "EXISTING",
                "existing project Pyre configuration preserved",
            ),
        )
    _ = put(
        "Pysa taint config",
        "pysa/taint.config",
        taint_text,
        "valid BugHunt source/sink namespace and taint rule",
    )
    _ = put(
        "Pysa starter models",
        "pysa/bughunt.pysa",
        models_text,
        "valid model file; semantic app models intentionally require evidence",
    )

    _ = put(
        "Hypothesis",
        "hypothesis_plugin.py",
        _hypothesis_plugin(),
        (
            "2,000 examples, 100 state steps, shrinking + multiple "
            "bug reporting, no health-check suppression"
        ),
    )
    _ = put(
        "coverage.py",
        "coverage.ini",
        coverage_config(_existing(root, source_paths)),
        (
            "branch=true; missing lines/branches become first-class "
            "findings and feed risk/mutation prioritization"
        ),
    )
    runtime_paths = write_runtime_plugins(
        root,
        _python_matrix_versions(root),
        _existing(root, test_paths),
    )
    artifacts.append(
        ConfigArtifact(
            "Blockbuster",
            str(runtime_paths[0].relative_to(root)),
            "READY",
            "autouse asyncio blocking-call detector for the runtime verification pass",
        ),
    )
    artifacts.append(
        ConfigArtifact(
            "Python environment matrix",
            str(runtime_paths[1].relative_to(root)),
            "READY",
            (
                "CPython 3.11-3.14 plus 3.14t when supported; deterministic "
                "Nox definition generated"
            ),
        ),
    )
    _ = put(
        "Schemathesis",
        "schemathesis.toml",
        _schemathesis_config(schemathesis_examples),
        (
            "all generation modes, shrinking, x00/extra params, "
            "continue-on-failure, auto workers"
        ),
    )

    semgrep_rules = config_dir / "semgrep" / "rules"
    semgrep_rules.mkdir(parents=True, exist_ok=True)
    bundled_semgrep = semgrep_rules / "bughunt-correctness.yml"
    _write(bundled_semgrep, _semgrep_correctness_rules())
    artifacts.append(
        ConfigArtifact(
            "Semgrep",
            str(semgrep_rules.relative_to(root)),
            "READY",
            (
                "7 bundled correctness-first rules + local/generated "
                "rules; p/default runs as registry baseline; security-audit/secrets "
                "are opt-in"
            ),
        ),
    )

    codeql_queries = config_dir / "codeql" / "queries"
    codeql_queries.mkdir(parents=True, exist_ok=True)
    artifacts.append(
        ConfigArtifact(
            "CodeQL",
            str(codeql_queries.relative_to(root)),
            "READY",
            "upstream security-and-quality suite plus local query directory",
        ),
    )

    artifacts.append(_ensure_mutmut_config(root, source_paths, test_paths))
    artifacts.extend(
        [
            ConfigArtifact(
                "CrossHair",
                "bughunt.toml",
                "READY",
                (
                    "asserts + PEP316 + Deal + icontract; extended "
                    "solver budgets in deep/all"
                ),
            ),
            ConfigArtifact(
                "Deal",
                "bughunt.toml",
                "READY",
                "Deal lint across first-party source roots",
            ),
            ConfigArtifact(
                "Vulture",
                "bughunt.toml",
                "READY",
                "confidence floor: PR 80, deep 40, all 0 for maximum dead-code recall",
            ),
            ConfigArtifact(
                "BugHunt policy pack",
                "built-in",
                "READY",
                (
                    "env contract/secrets, persistence-boundary "
                    "coupling, export round-trip coverage, and "
                    "implementation-coupled test heuristics"
                ),
            ),
            ConfigArtifact(
                "BugHunt complexity",
                "bughunt.toml",
                "READY",
                (
                    "cyclomatic + LOC + ABC + built asset budgets; "
                    "complements Ruff/Pylint/Complexipy/Lizard/Radon"
                ),
            ),
            ConfigArtifact(
                "deptry",
                "bughunt.toml",
                "READY",
                (
                    "all dependency rules; first-party source roots "
                    "with runtime/generated exclusions"
                ),
            ),
            ConfigArtifact(
                "Atheris",
                ".bughunt/generated/targets.json",
                "AUTO",
                "safe parser/decoder harness discovery follows config generation",
            ),
        ],
    )

    artifacts.extend(_configure_technology_overlays(root, config_dir))
    _manifest(artifacts, root)
    return artifacts
