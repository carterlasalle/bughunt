# Copyright (c) 2026 Carter LaSalle
"""Target-environment probes: resolve executables, modules, and repo paths."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import tomllib
from collections.abc import Iterable, Sequence
from pathlib import Path

from .technology import target_executable, target_has_module, target_python


# trace:v1 id=impl.src-bughunt-probes.executable work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def executable(*names: str) -> str | None:
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    return None


# trace:v1 id=impl.src-bughunt-probes.python_module_available work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def python_module_available(name: str) -> bool:
    """Check import availability without importing/triggering module side effects."""
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, AttributeError, ValueError):
        return False


# trace:v1 id=impl.src-bughunt-cli.atheris-available work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def atheris_available(root: Path) -> bool:
    # The pure-Python shim imports without the instrumenting native
    # extension; harnesses then fail per-target with ModuleNotFoundError.
    # Ready means the native module resolves in the TARGET environment
    # (or a built runtime tree with the compiled extension exists).
    if target_has_module(target_python(root), "atheris.native"):
        return True
    runtime = root / ".bughunt" / "runtime" / "atheris"
    # A bare installed tree without the compiled extension is the exact
    # failure in the field (per-target ModuleNotFoundError): presence of
    # the .so anywhere under the runtime tree is the readiness signal.
    return bool(runtime.exists() and any(runtime.rglob("atheris*.so")))


# trace:v1 id=impl.src-bughunt-cli.ast-grep-executable work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def ast_grep_executable(root: Path | None = None) -> str | None:
    """Find ast-grep without mistaking util-linux `sg` for ast-grep."""
    candidates = [target_executable(root, "ast-grep")] if root is not None else []
    direct = next((c for c in candidates if c), None) or shutil.which("ast-grep")
    if direct:
        return direct
    sg = shutil.which("sg")
    if not sg:
        return None
    try:
        probe = subprocess.run(  # noqa: S603 - audited: argv list, no shell
            [sg, "--version"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    banner = (probe.stdout + "\n" + probe.stderr).lower()
    return sg if "ast-grep" in banner else None


# trace:v1 id=impl.src-bughunt-cli.supports-flag work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _supports_flag(executable_path: str, flag: str, root: Path) -> bool:
    """Probe `--help` once so version-drifted CLIs never get unknown flags."""
    try:
        probe = subprocess.run(  # noqa: S603 - audited: argv list, no shell
            [executable_path, "--help"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return flag in (probe.stdout + "\n" + probe.stderr)


# trace:v1 id=impl.src-bughunt-cli.pylint-disables work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _pylint_disables(pylint_bin: str, cfg_file: Path, root: Path) -> list[str] | None:
    """Disables from the rcfile that the installed pylint accepts.

    Generated strict configs name messages the bundled pylint knows;
    `uv add` may resolve an older pylint that rejects them, which would
    otherwise poison every file with a config error. Returns None when
    the rcfile or the message list is unreadable (caller keeps rcfile).
    """
    try:
        text = cfg_file.read_text(errors="replace")
    except OSError:
        return None
    match = re.search(r"(?m)^disable\s*=\s*(.+)$", text)
    if not match:
        return None
    wanted = [part.strip() for part in match.group(1).split(",") if part.strip()]
    try:
        probe = subprocess.run(  # noqa: S603 - audited: argv list, no shell
            [pylint_bin, "--list-msgs"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    valid = set(re.findall(r"^:([a-z0-9\-]+) \(", probe.stdout, re.MULTILINE))
    valid |= set(re.findall(r"\(([A-Z]\d{4})\)", probe.stdout))
    kept = [name for name in wanted if name in valid]
    return kept if kept else None


# trace:v1 id=impl.src-bughunt-probes.existing_paths work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def existing_paths(root: Path, values: Iterable[str]) -> list[str]:
    out = [value for value in values if (root / value).exists()]
    return out or ["."]


# trace:v1 id=impl.src-bughunt-probes.generated_config work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def generated_config(root: Path, name: str) -> Path | None:
    path = root / ".bughunt" / "configs" / name
    return path if path.exists() else None


# trace:v1 id=impl.src-bughunt-probes.analysis_scope work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def analysis_scope(root: Path, values: Iterable[str]) -> list[str]:
    """Return first-party paths only; never fall back into .bughunt/runtime."""
    paths = existing_paths(root, values)
    if paths == ["."]:
        # `.` is still safe because every broad scanner gets explicit excludes,
        # but prefer real Python files/dirs when inference can find them.
        candidates = [x for x in ("src", "lib", "app", "tests") if (root / x).exists()]
        return candidates or ["."]
    return paths


# trace:v1 id=impl.src-bughunt-probes.import_linter_configured work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def import_linter_configured(root: Path) -> bool:
    """Return True only when Import Linter has an actual project config.

    Import Linter searches .importlinter, setup.cfg, and pyproject.toml, but an
    installed CLI with no root package/contracts is a configuration gap, not a
    code finding.
    """
    ini = root / ".importlinter"
    if ini.exists() and "[importlinter" in ini.read_text(errors="ignore"):
        return True
    setup_cfg = root / "setup.cfg"
    if setup_cfg.exists() and "[importlinter" in setup_cfg.read_text(errors="ignore"):
        return True
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        try:
            data = tomllib.loads(pyproject.read_text())
        except (OSError, tomllib.TOMLDecodeError):
            return False
        tool = data.get("tool", {})
        return isinstance(tool, dict) and isinstance(tool.get("importlinter"), dict)
    return False


# trace:v1 id=impl.src-bughunt-cli.python-package-names work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def python_package_names(root: Path, source_paths: Sequence[str]) -> list[str]:
    """Infer importable first-party top-level packages without importing them."""
    names: list[str] = []
    for rel in source_paths:
        base = root / rel
        if base.is_file() and base.suffix == ".py" and base.stem != "__init__":
            names.append(base.stem)
            continue
        if not base.is_dir():
            continue
        if (base / "__init__.py").exists():
            names.append(base.name)
        else:
            names.extend(
                child.name
                for child in sorted(base.iterdir())
                if child.is_dir() and (child / "__init__.py").exists()
            )
    return list(dict.fromkeys(x for x in names if x.isidentifier()))


# trace:v1 id=impl.src-bughunt-cli.-publishable-package-json work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _publishable_package_json(root: Path) -> Path | None:
    """A package.json publint can actually pack: name and version declared."""
    path = root / "package.json"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or not data.get("name") or not data.get("version"):
        return None
    return path


# trace:v1 id=impl.src-bughunt-cli.local-schema-pairs work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def local_schema_pairs(root: Path, files: Sequence[str]) -> list[tuple[str, str]]:
    """Resolve explicit *local* $schema references without network access."""
    pairs: list[tuple[str, str]] = []
    root_resolved = root.resolve(strict=False)
    for rel in files:
        path = root / rel
        try:
            text = path.read_text(errors="replace")
        except OSError:
            # One bad file never fails a scan; skipped
            continue
        schema_ref: str | None = None
        if path.suffix.lower() == ".json":
            try:
                payload = json.loads(text)
                raw = payload.get("$schema") if isinstance(payload, dict) else None
                schema_ref = raw if isinstance(raw, str) else None
            except json.JSONDecodeError:
                # Malformed payload carries no data; skipped
                pass
        if schema_ref is None:
            match = re.search(r"(?m)^\s*\$schema\s*:\s*[\"']?([^\"'\s#]+)", text)
            if match:
                schema_ref = match.group(1)
        if not schema_ref or re.match(
            r"^[a-z][a-z0-9+.-]*://",
            schema_ref,
            re.IGNORECASE,
        ):
            continue
        schema = (path.parent / schema_ref).resolve(strict=False)
        try:
            _ = schema.relative_to(root_resolved)
        except ValueError:
            # Unparseable value keeps its default
            continue
        if schema.is_file():
            pairs.append((rel, schema.relative_to(root_resolved).as_posix()))
    return pairs


# trace:v1 id=impl.src-bughunt-cli.pact-json-files work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def pact_json_files(root: Path, files: Sequence[str]) -> list[str]:
    out: list[str] = []
    for rel in files:
        path = root / rel
        if path.suffix.lower() != ".json" or not path.is_file():
            continue
        try:
            payload = json.loads(path.read_text(errors="replace"))
        except (OSError, json.JSONDecodeError):
            # Unreadable or malformed input carries no data
            continue
        if not isinstance(payload, dict):
            continue
        if (
            isinstance(payload.get("consumer"), dict)
            and isinstance(payload.get("provider"), dict)
            and isinstance(payload.get("interactions"), list)
        ):
            out.append(rel)
    return out


# trace:v1 id=impl.src-bughunt-probes.pysa_executable work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def pysa_executable(root: Path) -> str | None:
    """Prefer BugHunt's isolated Pysa runtime over the project's Pyre CLI."""
    private = root / ".bughunt" / "runtime" / "pysa-venv" / "bin" / "pyre"
    if private.exists() and os.access(private, os.X_OK):
        return str(private)
    return executable("pyre")


# trace:exempt reason=internal-detail
def _optional_cmd(exe: str | None, args: Sequence[str]) -> list[str] | None:
    """Build a tool command when the executable resolved; None (SKIP) otherwise."""
    return [exe, *args] if exe else None
