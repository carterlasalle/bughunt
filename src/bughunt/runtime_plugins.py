from __future__ import annotations

from pathlib import Path


def blockbuster_plugin() -> str:
    return '''from __future__ import annotations\n\nimport pytest\nfrom blockbuster import blockbuster_ctx\n\n@pytest.fixture(autouse=True)\ndef _bughunt_blockbuster():\n    with blockbuster_ctx():\n        yield\n'''


def noxfile(python_versions: list[str], test_paths: list[str]) -> str:
    versions = repr(python_versions)
    paths = repr(test_paths or ["tests"])
    return f'''from __future__ import annotations

import os
import secrets
import nox

PYTHONS = {versions}
TEST_PATHS = {paths}

@nox.session(python=PYTHONS, venv_backend="uv|virtualenv")
def tests(session):
    session.install(".", "pytest", "hypothesis", "pytest-randomly", "pytest-timeout")
    seed = str(secrets.randbelow(2**31 - 2) + 1)
    env = {{"PYTHONHASHSEED": seed, "PYTHONASYNCIODEBUG": "1"}}
    cmd = ["pytest", "-q", "--timeout=300", f"--randomly-seed={{seed}}", *TEST_PATHS]
    # Free-threaded interpreters deserve an extra concurrent pass.  Do not make
    # ordinary interpreter sessions pay this cost.
    if str(session.python).endswith("t"):
        session.install("pytest-run-parallel")
        cmd[1:1] = ["--parallel-threads=auto", "--iterations=2"]
    session.run(*cmd, env=env)
'''


def write_runtime_plugins(root: Path, python_versions: list[str], test_paths: list[str]) -> list[Path]:
    cfg = root / ".bughunt" / "configs"
    gen = root / ".bughunt" / "generated"
    cfg.mkdir(parents=True, exist_ok=True)
    gen.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    blocker = cfg / "blockbuster_plugin.py"
    blocker.write_text(blockbuster_plugin())
    paths.append(blocker)
    nox = gen / "noxfile.py"
    nox.write_text(noxfile(python_versions, test_paths))
    paths.append(nox)
    return paths
