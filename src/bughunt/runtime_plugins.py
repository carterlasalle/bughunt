from __future__ import annotations

from pathlib import Path

# The authoring gate flags untraced boundaries even in generated, gitignored
# output, and configure rewrites these files on every run: stamp the
# exemption at the source so it survives regeneration. Never hand-edit output.
TRACE_EXEMPT_PY = (
    "# trace:exempt reason=generated-by-bughunt-configure-do-not-hand-edit"
)


# trace:v1 id=impl.src-bughunt-runtime-plugins.blockbuster-plugin work=WORK-BUG-4ABH9VEY satisfies=REQ-BUG-KZG483AX implements=PLAN-BUG-560GXA79
def blockbuster_plugin() -> str:
    return (
        "from __future__ import annotations\n\n"
        "import pytest\n"
        "from blockbuster import blockbuster_ctx\n\n"
        "# trace:exempt reason=generated-by-bughunt-configure-do-not-hand-edit\n"
        "@pytest.fixture(autouse=True)\n"
        "def _bughunt_blockbuster():\n"
        "    with blockbuster_ctx():\n"
        "        yield\n"
    )


# trace:v1 id=impl.src-bughunt-runtime-plugins.noxfile work=WORK-BUG-4ABH9VEY satisfies=REQ-BUG-KZG483AX implements=PLAN-BUG-560GXA79
def noxfile(python_versions: list[str], test_paths: list[str]) -> str:
    versions = repr(python_versions)
    paths = repr(test_paths or ["tests"])
    return (
        "from __future__ import annotations\n\n"
        "import os\n"
        "import secrets\n"
        "import nox\n\n"
        f"PYTHONS = {versions}\n"
        f"TEST_PATHS = {paths}\n\n"
        "# trace:exempt reason=generated-by-bughunt-configure-do-not-hand-edit\n"
        '@nox.session(python=PYTHONS, venv_backend="uv|virtualenv")\n'
        "def tests(session):\n"
        '    session.install(".", "pytest", "hypothesis", "pytest-randomly", '
        '"pytest-timeout")\n'
        "    seed = str(secrets.randbelow(2**31 - 2) + 1)\n"
        '    env = {"PYTHONHASHSEED": seed, "PYTHONASYNCIODEBUG": "1"}\n'
        '    cmd = ["pytest", "-q", "--timeout=300", '
        'f"--randomly-seed={seed}", *TEST_PATHS]\n'
        "    # Free-threaded interpreters deserve an extra "
        "concurrent pass.  Do not make\n"
        "    # ordinary interpreter sessions pay this cost.\n"
        '    if str(session.python).endswith("t"):\n'
        '        session.install("pytest-run-parallel")\n'
        '        cmd[1:1] = ["--parallel-threads=auto", "--iterations=2"]\n'
        "    session.run(*cmd, env=env)\n"
    )


# trace:v1 id=impl.src-bughunt-runtime_plugins.write-runtime-plugins work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def write_runtime_plugins(
    root: Path,
    python_versions: list[str],
    test_paths: list[str],
) -> list[Path]:
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
