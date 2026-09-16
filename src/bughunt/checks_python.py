# Copyright (c) 2026 Carter LaSalle
"""Python compile, type, and lint check builders."""

from __future__ import annotations

import sys

from .checkctx import CheckBuildCx
from .probes import _optional_cmd
from .probes import _pylint_disables, generated_config
from .technology import target_executable
from .parsers import parse_basedpyright, parse_pylint, parse_pyrefly, parse_ruff
from .models import Result, Status


# trace:v1 id=impl.src-bughunt-checks-python.-build-python-checks work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _build_python_checks(cx: CheckBuildCx) -> None:
    cx.add(
        "compile",
        "syntax",
        [sys.executable, "-m", "compileall", "-q", *cx.py],
        findings_exit_codes={1},
    )
    ruff_cfg = generated_config(cx.root, "ruff.toml")
    ruff_cmd = _optional_cmd(
        target_executable(cx.root, "ruff"), ["check", *cx.py, "--output-format=json"]
    )
    if ruff_cmd and ruff_cfg:
        ruff_cmd += ["--config", str(ruff_cfg)]
    cx.add("ruff", "lint", ruff_cmd, parse_ruff, reason="ruff not installed")
    bp_cfg = generated_config(cx.root, "basedpyrightconfig.json")
    bp_cmd = _optional_cmd(
        target_executable(cx.root, "basedpyright"),
        ["--outputjson", "--pythonpath", sys.executable],
    )
    if bp_cmd and bp_cfg:
        bp_cmd += ["--project", str(bp_cfg)]
    cx.add(
        "basedpyright",
        "types",
        bp_cmd,
        parse_basedpyright,
        reason="basedpyright not installed",
        findings_exit_codes={1},
    )
    mypy_cfg = generated_config(cx.root, "mypy.ini")
    mypy_cmd = _optional_cmd(
        target_executable(cx.root, "mypy"),
        [*cx.py, "--show-error-codes", "--no-pretty", "--no-color-output"],
    )
    if mypy_cmd and mypy_cfg:
        mypy_cmd += ["--config-file", str(mypy_cfg)]
    cx.add("mypy", "types", mypy_cmd, reason="mypy not installed")
    ty_cfg = generated_config(cx.root, "ty.toml")
    ty_cmd = _optional_cmd(target_executable(cx.root, "ty"), ["check", *cx.py])
    if ty_cmd and ty_cfg:
        ty_cmd += ["--config-file", str(ty_cfg)]
    cx.add("ty", "types", ty_cmd, reason="ty not installed", findings_exit_codes={1})
    pyrefly_cfg = generated_config(cx.root, "pyrefly.toml")
    pyrefly_cmd = _optional_cmd(
        target_executable(cx.root, "pyrefly"),
        ["check", "--output-format=json"],
    )
    if pyrefly_cmd and pyrefly_cfg:
        pyrefly_cmd += ["--config", str(pyrefly_cfg)]
    cx.add(
        "pyrefly",
        "types",
        pyrefly_cmd,
        parse_pyrefly,
        reason="pyrefly not installed",
        findings_exit_codes={1},
    )
    pylint_cfg = generated_config(cx.root, "pylintrc")
    pylint_cmd = _optional_cmd(
        target_executable(cx.root, "pylint"), [*cx.py, "--output-format=json2"]
    )
    if pylint_cmd and pylint_cfg:
        pylint_cmd += ["--rcfile", str(pylint_cfg)]
        validated = _pylint_disables(pylint_cmd[0], pylint_cfg, cx.root)
        if validated is not None:
            pylint_cmd += ["--disable=" + ",".join(validated)]
    cx.add(
        "pylint",
        "lint",
        pylint_cmd,
        parse_pylint,
        reason="pylint not installed",
        findings_exit_codes={code for code in range(1, 32)},
    )
    _want_pylint_tests = (
        "pylint-tests" in cx.wanted and "pylint-tests" not in cx.excluded
    )
    if _want_pylint_tests and not cx.tests:
        cx.skipped.append(
            Result(
                "pylint-tests",
                "lint",
                Status.SKIPPED,
                note="no test paths in scope",
            ),
        )
    else:
        pylint_tests_cfg = generated_config(cx.root, "pylintrc-tests")
        pylint_tests_cmd = _optional_cmd(
            target_executable(cx.root, "pylint"),
            [*cx.tests, "--output-format=json2"],
        )
        if pylint_tests_cmd and pylint_tests_cfg:
            pylint_tests_cmd += ["--rcfile", str(pylint_tests_cfg)]
            validated_tests = _pylint_disables(
                pylint_tests_cmd[0], pylint_tests_cfg, cx.root
            )
            if validated_tests is not None:
                pylint_tests_cmd += ["--disable=" + ",".join(validated_tests)]
        cx.add(
            "pylint-tests",
            "lint",
            pylint_tests_cmd,
            lambda o, e, c: parse_pylint(o, e, c, tool="pylint-tests"),
            reason="pylint not installed",
            findings_exit_codes={code for code in range(1, 32)},
        )
