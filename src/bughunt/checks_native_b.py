# Copyright (c) 2026 Carter LaSalle
"""Native toolchain check builders, part two."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from functools import partial
from .checkctx import CheckBuildCx
from .probes import (
    publishable_package_json,
    generated_config,
    local_schema_pairs,
    pact_json_files,
)
from .technology import (
    ENGINE_CATEGORY,
    llvm_executable,
    project_executable,
    target_has_module,
)
from .parsers import (
    ESLINT_EMPTY_SCOPE,
    OXLINT_EMPTY_SCOPE,
    parse_bughunt_helper,
    parse_clippy,
    parse_cppcheck,
    parse_eslint,
    parse_oxlint,
    parse_phpstan,
    text_findings,
)
from .models import Check, Result, Status
from .configurator import JS_TOOL_IGNORES


# trace:v1 id=impl.src-bughunt-checks-native-b.-build-native-b-checks work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def build_native_b_checks(cx: CheckBuildCx) -> None:
    cargo = project_executable(cx.root, "cargo")
    clippy_cmd = (
        [
            cargo,
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--message-format=json",
            "--",
            "-D",
            "clippy::correctness",
            "-D",
            "clippy::suspicious",
            "-W",
            "clippy::complexity",
            "-W",
            "clippy::perf",
        ]
        if cargo
        else None
    )
    cx.add_technology(
        "clippy",
        clippy_cmd,
        parse_clippy,
        reason="Rust detected but cargo/clippy is not installed",
        findings_exit_codes={1, 101},
    )
    compile_db = cx.technology.files.get("cpp-compile-db", [])
    cpp_files = cx.technology.files.get("cpp", [])
    cppcheck = project_executable(cx.root, "cppcheck")
    cppcheck_cmd: list[str] | None = None
    if cppcheck:
        cppcheck_cmd = [
            cppcheck,
            "--xml",
            "--xml-version=2",
            "--error-exitcode=1",
            "--enable=warning,performance,portability",
            "--inconclusive",
        ]
        if compile_db:
            cppcheck_cmd += [f"--project={compile_db[0]}"]
        else:
            cppcheck_cmd += cpp_files
    cx.add_technology(
        "cppcheck",
        cppcheck_cmd,
        parse_cppcheck,
        reason="C/C++ detected but Cppcheck is not installed",
        findings_exit_codes={1},
    )
    run_clang_tidy = llvm_executable(cx.root, "run-clang-tidy") or llvm_executable(
        cx.root,
        "run-clang-tidy.py",
    )
    clang_cmd = None
    if run_clang_tidy and compile_db:
        clang_cmd = [
            run_clang_tidy,
            f"-p={Path(compile_db[0]).parent}",
            "-checks=-*,clang-analyzer-*,bugprone-*,concurrency-*",
            "-warnings-as-errors=*",
        ]
    cx.add_technology(
        "clang-tidy",
        clang_cmd,
        reason=(
            "C/C++ compile_commands.json detected but run-clang-tidy is not installed"
            if compile_db
            else "clang-tidy requires compile_commands.json"
        ),
        findings_exit_codes={1},
    )
    infer = project_executable(cx.root, "infer")
    infer_cmd = (
        [
            infer,
            "run",
            "--compilation-database",
            compile_db[0],
            "--fail-on-issue",
            "--results-dir",
            str(cx.root / ".bughunt" / "cache" / "infer"),
        ]
        if infer and compile_db
        else None
    )
    cx.add_technology(
        "infer",
        infer_cmd,
        reason="C/C++ compilation database detected but Infer is not installed",
        findings_exit_codes={2},
    )
    phpstan = project_executable(cx.root, "phpstan")
    php_cfg = generated_config(cx.root, "phpstan.neon")
    php_cmd = (
        [phpstan, "analyse", "--no-progress", "--error-format=json"]
        if phpstan
        else None
    )
    if php_cmd and php_cfg:
        php_cmd += ["--configuration", str(php_cfg)]
    cx.add_technology(
        "phpstan",
        php_cmd,
        parse_phpstan,
        reason="PHP detected but PHPStan is not installed",
        findings_exit_codes={1},
    )
    oxlint = project_executable(cx.root, "oxlint")
    oxlint_cfg = generated_config(cx.root, "oxlintrc.json")
    oxlint_cmd = [oxlint, "--format=json", "--deny-warnings"] if oxlint else None
    if oxlint_cmd:
        # oxlint config-file ignorePatterns cannot address files outside the
        # generated config's own directory (`..` is rejected), so root-relative
        # ignores travel as cwd-relative CLI flags instead. Bare directory
        # names: the `/**` form misbehaves on tracked dot-directories.
        oxlint_cmd += [
            f"--ignore-pattern={p.removesuffix('/**')}" for p in JS_TOOL_IGNORES
        ]
    if oxlint_cmd and oxlint_cfg:
        oxlint_cmd += ["--config", str(oxlint_cfg)]
    cx.add_technology(
        "oxlint",
        oxlint_cmd,
        parse_oxlint,
        reason="JavaScript/TypeScript detected but Oxlint is not installed",
        findings_exit_codes={1},
        empty_scope_markers=(OXLINT_EMPTY_SCOPE,),
    )
    eslint = project_executable(cx.root, "eslint")
    eslint_cfg = generated_config(cx.root, "eslint.config.mjs")
    existing_eslint = next(
        (
            p
            for p in (
                "eslint.config.js",
                "eslint.config.mjs",
                "eslint.config.cjs",
                ".eslintrc",
                ".eslintrc.json",
                ".eslintrc.js",
            )
            if (cx.root / p).exists()
        ),
        None,
    )
    chosen_eslint = eslint_cfg or (
        (cx.root / existing_eslint) if existing_eslint else None
    )
    eslint_cmd = [eslint, ".", "--format", "json"] if eslint and chosen_eslint else None
    if eslint_cmd and eslint_cfg:
        eslint_cmd += ["--config", str(eslint_cfg)]
    cx.add_technology(
        "eslint",
        eslint_cmd,
        parse_eslint,
        reason=(
            "JavaScript/TypeScript detected but ESLint is not installed"
            if not eslint
            else "ESLint detected but no safe config is available"
        ),
        findings_exit_codes={1},
        empty_scope_markers=(ESLINT_EMPTY_SCOPE,),
    )
    react_doctor = project_executable(cx.root, "react-doctor")
    react_cmd = (
        [react_doctor, ".", "--json", "--no-supply-chain"] if react_doctor else None
    )
    cx.add_technology(
        "react-doctor",
        react_cmd,
        lambda o, e, c: parse_eslint(o, e, c, tool="react-doctor"),
        reason="React detected but React Doctor is not installed",
        findings_exit_codes={1},
    )
    tsc = project_executable(cx.root, "tsc")
    tsconfig = cx.root / "tsconfig.json"
    tsc_cmd = (
        [tsc, "--noEmit", "--pretty", "false"] if tsc and tsconfig.exists() else None
    )
    cx.add_technology(
        "tsc",
        tsc_cmd,
        reason=(
            "TypeScript detected but tsc is not installed"
            if not tsc
            else "TypeScript detected but no root tsconfig.json project exists"
        ),
        findings_exit_codes={1, 2},
    )
    knip = project_executable(cx.root, "knip")
    knip_cfg = generated_config(cx.root, "knip.json")
    knip_cmd = [knip, "--strict"] if knip else None
    if knip_cmd and knip_cfg:
        knip_cmd += ["--config", str(knip_cfg)]
    cx.add_technology(
        "knip",
        knip_cmd,
        reason="JavaScript/TypeScript detected but Knip is not installed",
        findings_exit_codes={1},
    )
    madge = project_executable(cx.root, "madge")
    cx.add_technology(
        "madge",
        [madge, "--circular", "."] if madge else None,
        reason="JavaScript/TypeScript detected but Madge is not installed",
        findings_exit_codes={1},
    )
    publint = project_executable(cx.root, "publint")
    package_json = publishable_package_json(cx.root)
    if publint and package_json:
        publint_cmd: list[str] | None = [publint, str(package_json)]
        publint_reason = ""
    elif publint:
        publint_cmd = None
        publint_reason = (
            "publint is installed but package.json is missing name/version; "
            "add both fields to make the package publishable"
        )
    else:
        publint_cmd = None
        publint_reason = "JavaScript package detected but publint is not installed"
    cx.add_technology(
        "publint",
        publint_cmd,
        reason=publint_reason,
        findings_exit_codes={1},
    )
    taplo = project_executable(cx.root, "taplo")
    toml_files = cx.technology.files.get("toml", [])
    cx.add_technology(
        "taplo",
        [taplo, "lint", *toml_files] if taplo and toml_files else None,
        reason="TOML detected but Taplo is not installed",
        findings_exit_codes={1},
    )
    yamllint = project_executable(cx.root, "yamllint")
    yaml_files = cx.technology.files.get("yaml", [])
    cx.add_technology(
        "yamllint",
        [
            yamllint,
            "-d",
            (
                "{extends: default, rules: {line-length: disable, truthy: disable, "
                "document-start: disable}}"
            ),
            *yaml_files,
        ]
        if yamllint and yaml_files
        else None,
        reason="YAML detected but yamllint is not installed",
        findings_exit_codes={1},
    )
    if "check-jsonschema" in cx.wanted:
        if not cx.technology.has("schema-ref"):
            cx.add_technology("check-jsonschema", None)
        else:
            checker = project_executable(cx.root, "check-jsonschema")
            pairs = local_schema_pairs(
                cx.root, cx.technology.files.get("schema-ref", [])
            )
            if checker and pairs:
                for instance, schema in pairs:
                    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", instance)
                    cx.checks.append(
                        Check(
                            f"check-jsonschema:{safe}",
                            ENGINE_CATEGORY["check-jsonschema"],
                            [
                                checker,
                                "--schemafile",
                                schema,
                                "--output-format",
                                "JSON",
                                instance,
                            ],
                            partial(text_findings, f"check-jsonschema:{safe}"),
                            cx.timeout,
                            cx.root,
                            findings_exit_codes={1},
                        ),
                    )
            elif not checker:
                cx.add_technology(
                    "check-jsonschema",
                    None,
                    reason=(
                        "local schema reference detected but check-jsonschema "
                        "is not installed"
                    ),
                )
            else:
                cx.skipped.append(
                    Result(
                        "check-jsonschema",
                        ENGINE_CATEGORY["check-jsonschema"],
                        Status.SKIPPED,
                        note=(
                            "schema references exist, but none "
                            "resolve to a repository-local schema; "
                            "BugHunt refuses to fetch arbitrary "
                            "remote schemas"
                        ),
                    ),
                )
    alembic = project_executable(cx.root, "alembic")
    alembic_configured = (cx.root / "alembic.ini").exists() or (
        cx.root / "alembic" / "env.py"
    ).exists()
    cx.add_technology(
        "alembic-check",
        [alembic, "check"] if alembic and alembic_configured else None,
        reason="Alembic project detected but alembic is not installed"
        if alembic_configured
        else "Alembic dependency detected but no runnable migration "
        "config (alembic.ini or alembic/env.py); refusing to fail a "
        "check that cannot execute",
        findings_exit_codes={1},
    )
    manage = cx.root / "manage.py"
    cx.add_technology(
        "django-migrations",
        [sys.executable, str(manage), "makemigrations", "--check", "--dry-run"]
        if manage.exists()
        else None,
        reason="Django detected but manage.py is unavailable",
        findings_exit_codes={1},
    )
    if "pact-contracts" in cx.wanted:
        if not cx.technology.has("pact"):
            cx.add_technology("pact-contracts", None)
        else:
            pacts = pact_json_files(cx.root, cx.technology.files.get("pact", []))
            asgi = [
                t
                for t in cx.generated_targets
                if t.kind == "schemathesis"
                and (t.metadata or {}).get("transport") == "asgi"
            ]
            pact_ready = target_has_module(cx.target_py, "pact") and target_has_module(
                cx.target_py,
                "uvicorn",
            )
            if len(asgi) == 1 and pacts and pact_ready:
                app = asgi[0].name
                cx.add_technology(
                    "pact-contracts",
                    [
                        sys.executable,
                        "-m",
                        "bughunt.pact_runner",
                        str(cx.root),
                        app,
                        *pacts,
                    ],
                    lambda o, e, c: parse_bughunt_helper("pact-contracts", o, e, c),
                    reason="Pact contract/provider target unavailable",
                    findings_exit_codes={1},
                    check_timeout=cx.cfg.timeout(cx.profile),
                )
            else:
                reasons = []
                if not pacts:
                    reasons.append("no concrete local Pact JSON files")
                if len(asgi) != 1:
                    reasons.append(
                        f"need exactly one high-confidence local ASGI provider target "
                        f"(found {len(asgi)})",
                    )
                if not pact_ready:
                    reasons.append("pact-python/uvicorn not installed")
                cx.skipped.append(
                    Result(
                        "pact-contracts",
                        ENGINE_CATEGORY["pact-contracts"],
                        Status.SKIPPED,
                        note=(
                            "Pact capability detected but auto-verification "
                            "is guarded: "
                        )
                        + "; ".join(reasons),
                    ),
                )
