# Copyright (c) 2026 Carter LaSalle
"""Native toolchain check builders, part one."""

from __future__ import annotations

import re
from functools import partial
from .checkctx import CheckBuildCx
from .probes import generated_config
from .technology import ENGINE_CATEGORY, git_path_exists, project_executable
from .parsers import (
    parse_actionlint,
    parse_buf_json_lines,
    parse_golangci,
    parse_hadolint,
    parse_json_list,
    parse_shellcheck,
    parse_sqlfluff,
    parse_squawk,
    parse_tflint,
    text_findings,
)
from .models import Check


# trace:v1 id=impl.src-bughunt-checks-native-a.-build-native-a-checks work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def build_native_a_checks(cx: CheckBuildCx) -> None:
    actionlint = project_executable(cx.root, "actionlint")
    action_files = cx.technology.files.get("github-actions", [])
    action_cmd = (
        [actionlint, "-format", "{{json .}}", *action_files] if actionlint else None
    )
    cx.add_technology(
        "actionlint",
        action_cmd,
        parse_actionlint,
        reason="GitHub Actions detected but actionlint is not installed",
        findings_exit_codes={1},
    )
    shellcheck = project_executable(cx.root, "shellcheck")
    shell_files = cx.technology.files.get("shell", [])
    shell_cmd = (
        [shellcheck, "-f", "json1", *shell_files]
        if shellcheck and shell_files
        else None
    )
    cx.add_technology(
        "shellcheck",
        shell_cmd,
        parse_shellcheck,
        reason="shell scripts detected but ShellCheck is not installed",
        findings_exit_codes={1},
    )
    dotenv = project_executable(cx.root, "dotenv-linter")
    env_files = cx.technology.files.get("dotenv", [])
    dotenv_cmd = [dotenv, "check", *env_files] if dotenv and env_files else None
    cx.add_technology(
        "dotenv-linter",
        dotenv_cmd,
        reason="environment files detected but dotenv-linter is not installed",
        findings_exit_codes={1},
    )
    if (
        "dotenv-linter" in cx.wanted
        and cx.technology.has("dotenv")
        and dotenv
        and ".env" in env_files
        and ".env.example" in env_files
    ):
        cx.checks.append(
            Check(
                "dotenv-linter:contract",
                ENGINE_CATEGORY["dotenv-linter"],
                [dotenv, "diff", ".env", ".env.example"],
                lambda o, e, c: text_findings("dotenv-linter", o, e, c),
                cx.timeout,
                cx.root,
                findings_exit_codes={1},
            ),
        )
    oasdiff = project_executable(cx.root, "oasdiff")
    openapi_files = cx.technology.files.get("openapi", [])
    if "oasdiff" in cx.wanted:
        if not cx.technology.has("openapi"):
            cx.add_technology("oasdiff", None)
        elif not oasdiff:
            cx.add_technology(
                "oasdiff",
                None,
                reason="OpenAPI detected but oasdiff is not installed",
            )
        else:
            for spec in openapi_files:
                safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", spec)
                cx.checks.append(
                    Check(
                        f"oasdiff:validate:{safe_name}",
                        ENGINE_CATEGORY["oasdiff"],
                        [oasdiff, "validate", spec],
                        partial(text_findings, f"oasdiff:validate:{safe_name}"),
                        cx.timeout,
                        cx.root,
                        findings_exit_codes={1},
                    ),
                )
                if cx.technology.git_baseline and git_path_exists(
                    cx.root,
                    cx.technology.git_baseline,
                    spec,
                ):
                    cx.checks.append(
                        Check(
                            f"oasdiff:breaking:{safe_name}",
                            ENGINE_CATEGORY["oasdiff"],
                            [
                                oasdiff,
                                "breaking",
                                "--format",
                                "json",
                                f"{cx.technology.git_baseline}:{spec}",
                                spec,
                            ],
                            partial(parse_json_list, f"oasdiff:breaking:{safe_name}"),
                            cx.timeout,
                            cx.root,
                            findings_exit_codes={1},
                        ),
                    )
    buf = project_executable(cx.root, "buf")
    if "buf" in cx.wanted:
        if not cx.technology.has("protobuf"):
            cx.add_technology("buf", None)
        elif not buf:
            cx.add_technology(
                "buf",
                None,
                reason="Protocol Buffers detected but buf is not installed",
            )
        else:
            buf_cfg = generated_config(cx.root, "buf.yaml")
            lint_cmd = [buf, "lint", ".", "--error-format=json"]
            if buf_cfg:
                lint_cmd += ["--config", str(buf_cfg)]
            cx.checks.append(
                Check(
                    "buf:lint",
                    ENGINE_CATEGORY["buf"],
                    lint_cmd,
                    parse_buf_json_lines,
                    cx.timeout,
                    cx.root,
                    findings_exit_codes={1, 100},
                ),
            )
            if cx.technology.git_baseline:
                breaking_cmd = [
                    buf,
                    "breaking",
                    ".",
                    "--against",
                    f".git#ref={cx.technology.git_baseline}",
                    "--error-format=json",
                ]
                if buf_cfg:
                    breaking_cmd += ["--config", str(buf_cfg)]
                cx.checks.append(
                    Check(
                        "buf:breaking",
                        ENGINE_CATEGORY["buf"],
                        breaking_cmd,
                        parse_buf_json_lines,
                        cx.timeout,
                        cx.root,
                        findings_exit_codes={1, 100},
                    ),
                )
    sqlfluff = project_executable(cx.root, "sqlfluff")
    sql_files = cx.technology.files.get("sql", [])
    sql_cfg = generated_config(cx.root, "sqlfluff.ini")
    sql_cmd = (
        [sqlfluff, "lint", *sql_files, "--format", "json"]
        if sqlfluff and sql_files
        else None
    )
    if sql_cmd and sql_cfg:
        sql_cmd += ["--config", str(sql_cfg)]
    cx.add_technology(
        "sqlfluff",
        sql_cmd,
        parse_sqlfluff,
        reason="SQL detected but SQLFluff is not installed",
        findings_exit_codes={1},
    )
    squawk = project_executable(cx.root, "squawk")
    migration_files = cx.technology.files.get("postgres-migrations", [])
    squawk_cmd = (
        [squawk, "--reporter", "json", *migration_files]
        if squawk and migration_files
        else None
    )
    cx.add_technology(
        "squawk",
        squawk_cmd,
        parse_squawk,
        reason="PostgreSQL migrations detected but Squawk is not installed",
        findings_exit_codes={1},
    )
    hadolint = project_executable(cx.root, "hadolint")
    docker_files = cx.technology.files.get("docker", [])
    hadolint_cfg = generated_config(cx.root, "hadolint.yaml")
    hadolint_cmd = [hadolint, "-f", "json"] if hadolint and docker_files else None
    if hadolint_cmd and hadolint_cfg:
        hadolint_cmd += ["--config", str(hadolint_cfg)]
    if hadolint_cmd:
        hadolint_cmd += docker_files
    cx.add_technology(
        "hadolint",
        hadolint_cmd,
        parse_hadolint,
        reason="Dockerfiles detected but Hadolint is not installed",
        findings_exit_codes={1},
    )
    tflint = project_executable(cx.root, "tflint")
    tflint_cfg = generated_config(cx.root, "tflint.hcl")
    tflint_cmd = [tflint, "--recursive", "--format=json"] if tflint else None
    if tflint_cmd and tflint_cfg:
        tflint_cmd += [f"--config={tflint_cfg}"]
    cx.add_technology(
        "tflint",
        tflint_cmd,
        parse_tflint,
        reason="Terraform detected but TFLint is not installed",
        findings_exit_codes={1},
    )
    golangci = project_executable(cx.root, "golangci-lint")
    go_linters = [
        "errcheck",
        "govet",
        "staticcheck",
        "ineffassign",
        "unused",
        "bodyclose",
        "durationcheck",
        "errorlint",
        "exhaustive",
        "makezero",
        "rowserrcheck",
        "sqlclosecheck",
    ]
    go_cmd = [golangci, "run", "--default=none"] if golangci else None
    if go_cmd:
        for linter in go_linters:
            go_cmd += ["--enable", linter]
        go_cmd += [
            "--output.json.path=stdout",
            "--output.text.path=",
            "--show-stats=false",
            "--issues-exit-code=1",
        ]
    cx.add_technology(
        "golangci-lint",
        go_cmd,
        parse_golangci,
        reason="Go detected but golangci-lint is not installed",
        findings_exit_codes={1},
    )
