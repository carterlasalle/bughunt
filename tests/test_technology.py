# Copyright (c) 2026 Carter LaSalle
from __future__ import annotations

import json
from pathlib import Path

import pytest

from bughunt.cli import (
    Config,
    Finding,
    Result,
    Status,
    _default_config_raw,
    build_checks,
    overall_score,
    parse_actionlint,
    parse_clippy,
    parse_hadolint,
    parse_shellcheck,
    parse_sqlfluff,
    parse_tflint,
)
from bughunt.configurator import configure_all
from bughunt.technology import discover_technologies, infer_sql_dialect


# trace:v1 id=test.tests-test-technology.test-detects-mixed-repository-capabilities work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_detects_mixed_repository_capabilities(tmp_path: Path) -> None:
    (tmp_path / ".github/workflows").mkdir(parents=True)
    (tmp_path / ".github/workflows/ci.yml").write_text("name: ci\non: push\n")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts/build.sh").write_text("#!/bin/sh\necho ok\n")
    (tmp_path / ".env.example").write_text("PORT=8000\n")
    (tmp_path / "openapi.yaml").write_text(
        "openapi: 3.1.0\ninfo: {title: x, version: '1'}\npaths: {}\n",
    )
    (tmp_path / "proto").mkdir()
    (tmp_path / "proto/x.proto").write_text('syntax = "proto3";\npackage x;\n')
    (tmp_path / "migrations").mkdir()
    (tmp_path / "migrations/001_create.sql").write_text(
        "CREATE TABLE x (id SERIAL PRIMARY KEY);\n",
    )
    (tmp_path / "Dockerfile").write_text("FROM scratch\n")
    (tmp_path / "main.tf").write_text('terraform { required_version = ">= 1.0" }\n')
    (tmp_path / "go.mod").write_text("module example.com/x\n")
    (tmp_path / "Cargo.toml").write_text('[package]\nname="x"\nversion="0.1.0"\n')
    (tmp_path / "compile_commands.json").write_text("[]")
    (tmp_path / "main.cpp").write_text("int main(){return 0;}\n")
    (tmp_path / "composer.json").write_text("{}")
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"react": "^19"}}),
    )
    (tmp_path / "App.tsx").write_text("export const App = () => <div/>;\n")

    inv = discover_technologies(tmp_path)
    for capability in (
        "github-actions",
        "shell",
        "dotenv",
        "openapi",
        "protobuf",
        "sql",
        "postgres-migrations",
        "docker",
        "terraform",
        "go",
        "rust",
        "cpp",
        "cpp-compile-db",
        "php",
        "javascript-typescript",
        "react",
    ):
        assert inv.has(capability), capability


# trace:v1 id=test.tests-test-technology.test-ignored-trees-do-not-create-capabilities work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_ignored_trees_do_not_create_capabilities(tmp_path: Path) -> None:
    (tmp_path / "node_modules/pkg").mkdir(parents=True)
    (tmp_path / "node_modules/pkg/index.ts").write_text("const x: number = 1")
    (tmp_path / ".bughunt/generated").mkdir(parents=True)
    (tmp_path / ".bughunt/generated/openapi.yaml").write_text("openapi: 3.1.0\n")
    inv = discover_technologies(tmp_path)
    assert not inv.has("javascript-typescript")
    assert not inv.has("openapi")


# trace:v1 id=test.tests-test-technology.test-sql-dialect-inference-detects-postgres work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_sql_dialect_inference_detects_postgres(tmp_path: Path) -> None:
    (tmp_path / "x.sql").write_text(
        "CREATE TABLE x (id SERIAL PRIMARY KEY, body JSONB);\n",
    )
    assert infer_sql_dialect(tmp_path, ["x.sql"]) == "postgres"


def test_not_applicable_defenses_do_not_lower_health() -> None:
    results = [
        Result("compile", "syntax", Status.PASS),
        Result("clippy", "rust", Status.NA),
        Result("buf", "schema", Status.NA),
    ]
    assert overall_score(results) == 100


# trace:v1 id=test.tests-test-technology.test-build-checks-marks-irrelevant-technology-na work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_build_checks_marks_irrelevant_technology_na(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src/x.py").write_text("x = 1\n")
    cfg = Config(
        tmp_path,
        {
            "project": {
                "source_paths": ["src"],
                "test_paths": [],
                "python_paths": ["src"],
            },
            "profiles": {"pr": {"tools": ["compile"]}},
            "timeouts": {"pr": 60},
        },
    )
    _, results = build_checks(cfg, "pr")
    by_name = {r.name: r for r in results}
    assert by_name["clippy"].status == Status.NA
    assert by_name["oasdiff"].status == Status.NA


# trace:v1 id=test.tests-test-technology.test-configure-generates-applicable-technology-overlays work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_configure_generates_applicable_technology_overlays(tmp_path: Path) -> None:
    (tmp_path / "queries").mkdir()
    (tmp_path / "queries/x.sql").write_text("select * from x limit 1;\n")
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"react": "19"}}),
    )
    (tmp_path / "App.jsx").write_text("export function App(){ return <div/> }\n")
    (tmp_path / "main.tf").write_text("terraform {}\n")
    (tmp_path / "Dockerfile").write_text("FROM scratch\n")
    configure_all(tmp_path, ["."], ["."], [], schemathesis_examples=1000)
    config = tmp_path / ".bughunt/configs"
    assert (config / "sqlfluff.ini").exists()
    assert (config / "oxlintrc.json").exists()
    assert (config / "eslint.config.mjs").exists()
    assert (config / "tflint.hcl").exists()
    assert (config / "hadolint.yaml").exists()


def test_parse_actionlint_json_lines() -> None:
    out = parse_actionlint(
        '{"filepath":".github/workflows/ci.yml","line":7,"column":3,'
        '"kind":"expression","message":"unknown property"}\n',
        "",
        1,
    )
    assert out == [
        Finding(
            tool="actionlint",
            path=".github/workflows/ci.yml",
            line=7,
            column=3,
            code="expression",
            message="unknown property",
            severity="error",
        ),
    ]


def test_parse_shellcheck_json1() -> None:
    data = {
        "comments": [
            {
                "file": "x.sh",
                "line": 3,
                "column": 2,
                "level": "warning",
                "code": 2086,
                "message": "Double quote",
            },
        ],
    }
    out = parse_shellcheck(json.dumps(data), "", 1)
    assert out[0].code == "SC2086"
    assert out[0].path == "x.sh"


def test_parse_sqlfluff_json() -> None:
    data = [
        {
            "filepath": "q.sql",
            "violations": [
                {
                    "code": "AM09",
                    "description": "LIMIT without ORDER BY",
                    "start_line_no": 4,
                    "start_line_pos": 1,
                },
            ],
        },
    ]
    out = parse_sqlfluff(json.dumps(data), "", 1)
    assert out[0].code == "AM09"
    assert out[0].line == 4


def test_parse_hadolint_and_tflint() -> None:
    h = parse_hadolint(
        json.dumps(
            [
                {
                    "file": "Dockerfile",
                    "line": 2,
                    "column": 1,
                    "level": "warning",
                    "code": "DL3003",
                    "message": "Use WORKDIR",
                },
            ],
        ),
        "",
        1,
    )
    assert h[0].code == "DL3003"
    t = parse_tflint(
        json.dumps(
            {
                "issues": [
                    {
                        "rule": {
                            "name": "terraform_unused_declarations",
                            "severity": "warning",
                        },
                        "message": "unused",
                        "range": {
                            "filename": "main.tf",
                            "start": {"line": 3, "column": 1},
                        },
                    },
                ],
            },
        ),
        "",
        1,
    )
    assert t[0].code == "terraform_unused_declarations"


def test_parse_clippy_compiler_message() -> None:
    payload = {
        "reason": "compiler-message",
        "message": {
            "level": "warning",
            "message": "this expression does nothing",
            "code": {"code": "clippy::no_effect"},
            "spans": [
                {
                    "is_primary": True,
                    "file_name": "src/lib.rs",
                    "line_start": 9,
                    "column_start": 5,
                },
            ],
        },
    }
    out = parse_clippy(json.dumps(payload) + "\n", "", 1)
    assert out[0].code == "clippy::no_effect"
    assert out[0].path == "src/lib.rs"


# trace:v1 id=test.tests-test-technology.test-python-only-defenses-are-na-without-python work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_python_only_defenses_are_na_without_python(tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text('[package]\nname="demo"\nversion="0.1.0"\n')
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "lib.rs").write_text("pub fn add(a:i32,b:i32)->i32{a+b}\n")
    discover_technologies(tmp_path, persist=True)
    raw = _default_config_raw()
    raw["profiles"]["all"]["tools"] = [
        "compile",
        "mypy",
        "codeql",
        "pysa",
        "mutmut",
        "clippy",
    ]
    cfg = Config(root=tmp_path, raw=raw)
    checks, skipped = build_checks(cfg, "all")
    status = {r.name: r.status for r in skipped}
    assert status["compile"] == Status.NA
    assert status["mypy"] == Status.NA
    assert status["codeql"] == Status.NA
    assert status["pysa"] == Status.NA
    assert status["mutmut"] == Status.NA
    assert not any(c.name in {"compile", "mypy"} for c in checks)


# trace:v1 id=test.tests-test-technology.test-oxlint-empty-scope-banner-parses-clean work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def test_oxlint_empty_scope_banner_parses_clean() -> None:
    from bughunt.cli import OXLINT_EMPTY_SCOPE, parse_oxlint

    # Ignore patterns excluding every candidate file must not become a finding:
    # the runner maps the banner to SKIPPED ("nothing in scope").
    stdout = (
        f"{OXLINT_EMPTY_SCOPE}. Please check your paths and ignore patterns.\n"
        '{"diagnostics": []}'
    )
    assert parse_oxlint(stdout, "", 1) == []
    real = (
        '{"diagnostics": [{"message": "x", "code": "no-undef", '
        '"severity": "error", "filename": "a.js"}]}'
    )
    assert len(parse_oxlint(real, "", 1)) == 1


# trace:v1 id=test.tests-test-technology.test-eslint-empty-scope-banner-parses-clean work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def test_eslint_empty_scope_banner_parses_clean() -> None:
    from bughunt.cli import ESLINT_EMPTY_SCOPE, parse_eslint

    stderr = f'You are linting ".", but {ESLINT_EMPTY_SCOPE} "." are ignored.\n'
    assert parse_eslint("", stderr, 2) == []


# trace:v1 id=test.tests-test-technology.test-tsc-gated-on-tsconfig work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_tsc_gated_on_tsconfig(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from bughunt import cli as cli_mod

    # Without a project file tsc prints help text that is not a finding;
    # with one, the check is built. tsc is force-present: host PATH varies.
    monkeypatch.setattr(cli_mod, "project_executable", lambda root, *names: "/bin/tsc")
    (tmp_path / "app.ts").write_text("export const x: number = 1;\n")
    cfg = Config(root=tmp_path, raw=_default_config_raw())
    _, skipped = build_checks(cfg, "pr")
    tsc_skip = next(r for r in skipped if r.name == "tsc")
    assert tsc_skip.status == Status.SKIPPED
    assert tsc_skip.note is not None and "tsconfig" in tsc_skip.note
    (tmp_path / "tsconfig.json").write_text("{}")
    checks, _ = build_checks(cfg, "pr")
    assert any(c.name == "tsc" for c in checks)
