from pathlib import Path

import pytest

from bughunt.cli import (
    Config,
    Finding,
    Result,
    Status,
    overall_score,
    parse_basedpyright,
    parse_ruff,
)


def test_parse_ruff():
    raw = """[
      {
        "code":"F821",
        "message":"Undefined name `x`",
        "filename":"src/a.py",
        "location":{"row":10,"column":3}
      }
    ]"""
    got = parse_ruff(raw, "", 1)
    assert len(got) == 1
    assert got[0].code == "F821"
    assert got[0].line == 10


def test_parse_basedpyright_zero_based_locations():
    raw = """{
      "generalDiagnostics": [{
        "file":"src/a.py",
        "severity":"error",
        "message":"boom",
        "rule":"reportGeneralTypeIssues",
        "range":{"start":{"line":4,"character":2},"end":{"line":4,"character":3}}
      }]
    }"""
    got = parse_basedpyright(raw, "", 1)
    assert got[0].line == 5
    assert got[0].column == 3


def test_fingerprint_ignores_line_motion():
    a = Finding(tool="ruff", path="a.py", line=1, code="X", message="bad")
    b = Finding(tool="ruff", path="a.py", line=200, code="X", message="bad")
    assert a.fingerprint == b.fingerprint


def test_health_penalizes_findings():
    clean = [Result("a", "x", Status.PASS)]
    dirty = [Result("a", "x", Status.FINDINGS)]
    assert overall_score(clean) > overall_score(dirty)


# trace:v1 id=test.tests-test-core.test-install-only-cli-is-wired work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_install_only_cli_is_wired(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """Regression: the source hotfix must expose --only all the way to install_all."""
    from bughunt import cli

    seen = {}

    def fake_install_all(root, *, dry_run=False, emit=print, only=None):
        seen["root"] = root
        seen["dry_run"] = dry_run
        seen["only"] = only
        return []

    monkeypatch.setattr(cli, "install_all", fake_install_all)
    rc = cli.main(
        ["--root", str(tmp_path), "install", "--only", "atheris", "--dry-run"],
    )
    assert rc == 0
    assert seen["dry_run"] is True
    assert seen["only"] == {"atheris"}


def test_text_findings_extracts_mypy_error_code():
    from bughunt.cli import text_findings

    got = text_findings(
        "mypy",
        'src/a.py:7: error: Name "x" is not defined  [name-defined]\n',
        "",
        1,
    )
    assert len(got) == 1
    assert got[0].code == "name-defined"
    assert got[0].message == 'Name "x" is not defined'


# trace:v1 id=test.tests-test-core.test-import-linter-requires-real-config work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_import_linter_requires_real_config(tmp_path: Path):
    from bughunt.cli import import_linter_configured

    (tmp_path / "pyproject.toml").write_text('[project]\nname="x"\nversion="0"\n')
    assert not import_linter_configured(tmp_path)
    (tmp_path / "pyproject.toml").write_text('[tool.importlinter]\nroot_package="x"\n')
    assert import_linter_configured(tmp_path)


def test_pylint_json2_messages_are_individual_findings():
    from bughunt.cli import parse_json_list

    raw = (
        '{"messages":[{"type":"warning","path":"a.py","line":2,"column":0,'
        '"message-id":"W0718","symbol":"broad-exception-caught","message":'
        '"Catching too general exception Exception"},{"type":"warning","path":'
        '"b.py","line":4,"column":1,"message-id":"W0718","symbol":'
        '"broad-exception-caught","message":"Catching too general exception '
        'Exception"}],"statistics":{}}'
    )
    got = parse_json_list("pylint", raw, "", 4)
    assert len(got) == 2
    assert all(x.code == "W0718" for x in got)
    assert all(x.severity == "warning" for x in got)


# trace:v1 id=test.tests-test-core.test-configure-all-generates-paranoid-configs-and-is-idempotent work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_configure_all_generates_paranoid_configs_and_is_idempotent(tmp_path: Path):
    import json
    import tomllib

    from bughunt.configurator import configure_all

    (tmp_path / "src/pkg").mkdir(parents=True)
    (tmp_path / "src/pkg/__init__.py").write_text("")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests/test_smoke.py").write_text("def test_ok(): assert True\n")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="pkg"\nversion="0.0.0"\nrequires-python=">=3.11"\n',
    )

    configure_all(tmp_path, ["src", "tests"], ["src"], ["tests"])
    cfg = tmp_path / ".bughunt/configs"

    ruff = (cfg / "ruff.toml").read_text()
    assert 'select = ["ALL"]' in ruff
    assert "preview = true" in ruff
    assert "force-exclude = true" in ruff
    assert ".bughunt/runtime" in ruff

    bp = json.loads((cfg / "basedpyrightconfig.json").read_text())
    assert bp["typeCheckingMode"] == "all"
    assert bp["reportAny"] == "error"
    assert bp["enableTypeIgnoreComments"] is False
    assert bp["reportInvalidCast"] == "error"

    mypy = (cfg / "mypy.ini").read_text()
    assert "strict = True" in mypy
    assert "follow_untyped_imports = True" in mypy
    assert "disallow_any_expr = True" in mypy
    assert "possibly-undefined" in mypy

    ty = (cfg / "ty.toml").read_text()
    assert 'all = "error"' in ty
    assert "respect-type-ignore-comments = false" in ty

    pyrefly = (cfg / "pyrefly.toml").read_text()
    assert 'preset = "all"' in pyrefly
    assert "replace-untyped-imports-with-any = []" in pyrefly
    assert "ignore-errors-in-generated-code = false" in pyrefly

    il = (cfg / "importlinter.toml").read_text()
    assert 'type = "acyclic_siblings"' in il
    assert 'ancestors = ["pkg"]' in il

    project_after_first = (tmp_path / "pyproject.toml").read_text()
    assert project_after_first.count("[tool.mutmut]") == 1
    configure_all(tmp_path, ["src", "tests"], ["src"], ["tests"])
    assert (tmp_path / "pyproject.toml").read_text().count("[tool.mutmut]") == 1
    # Still valid TOML after the managed mutation block.
    tomllib.loads((tmp_path / "pyproject.toml").read_text())


# trace:v1 id=test.tests-test-core.test-run-process-handles-huge-single-line-without-readline-limit work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_run_process_handles_huge_single_line_without_readline_limit(tmp_path: Path):
    import asyncio
    import sys

    from bughunt.cli import Check, run_process

    check = Check(
        name="huge-json",
        category="regression",
        command=[sys.executable, "-c", "import sys; sys.stdout.write('x' * 250000)"],
        parser=lambda out, err, code: [],
        timeout=10,
        cwd=tmp_path,
        findings_exit_codes={1},
    )
    result = asyncio.run(run_process(check, 300000))
    assert result.status == Status.PASS
    assert len(result.stdout) == 250000


# trace:v1 id=test.tests-test-core.test-deep-profile-is-not-downgraded-to-pr work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_deep_profile_is_not_downgraded_to_pr(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    from bughunt import cli

    seen = {}

    monkeypatch.setattr(cli, "auto_configure", lambda cfg, quiet=False: [])

    # trace:v1 id=test.tests-test-core-test-deep-profile-is-not-downgraded-to-pr.fake-run-all work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    async def fake_run_all(cfg: Config, profile: str, *, auto_discover: bool = True):
        seen["profile"] = profile
        return [], 0.01

    monkeypatch.setattr(cli, "run_all", fake_run_all)
    monkeypatch.setattr(
        cli,
        "write_reports",
        lambda *a, **k: (tmp_path / "r.md", tmp_path / "r.json"),
    )
    monkeypatch.setattr(cli, "render_terminal", lambda *a, **k: None)

    rc = cli.main(["--root", str(tmp_path), "run", "--profile", "deep"])
    assert rc == 0
    assert seen["profile"] == "deep"


# trace:v1 id=test.tests-test-core.test-quick-alias-routes-fast work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_quick_alias_routes_fast(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    from bughunt import cli

    seen = {}
    monkeypatch.setattr(cli, "auto_configure", lambda cfg, quiet=False: [])

    # trace:v1 id=test.tests-test-core-test-quick-alias-routes-fast.fake-run-all work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    async def fake_run_all(cfg: Config, profile: str, *, auto_discover: bool = True):
        seen["profile"] = profile
        return [], 0.01

    monkeypatch.setattr(cli, "run_all", fake_run_all)
    monkeypatch.setattr(
        cli,
        "write_reports",
        lambda *a, **k: (tmp_path / "r.md", tmp_path / "r.json"),
    )
    monkeypatch.setattr(cli, "render_terminal", lambda *a, **k: None)

    rc = cli.main(["--root", str(tmp_path), "quick"])
    assert rc == 0
    assert seen["profile"] == "fast"


def test_deptry_parser_preserves_dependency_rule_codes():
    from bughunt.cli import parse_deptry

    raw = (
        "src/a.py:4:0: DEP004 'pytest' imported but declared as "
        "a dev dependency\npyproject.toml: DEP002 'foo' defined "
        "as a dependency but not used\n"
    )
    got = parse_deptry(raw, "", 1)
    assert [x.code for x in got] == ["DEP004", "DEP002"]
    assert got[1].path == "pyproject.toml"


def test_pyrefly_parser_uses_named_diagnostic_instead_of_internal_negative_code():
    import json

    from bughunt.cli import parse_pyrefly

    raw = json.dumps(
        {
            "errors": [
                {
                    "path": "src/a.py",
                    "line": 7,
                    "column": 3,
                    "code": -2,
                    "name": "bad-assignment",
                    "message": "incompatible assignment",
                },
            ],
        },
    )
    got = parse_pyrefly(raw, "", 1)
    assert got[0].code == "bad-assignment"
    assert got[0].signal_key == "pyrefly:bad-assignment"


def test_generic_mypy_misc_signals_do_not_collapse_unrelated_messages():
    from bughunt.cli import Finding

    a = Finding(tool="mypy", code="misc", message="Expression type contains Any")
    b = Finding(tool="mypy", code="misc", message="Class cannot subclass final class")
    assert a.signal_key != b.signal_key


# trace:v1 id=test.tests-test-core.test-canonicalize-findings-collapses-absolute-and-relative-repo-paths work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_canonicalize_findings_collapses_absolute_and_relative_repo_paths(
    tmp_path: Path,
):
    from bughunt.cli import (
        Finding,
        Result,
        Status,
        canonicalize_findings,
        hotspot_files,
    )

    (tmp_path / "src").mkdir()
    target = tmp_path / "src" / "a.py"
    target.write_text("x = 1\n")
    results = [
        Result(
            "a",
            "x",
            Status.FINDINGS,
            findings=[Finding("a", "m", path=str(target))],
        ),
        Result(
            "b",
            "x",
            Status.FINDINGS,
            findings=[Finding("b", "m", path="src/a.py")],
        ),
    ]
    canonicalize_findings(tmp_path, results)
    assert hotspot_files(results)[0] == ("src/a.py", 2)


# trace:v1 id=test.tests-test-core.test-canonicalize-findings-exempts-trace-marker-lines work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def test_canonicalize_findings_exempts_trace_marker_lines(tmp_path: Path):
    from bughunt.cli import (
        Finding,
        Result,
        Status,
        canonicalize_findings,
    )

    target = tmp_path / "a.py"
    target.write_text(
        "# trace:v1 id=impl.x work=W satisfies=R\n"
        "<!-- trace:v1 id=doc.y work=W documents=R -->\n"
        "x = 1\n"
    )
    results = [
        Result(
            "ruff",
            "lint",
            Status.FINDINGS,
            findings=[
                Finding("ruff", "line too long", path="a.py", line=1),
                Finding("ruff", "line too long", path="a.py", line=2),
                Finding("ruff", "line too long", path="a.py", line=3),
                Finding("ruff", "no line", path="a.py"),
            ],
        ),
    ]
    canonicalize_findings(tmp_path, results)
    surviving = [(f.line) for f in results[0].findings]
    assert surviving == [3, None]


# trace:v1 id=test.tests-test-core.test-generated-pylint-config-omits-removed-suggestion-mode work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_generated_pylint_config_omits_removed_suggestion_mode(tmp_path: Path):
    from bughunt.configurator import configure_all

    (tmp_path / "src/pkg").mkdir(parents=True)
    (tmp_path / "src/pkg/__init__.py").write_text("")
    (tmp_path / "tests").mkdir()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="pkg"\nversion="0"\nrequires-python=">=3.11"\n',
    )
    configure_all(tmp_path, ["src", "tests"], ["src"], ["tests"])
    text = (tmp_path / ".bughunt/configs/pylintrc").read_text()
    assert "suggestion-mode" not in text


# trace:v1 id=test.tests-test-core.test-semgrep-auto-is-rewritten-to-explicit-default-pack work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_semgrep_auto_is_rewritten_to_explicit_default_pack(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    from bughunt import cli

    (tmp_path / "src").mkdir()
    (tmp_path / "src/a.py").write_text("x = 1\n")
    cfg = cli.Config(
        tmp_path,
        {
            "project": {
                "python_paths": ["src"],
                "source_paths": ["src"],
                "test_paths": [],
            },
            "profiles": {"pr": {"tools": ["semgrep"]}},
            "semgrep": {"configs": ["auto"]},
        },
    )
    real = cli.executable
    monkeypatch.setattr(
        cli,
        "executable",
        lambda *names: "/usr/bin/semgrep" if "semgrep" in names else real(*names),
    )
    checks, _ = cli.build_checks(cfg, "pr")
    command = next(c.command for c in checks if c.name == "semgrep")
    assert "auto" not in command
    assert "p/default" in command
    assert "p/security-audit" not in command
    assert "p/secrets" not in command
    assert "--metrics=off" in command
    assert "--oss-only" in command


# trace:v1 id=test.tests-test-core.test-internal-progress-stage-is-not-counted-as-completed-defense work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_internal_progress_stage_is_not_counted_as_completed_defense(tmp_path: Path):
    import asyncio
    import sys

    from bughunt.cli import Check, LiveRunState, run_process

    progress = LiveRunState(total=1)
    check = Check(
        "internal",
        "phase",
        [sys.executable, "-c", "print('ok')"],
        lambda o, e, c: [],
        10,
        tmp_path,
        record_progress=False,
    )
    result = asyncio.run(run_process(check, 4096, progress))
    assert result.status == Status.PASS
    assert progress.completed == []
    assert "internal" not in progress.running


# trace:v1 id=test.tests-test-core.test-pysa-is-installed-into-private-compatibility-runtime work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_pysa_is_installed_into_private_compatibility_runtime(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    from bughunt import installers

    (tmp_path / "pyproject.toml").write_text('[project]\nname="x"\nversion="0"\n')
    monkeypatch.setattr(
        installers.shutil,
        "which",
        lambda name: "/usr/bin/uv" if name == "uv" else None,
    )
    got = installers.install_all(
        tmp_path,
        dry_run=True,
        emit=lambda _: None,
        only={"pysa"},
    )
    commands = [" ".join(x.command) for x in got]
    assert any("uv venv --python 3.12" in cmd for cmd in commands)
    assert any("click<8.2" in cmd and "pyre-check" in cmd for cmd in commands)
    assert not any("uv add --dev pyre-check" in cmd for cmd in commands)


def test_ruff_fix_metadata_is_preserved():
    from bughunt.cli import parse_ruff

    raw = (
        '[{"code":"F401","message":"unused","filename":"a.py","location":'
        '{"row":1,"column":1},"fix":{"applicability":"safe","message":'
        '"Remove import","edits":[]}}]'
    )
    finding = parse_ruff(raw, "", 1)[0]
    assert finding.fixable is True
    assert finding.fix_safety == "safe"
    assert finding.fix_preview == "Remove import"


def test_semgrep_fix_metadata_is_preserved():
    from bughunt.cli import parse_semgrep

    raw = (
        '{"results":[{"check_id":"x","path":"a.py","start":{"line":1,"col":1},'
        '"extra":{"message":"bad","severity":"WARNING","fix":"good()"}}]}'
    )
    finding = parse_semgrep(raw, "", 1)[0]
    assert finding.fixable is True
    assert finding.fix_safety == "rule"
    assert finding.fix_preview == "good()"


# trace:v1 id=test.tests-test-core.test-flat-layout-source-path-inference work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_flat_layout_source_path_inference(tmp_path: Path):
    from bughunt.cli import load_config

    package = tmp_path / "demo"
    package.mkdir()
    (package / "__init__.py").write_text("")
    cfg = load_config(tmp_path)
    assert cfg.source_paths == ["demo"]
    assert "demo" in cfg.python_paths


# trace:v1 id=test.tests-test-core.test-flat-layout-python-paths-do-not-get-masked-by-tests-dir work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_flat_layout_python_paths_do_not_get_masked_by_tests_dir(tmp_path: Path):
    from bughunt.cli import load_config

    package = tmp_path / "demo"
    package.mkdir()
    (package / "__init__.py").write_text("")
    (tmp_path / "tests").mkdir()
    cfg = load_config(tmp_path)
    assert "demo" in cfg.python_paths
    assert "tests" in cfg.python_paths
    assert "src" not in cfg.python_paths


# trace:v1 id=test.tests-test-core.test-default-pr-profile-contains-policy-and-complexity-engines work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_default_pr_profile_contains_policy_and_complexity_engines(tmp_path: Path):
    from bughunt.cli import load_config

    cfg = load_config(tmp_path)
    tools = cfg.tools("pr")
    for tool in ("policy", "complexity", "complexipy", "radon", "lizard"):
        assert tool in tools


# trace:v1 id=test.tests-test-core.test-full-alias-routes-to-all-and-bootstraps-by-default work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_full_alias_routes_to_all_and_bootstraps_by_default(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    from bughunt import cli

    seen = {"install": 0}

    def fake_install_all(root, *, dry_run=False, emit=print, only=None):
        seen["install"] += 1
        return []

    # trace:v1 id=test.tests-test-core-test-full-alias-routes-to-all-and-bootstraps-by-default.fake-run-all work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    async def fake_run_all(cfg: Config, profile: str, *, auto_discover: bool = True):
        seen["profile"] = profile
        return [], 0.01

    monkeypatch.setattr(cli, "install_all", fake_install_all)
    monkeypatch.setattr(cli, "auto_configure", lambda cfg, quiet=False: [])
    monkeypatch.setattr(cli, "run_all", fake_run_all)
    monkeypatch.setattr(
        cli,
        "write_reports",
        lambda *a, **k: (tmp_path / "r.md", tmp_path / "r.json"),
    )
    monkeypatch.setattr(cli, "render_terminal", lambda *a, **k: None)

    rc = cli.main(["--root", str(tmp_path), "full"])
    assert rc == 0
    assert seen["profile"] == "all"
    assert seen["install"] == 1


def test_complexity_parsers_preserve_tool_specific_signals():
    from bughunt.cli import parse_complexipy, parse_lizard, parse_radon_mi

    complexipy = parse_complexipy("src/a.py f 17\n", "", 1)
    assert complexipy and complexipy[0].code == "COG001"

    lizard = parse_lizard(
        "src/a.py:12: warning: f has 14 CCN and 90 NLOC [CCN > 10]\n",
        "",
        1,
    )
    assert lizard and lizard[0].tool == "lizard"

    radon = parse_radon_mi('{"src/a.py":{"mi":8.5,"rank":"C"}}', "", 0)
    assert radon and radon[0].code == "RADON_MI" and radon[0].severity == "error"


# trace:v1 id=test.tests-test-core.test-full-alias-accepts-no-install-missing work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_full_alias_accepts_no_install_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    from bughunt import cli

    seen = {"install": 0, "profile": None}
    monkeypatch.setattr(cli, "auto_configure", lambda cfg, quiet=False: [])
    monkeypatch.setattr(
        cli,
        "install_all",
        lambda *a, **k: seen.__setitem__("install", seen["install"] + 1) or [],
    )

    # trace:v1 id=test.tests-test-core-test-full-alias-accepts-no-install-missing.fake-run-all work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    async def fake_run_all(cfg: Config, profile: str, *, auto_discover: bool = True):
        seen["profile"] = profile
        return [], 0.01

    monkeypatch.setattr(cli, "run_all", fake_run_all)
    monkeypatch.setattr(
        cli,
        "write_reports",
        lambda *a, **k: (tmp_path / "r.md", tmp_path / "r.json"),
    )
    monkeypatch.setattr(cli, "render_terminal", lambda *a, **k: None)

    rc = cli.main(["--root", str(tmp_path), "full", "--no-install-missing"])
    assert rc == 0
    assert seen["install"] == 0
    assert seen["profile"] == "all"


# trace:v1 id=test.tests-test-core.test-rules-command-lists-native-pack work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_rules_command_lists_native_pack(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    from bughunt import cli

    seen = {"called": False}
    monkeypatch.setattr(
        cli,
        "show_default_rules",
        lambda: seen.__setitem__("called", True) or 0,
    )
    rc = cli.main(["--root", str(tmp_path), "rules"])
    assert rc == 0
    assert seen["called"] is True


# trace:v1 id=test.tests-test-core.test-build-checks-marks-explicitly-skipped-mutmut work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_build_checks_marks_explicitly_skipped_mutmut(tmp_path: Path):
    from bughunt import cli

    cfg = cli.load_config(tmp_path)
    checks, skipped = cli.build_checks(cfg, "all", excluded={"mutmut"})
    assert not any(check.name == "mutmut" for check in checks)
    item = next(result for result in skipped if result.name == "mutmut")
    assert item.status == cli.Status.SKIPPED
    assert "explicitly skipped" in (item.note or "")


# trace:v1 id=test.tests-test-core.test-skipmutmut-alias-passes-exclusion-and-avoids-install work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_skipmutmut_alias_passes_exclusion_and_avoids_install(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    from bughunt import cli

    seen = {}
    monkeypatch.setattr(cli, "auto_configure", lambda cfg, quiet=False: [])

    def fake_install_all(root, *, dry_run=False, emit=print, only=None, exclude=None):
        seen["install_exclude"] = set(exclude or ())
        return []

    # trace:v1 id=test.tests-test-core-test-skipmutmut-alias-passes-exclusion-and-avoids-install.fake-run-all work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    async def fake_run_all(
        cfg: Config,
        profile: str,
        *,
        auto_discover: bool = True,
        excluded: set[str] | None = None,
    ):
        seen["profile"] = profile
        seen["excluded"] = set(excluded or ())
        return [], 0.01

    monkeypatch.setattr(cli, "install_all", fake_install_all)
    monkeypatch.setattr(cli, "run_all", fake_run_all)
    monkeypatch.setattr(
        cli,
        "write_reports",
        lambda *a, **k: (tmp_path / "r.md", tmp_path / "r.json"),
    )
    monkeypatch.setattr(cli, "render_terminal", lambda *a, **k: None)
    rc = cli.main(["--root", str(tmp_path), "skipmutmut"])
    assert rc == 0
    assert seen["profile"] == "all"
    assert seen["excluded"] == {"mutmut"}
    assert seen["install_exclude"] == {"mutmut"}


# trace:v1 id=test.tests-test-core.test-run-accepts-positional-all-profile work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_run_accepts_positional_all_profile(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    from bughunt import cli

    seen = {}
    monkeypatch.setattr(cli, "auto_configure", lambda cfg, quiet=False: [])

    # trace:v1 id=test.tests-test-core-test-run-accepts-positional-all-profile.fake-run-all work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
    async def fake_run_all(
        cfg: Config,
        profile: str,
        *,
        auto_discover: bool = True,
        excluded: set[str] | None = None,
    ):
        seen["profile"] = profile
        return [], 0.01

    monkeypatch.setattr(cli, "run_all", fake_run_all)
    monkeypatch.setattr(
        cli,
        "write_reports",
        lambda *a, **k: (tmp_path / "r.md", tmp_path / "r.json"),
    )
    monkeypatch.setattr(cli, "render_terminal", lambda *a, **k: None)
    rc = cli.main(["--root", str(tmp_path), "run", "all", "--skip-mutmut"])
    assert rc == 0
    assert seen["profile"] == "all"


# trace:v1 id=test.tests-test-core.test-run-pysa-maps-missing-provider-to-skipped work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_run_pysa_maps_missing_provider_to_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import asyncio
    import stat

    from bughunt import cli as cli_mod
    from bughunt.cli import Config, Status, run_pysa

    # A missing Pyrefly provider means the defense cannot execute; it must
    # report SKIPPED with the repair, never an analysis ERROR (observed on a
    # fresh repo whose installer left pyre without its provider, 2026-09-11).
    (tmp_path / ".pyre_configuration").write_text("{}\n")
    fake = tmp_path / "pyre"
    fake.write_text(
        '#!/bin/sh\necho "Cannot locate a Pyrefly binary to run."\nexit 16\n'
    )
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setattr(cli_mod, "pysa_executable", lambda root: str(fake))
    raw = {
        "project": {"python_paths": ["src"], "source_paths": ["src"]},
        "execution": {"max_parallel": 1},
        "timeouts": {"deep": 60},
        "profiles": {"deep": {"tools": ["pysa"]}},
    }
    result = asyncio.run(run_pysa(Config(root=tmp_path, raw=raw), "deep", 512))
    assert result.status == Status.SKIPPED
    assert result.findings == []
    assert "install --only pysa" in (result.note or "")
