# Copyright (c) 2026 Carter LaSalle
from __future__ import annotations

from pathlib import Path

from bughunt.metrics_scan import scan as scan_metrics
from bughunt.policy_scan import ensure_env_example
from bughunt.policy_scan import scan as scan_policy


def _pkg(tmp_path: Path) -> Path:
    src = tmp_path / "src" / "demo"
    src.mkdir(parents=True)
    (src / "__init__.py").write_text("")
    (tmp_path / "tests").mkdir()
    return src


# trace:v1 id=test.tests-test-policy-metrics.test-env-example-is-generated-from-static-environment-contract work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_env_example_is_generated_from_static_environment_contract(
    tmp_path: Path,
) -> None:
    src = _pkg(tmp_path)
    (src / "config_use.py").write_text(
        "import os\n"
        "PORT = int(os.getenv('PORT', '8000'))\n"
        "API_TOKEN = os.environ['API_TOKEN']\n"
        "TIMEOUT_SECONDS = int(os.getenv('TIMEOUT_SECONDS', '30'))\n",
    )
    path, uses = ensure_env_example(tmp_path, ["src"])
    assert path == tmp_path / ".env.example"
    text = path.read_text()
    assert "PORT=8000" in text
    assert "TIMEOUT_SECONDS=30" in text
    assert "unit: seconds" in text
    assert "API_TOKEN=" in text
    assert len(uses) == 3
    # A generated env contract should satisfy its own drift checks.
    codes = {item.code for item in scan_policy(tmp_path, ["src"], ["tests"])}
    assert "BHCFG001" not in codes
    assert "BHCFG002" not in codes


# trace:v1 id=test.tests-test-policy-metrics.test-env-example-real-looking-secret-is-flagged work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_env_example_real_looking_secret_is_flagged(tmp_path: Path) -> None:
    src = _pkg(tmp_path)
    (src / "x.py").write_text("import os\nTOKEN = os.environ['API_TOKEN']\n")
    (tmp_path / ".env.example").write_text(
        "API_TOKEN=sk-abcdefghijklmnopqrstuvwxyz123456\n",
    )
    findings = scan_policy(tmp_path, ["src"], ["tests"])
    assert any(
        item.code == "BHCFG003" and item.severity == "error" for item in findings
    )


# trace:v1 id=test.tests-test-policy-metrics.test-policy-flags-private-and-persistence-implementation-cross-layer-imports work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_policy_flags_private_and_persistence_implementation_cross_layer_imports(
    tmp_path: Path,
) -> None:
    src = _pkg(tmp_path)
    api = src / "api"
    api.mkdir()
    (api / "__init__.py").write_text("")
    (api / "routes.py").write_text(
        "from demo.persistence.sqlite_impl import Connection\n"
        "from demo._internal import helper\n",
    )
    findings = scan_policy(tmp_path, ["src"], ["tests"])
    codes = {item.code for item in findings}
    assert "BHPERS001" in codes
    assert "BHARCH001" in codes


# trace:v1 id=test.tests-test-policy-metrics.test-export-import-pair-requires-roundtrip-test work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_export_import_pair_requires_roundtrip_test(tmp_path: Path) -> None:
    src = _pkg(tmp_path)
    (src / "formats.py").write_text(
        "def export_project(value: str) -> bytes:\n    return value.encode()\n\n"
        "def import_project(value: bytes) -> str:\n    return value.decode()\n",
    )
    findings = scan_policy(tmp_path, ["src"], ["tests"])
    assert any(item.code == "BHRT001" for item in findings)
    (tmp_path / "tests" / "test_formats.py").write_text(
        "from demo.formats import export_project, import_project\n\n"
        "def test_roundtrip() -> None:\n"
        "    assert import_project(export_project('x')) == 'x'\n",
    )
    findings = scan_policy(tmp_path, ["src"], ["tests"])
    assert not any(item.code == "BHRT001" for item in findings)


# trace:v1 id=test.tests-test-policy-metrics.test-implementation-coupled-mock-sequence-is-flagged work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_implementation_coupled_mock_sequence_is_flagged(tmp_path: Path) -> None:
    _pkg(tmp_path)
    (tmp_path / "tests" / "test_calls.py").write_text(
        "def test_internal_order(mock):\n    mock.assert_has_calls([])\n",
    )
    findings = scan_policy(tmp_path, ["src"], ["tests"])
    assert any(item.code == "BHTEST002" for item in findings)


# trace:v1 id=test.tests-test-policy-metrics.test-metrics-enforce-cyclomatic-loc-and-abc-budgets work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_metrics_enforce_cyclomatic_loc_and_abc_budgets(tmp_path: Path) -> None:
    src = _pkg(tmp_path)
    (tmp_path / "bughunt.toml").write_text(
        "[complexity]\n"
        "cyclomatic_warn=2\ncyclomatic_error=4\n"
        "function_loc_warn=5\nfunction_loc_error=20\n"
        "file_loc_warn=8\nfile_loc_error=100\n"
        "abc_warn=2\nabc_error=10\n",
    )
    (src / "complex.py").write_text(
        "def f(x: int) -> int:\n"
        "    total = 0\n"
        "    if x > 0:\n"
        "        total += abs(x)\n"
        "    if x > 10:\n"
        "        total += max(x, 1)\n"
        "    return total\n"
        "\n"
        "VALUE = 1\n",
    )
    findings = scan_metrics(tmp_path, ["src"])
    codes = {item.code for item in findings}
    assert "BHCX001" in codes
    assert "BHCX002" in codes
    assert "BHCX003" in codes
    assert "BHCX004" in codes


# trace:v1 id=test.tests-test-policy-metrics.test-metrics-enforce-built-asset-budget work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_metrics_enforce_built_asset_budget(tmp_path: Path) -> None:
    _pkg(tmp_path)
    (tmp_path / "bughunt.toml").write_text(
        "[complexity]\njs_file_kb_warn=1\nbundle_kb_warn=1\n",
    )
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "app.js").write_bytes(b"x" * 2048)
    findings = scan_metrics(tmp_path, ["src"])
    codes = {item.code for item in findings}
    assert "BHCX005" in codes
    assert "BHCX006" in codes


# trace:v1 id=test.tests-test-policy-metrics.test-env-example-documents-inferred-numeric-range work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_env_example_documents_inferred_numeric_range(tmp_path: Path) -> None:
    src = _pkg(tmp_path)
    (src / "settings.py").write_text(
        "import os\n"
        "PORT = int(os.getenv('PORT', '8000'))\n"
        "if not (1 <= PORT <= 65535):\n"
        "    raise ValueError('bad port')\n",
    )
    path, uses = ensure_env_example(tmp_path, ["src"])
    assert path is not None
    text = path.read_text()
    assert "accepted range: >=1 and <=65535" in text
    assert (
        next(item for item in uses if item.name == "PORT").accepted_range
        == ">=1 and <=65535"
    )


# trace:v1 id=test.tests-test-policy-metrics.test-finally-jump-is-default-builtin-error work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_finally_jump_is_default_builtin_error(tmp_path: Path) -> None:
    src = _pkg(tmp_path)
    (src / "danger.py").write_text(
        "def f() -> int:\n"
        "    try:\n"
        "        raise RuntimeError('boom')\n"
        "    finally:\n"
        "        return 1\n",
    )
    findings = scan_policy(tmp_path, ["src"], ["tests"])
    item = next(item for item in findings if item.code == "BHCTRL001")
    assert item.severity == "error"
    assert "finally" in item.message


# trace:v1 id=test.tests-test-policy-metrics.test-operational-keyword-literal-is-configuration-note work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_operational_keyword_literal_is_configuration_note(tmp_path: Path) -> None:
    src = _pkg(tmp_path)
    (src / "worker.py").write_text(
        "def call(**kwargs):\n    return kwargs\n\n"
        "def run():\n    return call(timeout=30, retries=4)\n",
    )
    findings = scan_policy(tmp_path, ["src"], ["tests"])
    hits = [item for item in findings if item.code == "BHCFG005"]
    assert len(hits) == 2
    assert all(item.severity == "note" for item in hits)


# trace:v1 id=test.tests-test-policy-metrics.test-one-sided-export-is-reported-as-roundtrip-contract-gap work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_one_sided_export_is_reported_as_roundtrip_contract_gap(tmp_path: Path) -> None:
    src = _pkg(tmp_path)
    (src / "formats.py").write_text(
        "def export_project(value: str) -> bytes:\n    return value.encode()\n",
    )
    findings = scan_policy(tmp_path, ["src"], ["tests"])
    assert any(
        item.code == "BHRT002" and "import_project" in item.message for item in findings
    )


# trace:v1 id=test.tests-test-policy-metrics.test-persistence-type-exposed-from-upper-layer-signature-is-flagged work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_persistence_type_exposed_from_upper_layer_signature_is_flagged(
    tmp_path: Path,
) -> None:
    src = _pkg(tmp_path)
    api = src / "api"
    api.mkdir()
    (api / "__init__.py").write_text("")
    (api / "service.py").write_text(
        "from sqlalchemy.orm import Session\n"
        "def fetch(session: Session) -> str:\n"
        "    return 'x'\n",
    )
    findings = scan_policy(tmp_path, ["src"], ["tests"])
    assert any(item.code == "BHPERS002" for item in findings)


# trace:v1 id=test.tests-test-policy-metrics.test-generated-source-exact-string-assertion-is-flagged work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_generated_source_exact_string_assertion_is_flagged(tmp_path: Path) -> None:
    _pkg(tmp_path)
    expected = "x" * 250
    (tmp_path / "tests" / "test_codegen.py").write_text(
        "def test_codegen():\n"
        f"    generated_source = 'actual'\n    assert generated_source == "
        f"{expected!r}\n",
    )
    findings = scan_policy(tmp_path, ["src"], ["tests"])
    assert any(item.code == "BHTEST005" for item in findings)


# trace:v1 id=test.tests-test-policy-metrics.test-unit-suffix-rules work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_unit_suffix_rules(tmp_path: Path) -> None:
    src = _pkg(tmp_path)
    (src / "timing.py").write_text(
        "timeout = 10\n"
        "timeout_ms = 5000\n"
        "retries = 3\n"
        "total = deadline_ms + grace_s\n"
        "backoff_s = backoff_ms / 1000\n"
        "timeout_ms = 5\n"
        "timeout_s = 1\n",
    )
    findings = scan_policy(tmp_path, ["src"], ["tests"])
    by_code = {}
    for item in findings:
        by_code.setdefault(item.code, []).append(item)
    assert len(by_code.get("BHUNIT001", [])) == 1
    assert len(by_code.get("BHUNIT002", [])) == 1
    assert len(by_code.get("BHUNIT003", [])) >= 1


# trace:v1 id=test.tests-test-policy-metrics.test-unit-rules-ignore-idiom work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_unit_rules_ignore_idiom(tmp_path: Path) -> None:
    src = _pkg(tmp_path)
    (src / "ok.py").write_text(
        "import subprocess\n"
        "size = len(items)\n"
        "backoff_ms = backoff_ms * 2\n"
        "if elapsed_ms > 0:\n"
        "    subprocess.run(cmd, timeout=10)\n",
    )
    findings = scan_policy(tmp_path, ["src"], ["tests"])
    assert not [item for item in findings if (item.code or "").startswith("BHUNIT")]
