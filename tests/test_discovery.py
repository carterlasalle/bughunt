from pathlib import Path

from bughunt.discovery import discover_all, discover_schemathesis


# trace:v1 id=test.tests-test-discovery.test-discovers-fastapi-and-parser work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_discovers_fastapi_and_parser(tmp_path: Path):
    src = tmp_path / "src" / "demo"
    src.mkdir(parents=True)
    (src / "__init__.py").write_text("")
    (src / "api.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "def parse_packet(data: bytes):\n"
        "    if not data:\n"
        '        raise ValueError("empty")\n'
        "    return data[0]\n",
    )
    targets = discover_all(
        tmp_path,
        ["src"],
        atheris_runs=123,
        schemathesis_examples=321,
    )
    assert any(
        t.kind == "schemathesis" and t.runnable and t.name == "demo.api.app"
        for t in targets
    )
    fuzz = next(
        t for t in targets if t.kind == "atheris" and t.name == "demo.api.parse_packet"
    )
    assert fuzz.runnable
    assert "-atheris_runs=123" in fuzz.command
    assert "--with" not in fuzz.command
    harness = tmp_path / fuzz.metadata["generated_harness"]
    text = harness.read_text()
    assert "ValueError" in text
    assert fuzz.metadata["seed_count"] >= 6
    api = next(
        t for t in targets if t.kind == "schemathesis" and t.name == "demo.api.app"
    )
    api_harness = (tmp_path / api.metadata["generated_harness"]).read_text()
    assert "max_examples=321" in api_harness
    assert "as_state_machine" in api_harness


# trace:v1 id=test.tests-test-discovery.test-remote-openapi-is-not-auto-run work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_remote_openapi_is_not_auto_run(tmp_path: Path):
    schema = tmp_path / "openapi.json"
    schema.write_text(
        '{"openapi":"3.1.0","info":{"title":"x","version":"1"},"servers":[{"url":"https://api.example.com"}],"paths":{}}',
    )
    targets = discover_schemathesis(tmp_path, ["src"])
    match = next(t for t in targets if t.name == "openapi.json")
    assert not match.runnable
    assert match.kind == "schemathesis-candidate"


# trace:v1 id=test.tests-test-discovery.test-discovers-semantic-custom-campaigns-and-pysa-models work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_discovers_semantic_custom_campaigns_and_pysa_models(tmp_path: Path):
    src = tmp_path / "src" / "demo"
    src.mkdir(parents=True)
    (src / "__init__.py").write_text("")
    (src / "core.py").write_text(
        "import os\n"
        "import subprocess\n"
        "def score_reference(x: int) -> int:\n"
        "    return x * 2\n"
        "def score_fast(x: int) -> int:\n"
        "    return x + x\n"
        "def encode(data: bytes) -> str:\n"
        "    return data.hex()\n"
        "def decode(data: str) -> bytes:\n"
        "    return bytes.fromhex(data)\n"
        "def normalize(value: str) -> str:\n"
        "    return value.strip().lower()\n"
        "def get_input() -> str:\n"
        "    return input()\n"
        "def run_command(cmd: str) -> None:\n"
        "    subprocess.run(cmd)\n"
        "def save_file(path: str, data: str) -> None:\n"
        "    with open(path, 'w') as handle:\n"
        "        handle.write(data)\n",
    )
    targets = discover_all(
        tmp_path,
        ["src"],
        atheris_runs=100,
        schemathesis_examples=100,
    )
    kinds = {target.kind for target in targets}
    assert "custom-differential" in kinds
    assert "custom-roundtrip" in kinds
    assert "custom-idempotence" in kinds
    assert "custom-fault-coverage" in kinds

    registry = __import__("json").loads(
        (tmp_path / ".bughunt/generated/targets.json").read_text(),
    )
    models = registry["pysa_models"]
    assert any(
        model["kind"] == "source" and "get_input" in model["symbol"] for model in models
    )
    assert any(
        model["kind"] == "sink" and "run_command" in model["symbol"] for model in models
    )
    pysa_text = (tmp_path / ".bughunt/configs/pysa/bughunt.pysa").read_text()
    assert "TaintSource[BugHuntUserControlled]" in pysa_text
    assert "TaintSink[BugHuntSensitiveOperation]" in pysa_text


# trace:v1 id=test.tests-test-discovery.test-does-not-invent-differential-oracle-for-io-functions work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_does_not_invent_differential_oracle_for_io_functions(tmp_path: Path):
    src = tmp_path / "src" / "demo"
    src.mkdir(parents=True)
    (src / "__init__.py").write_text("")
    (src / "core.py").write_text(
        "def save_reference(path: str) -> str:\n"
        "    with open(path) as handle:\n"
        "        return handle.read()\n"
        "def save_fast(path: str) -> str:\n"
        "    with open(path) as handle:\n"
        "        return handle.read()\n",
    )
    targets = discover_all(tmp_path, ["src"])
    assert not any(target.kind == "custom-differential" for target in targets)


# trace:v1 id=test.tests-test-discovery.test-discovers-flask-with-explicit-openapi-route work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_discovers_flask_with_explicit_openapi_route(tmp_path: Path):
    src = tmp_path / "src" / "demo"
    src.mkdir(parents=True)
    (src / "__init__.py").write_text("")
    (src / "api.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "@app.route('/openapi.json')\n"
        "def schema():\n"
        "    return {}\n",
    )
    targets = discover_schemathesis(tmp_path, ["src"])
    target = next(t for t in targets if t.name == "demo.api.app")
    assert target.runnable
    assert target.metadata["transport"] == "wsgi"


# trace:v1 id=test.tests-test-discovery.test-atheris-infers-expected-parser-rejections work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_atheris_infers_expected_parser_rejections(tmp_path: Path):
    src = tmp_path / "src" / "demo"
    src.mkdir(parents=True)
    (src / "__init__.py").write_text("")
    (src / "parser.py").write_text(
        "def decode(data: str) -> bytes:\n    return bytes.fromhex(data)\n",
    )
    targets = discover_all(tmp_path, ["src"])
    target = next(
        t for t in targets if t.kind == "atheris" and t.name == "demo.parser.decode"
    )
    assert "ValueError" in target.metadata["explicit_raises"]
    harness = (tmp_path / target.metadata["generated_harness"]).read_text()
    assert "importlib.import_module(owner)" in harness


# trace:v1 id=test.tests-test-discovery.test-export-import-names-generate-real-roundtrip-property-when-pure work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_export_import_names_generate_real_roundtrip_property_when_pure(
    tmp_path: Path,
) -> None:
    src = tmp_path / "src" / "demo"
    src.mkdir(parents=True)
    (src / "__init__.py").write_text("")
    (src / "formats.py").write_text(
        "def export_project(value: str) -> bytes:\n    return value.encode()\n\n"
        "def import_project(value: bytes) -> str:\n    return value.decode()\n",
    )
    targets = discover_all(tmp_path, ["src"])
    target = next(
        t
        for t in targets
        if t.kind == "custom-roundtrip" and "export_project" in t.name
    )
    assert target.runnable
    assert target.confidence == "high"
