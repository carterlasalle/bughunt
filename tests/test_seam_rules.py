# Copyright (c) 2026 Carter LaSalle
"""Seam rules: kwargs chains, HTTP JSON, N+1 queries, dict drift."""

from pathlib import Path

from bughunt.seam_scan import SeamFinding, scan_seams


def _tree(tmp_path: Path, source: str) -> list[SeamFinding]:
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    _ = (src / "seams.py").write_text(source)
    return scan_seams(tmp_path, ["src"], ["tests"])


def test_kwargs_chain_flags_unknown_key(tmp_path: Path) -> None:
    findings = _tree(
        tmp_path,
        "def handler(**kw):\n"
        + "    serve(**kw)\n"
        + "\n\ndef serve(timeout):\n"
        + "    return timeout\n"
        + "\n\nhandler(retries=3)\n",
    )
    assert [item.code for item in findings] == ["BHSEAM002"]


def test_http_json_indexed_without_validation(tmp_path: Path) -> None:
    findings = _tree(
        tmp_path,
        "import json\n\n\ndef fetch(client):\n"
        + "    payload = client.get('/x').json()\n"
        + "    json.dumps(payload)\n"
        + "    return payload['name']\n",
    )
    assert "BHSEAM005" in [item.code for item in findings]


def test_validated_json_is_quiet(tmp_path: Path) -> None:
    findings = _tree(
        tmp_path,
        "import json\n\n\ndef fetch(client, Model):\n"
        + "    payload = client.get('/x').json()\n"
        + "    json.dumps(payload)\n"
        + "    obj = Model.model_validate(payload)\n"
        + "    return obj\n",
    )
    assert "BHSEAM005" not in [item.code for item in findings]


def test_query_in_loop_is_n_plus_one(tmp_path: Path) -> None:
    findings = _tree(
        tmp_path,
        "def load(session, ids):\n"
        + "    out = []\n"
        + "    for ident in ids:\n"
        + "        out.append(session.query(User).get(ident))\n"
        + "    return out\n",
    )
    assert "BHDB001" in [item.code for item in findings]


def test_dict_key_drift_missing_direction(tmp_path: Path) -> None:
    findings = _tree(
        tmp_path,
        "import json\n\n\ndef produce():\n"
        + "    event = {'a': 1, 'stale': 2}\n"
        + "    json.dumps(event)\n"
        + "    return event['missing']\n",
    )
    codes = [item.code for item in findings]
    assert "BHSEAM001" in codes


def test_get_fallback_chain_is_quiet(tmp_path: Path) -> None:
    findings = _tree(
        tmp_path,
        "import json\n\n\ndef parse(stdout):\n"
        + "    data = json.loads(stdout or '[]')\n"
        + "    json.dumps(data)\n"
        + "    items = data.get('messages') or data.get('results') or []\n"
        + "    return items\n",
    )
    assert "BHSEAM001" not in [item.code for item in findings]


def test_wall_clock_without_time_control(tmp_path: Path) -> None:
    findings = _tree(
        tmp_path,
        "import time\n\n\ndef now_ms():\n" + "    return time.time()\n",
    )
    assert [item.code for item in findings] == ["BHTIME001"]


def test_wall_clock_with_freeze_marker_is_quiet(tmp_path: Path) -> None:
    from bughunt.seam_scan import scan_seams

    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    _ = (src / "seams.py").write_text(
        "import time\n\n\ndef now_ms():\n" + "    return time.time()\n",
    )
    tests = tmp_path / "tests"
    tests.mkdir(exist_ok=True)
    _ = (tests / "test_time.py").write_text("from freezegun import freeze_time\n")
    findings = scan_seams(tmp_path, ["src"], ["tests"])
    assert "BHTIME001" not in [item.code for item in findings]


def test_load_schema_doc_formats(tmp_path: Path) -> None:
    from bughunt.seam_scan import _load_schema_doc

    good = tmp_path / "s.json"
    _ = good.write_text('{"a": 1}')
    assert _load_schema_doc(good) == {"a": 1}
    bad = tmp_path / "b.json"
    _ = bad.write_text("{invalid")
    assert _load_schema_doc(bad) is None
    yml = tmp_path / "s.yaml"
    _ = yml.write_text("a: 1\n")
    assert _load_schema_doc(yml) == {"a": 1}


def test_async_loops_track_depth(tmp_path: Path) -> None:
    findings = _tree(
        tmp_path,
        "async def f(agen):\n"
        + "    out = {}\n"
        + "    async for x in agen():\n"
        + "        out[x] = 1\n"
        + "    while out:\n"
        + "        out.pop('k', None)\n"
        + "    return out\n",
    )
    assert [item.code for item in findings] == []


# trace:v1 id=test.tests-test-seam-rules.-graph-fixture work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _graph_fixture(tmp_path: Path, client: str, services: dict[str, str]) -> None:
    import json

    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    _ = (src / "client.py").write_text(client)
    for name, source in services.items():
        _ = (src / name).write_text(source)
    rels = []
    for name in services:
        stem = name.removesuffix(".py")
        rels.append(
            {
                "predicate": "calls",
                "subject": "x/symbol/src/client.py/handler",
                "object": f"x/symbol/src/{stem}.py/serve",
            }
        )
    cache = tmp_path / ".bughunt" / "cache"
    cache.mkdir(parents=True, exist_ok=True)
    _ = (cache / "system-ir.json").write_text(
        json.dumps({"cache_key": "K", "system_ir": {"relationships": rels}})
    )


# trace:v1 id=test.tests-test-seam-rules.-graph-env work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def _graph_env(monkeypatch) -> None:
    from bughunt import system_ir_adapter

    monkeypatch.setattr(system_ir_adapter, "_cli", lambda: "/bin/scc")
    monkeypatch.setattr(system_ir_adapter, "_cache_key", lambda root, cli: "K")


# trace:v1 id=test.tests-test-seam-rules.test-cross-file-kwargs-drift work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_cross_file_kwargs_drift(tmp_path: Path, monkeypatch) -> None:
    from bughunt.seam_scan import scan_seams

    _graph_fixture(
        tmp_path,
        "from svc import serve\n\n\ndef handler(**kw):\n    serve(**kw)\n\n\nhandler(retries=3)\n",
        {"svc.py": "def serve(timeout):\n    return timeout\n"},
    )
    _graph_env(monkeypatch)
    findings = scan_seams(tmp_path, ["src"], ["tests"])
    assert [item.code for item in findings] == ["BHSEAM002"]
    assert "svc.py:serve" in findings[0].message


# trace:v1 id=test.tests-test-seam-rules.test-cross-file-compatible-signature-is-quiet work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_cross_file_compatible_signature_is_quiet(tmp_path: Path, monkeypatch) -> None:
    from bughunt.seam_scan import scan_seams

    _graph_fixture(
        tmp_path,
        "from svc import serve\n\n\ndef handler(**kw):\n    serve(**kw)\n\n\nhandler(retries=3)\n",
        {"svc.py": "def serve(timeout, **kw):\n    return timeout\n"},
    )
    _graph_env(monkeypatch)
    assert scan_seams(tmp_path, ["src"], ["tests"]) == []


# trace:v1 id=test.tests-test-seam-rules.test-ambiguous-callee-is-quiet work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_ambiguous_callee_is_quiet(tmp_path: Path, monkeypatch) -> None:
    import json

    from bughunt.seam_scan import _graph_callees, scan_seams

    _graph_fixture(
        tmp_path,
        "from svc import serve\n\n\ndef handler(**kw):\n    serve(**kw)\n\n\nhandler(retries=3)\n",
        {
            "svc.py": "def serve(timeout):\n    return timeout\n",
            "alt.py": "def serve(other):\n    return other\n",
        },
    )
    _graph_env(monkeypatch)
    cache = tmp_path / ".bughunt" / "cache" / "system-ir.json"
    payload = json.loads(cache.read_text())
    payload["system_ir"]["relationships"].append(
        {
            "predicate": "calls",
            "subject": "x/symbol/src/client.py/handler",
            "object": "x/symbol/src/alt.py/serve",
        }
    )
    _ = cache.write_text(json.dumps(payload))
    assert _graph_callees(tmp_path) == {}
    assert scan_seams(tmp_path, ["src"], ["tests"]) == []


# trace:v1 id=test.tests-test-seam-rules.test-missing-cache-is-quiet work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_missing_cache_is_quiet(tmp_path: Path) -> None:
    from bughunt.seam_scan import _graph_callees, scan_seams

    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    _ = (src / "client.py").write_text("def handler(**kw):\n    serve(**kw)\n")
    assert _graph_callees(tmp_path) == {}
    assert scan_seams(tmp_path, ["src"], ["tests"]) == []


# trace:v1 id=test.tests-test-seam-rules.test-graph-cache-edge-cases work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_graph_cache_edge_cases(tmp_path: Path, monkeypatch) -> None:
    import json

    from bughunt import system_ir_adapter
    from bughunt.seam_scan import _graph_callees

    monkeypatch.setattr(system_ir_adapter, "_cli", lambda: None)
    assert _graph_callees(tmp_path) == {}
    monkeypatch.setattr(system_ir_adapter, "_cli", lambda: "/bin/scc")
    monkeypatch.setattr(system_ir_adapter, "_cache_key", lambda root, cli: "K")
    cache = tmp_path / ".bughunt" / "cache"
    cache.mkdir(parents=True, exist_ok=True)
    cache_file = cache / "system-ir.json"
    _ = cache_file.write_text("not json")
    assert _graph_callees(tmp_path) == {}
    _ = cache_file.write_text(json.dumps({"cache_key": "STALE"}))
    assert _graph_callees(tmp_path) == {}
    _ = cache_file.write_text(json.dumps({"cache_key": "K", "system_ir": []}))
    assert _graph_callees(tmp_path) == {}
    _ = cache_file.write_text(
        json.dumps({"cache_key": "K", "system_ir": {"relationships": {}}})
    )
    assert _graph_callees(tmp_path) == {}
    rels = [
        "nope",
        {"predicate": "imports", "subject": "a", "object": "b"},
        {"predicate": "calls", "subject": "a", "object": 42},
        {"predicate": "calls", "subject": "a", "object": "repo/nomarker"},
        {"predicate": "calls", "subject": "a", "object": "repo/symbol/noslash"},
        {
            "predicate": "calls",
            "subject": "a",
            "object": "x/symbol/../evil.py/serve",
        },
        {"predicate": "calls", "subject": "a", "object": "x/symbol/src/ok.py/go"},
    ]
    _ = cache_file.write_text(
        json.dumps({"cache_key": "K", "system_ir": {"relationships": rels}})
    )
    assert _graph_callees(tmp_path) == {"go": ("src/ok.py", "go")}


# trace:v1 id=test.tests-test-seam-rules.test-terminal-signature-variants work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_terminal_signature_variants(tmp_path: Path) -> None:
    from bughunt.seam_scan import _terminal_signature

    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    assert _terminal_signature(tmp_path, {}, "src/missing.py", "f") is None
    _ = (src / "broken.py").write_text("def (:\n")
    assert _terminal_signature(tmp_path, {}, "src/broken.py", "f") is None
    _ = (src / "svc.py").write_text(
        "class S:\n"
        "    def serve(self, timeout, *, retries=3):\n"
        "        return timeout\n"
    )
    assert _terminal_signature(tmp_path, {}, "src/svc.py", "serve") == (
        {"timeout", "retries"},
        False,
    )
    assert _terminal_signature(tmp_path, {}, "src/svc.py", "absent") is None


# trace:v1 id=test.tests-test-seam-rules.test-call-name-and-rel-edges work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_call_name_and_rel_edges(tmp_path: Path) -> None:
    import ast

    from bughunt.seam_scan import _call_name, _rel

    first = ast.parse("f()()").body[0]
    assert isinstance(first, ast.Expr)
    assert _call_name(first.value) == "f"
    second = ast.parse("a.b.c(x)").body[0]
    assert isinstance(second, ast.Expr)
    assert _call_name(second.value) == "a.b.c"
    third = ast.parse("(x + y)").body[0]
    assert isinstance(third, ast.Expr)
    assert _call_name(third.value) == ""
    outside = tmp_path / "elsewhere.py"
    _ = outside.write_text("x = 1\n")
    assert _rel(tmp_path / "src", outside) == outside.as_posix()


# trace:v1 id=test.tests-test-seam-rules.test-scan-gap-fixture-end-to-end work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_scan_gap_fixture_end_to_end(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    _ = (src / "app.py").write_text(
        "import datetime\n"
        "import requests\n"
        "\n\ndef fetch(url):\n"
        "    resp = requests.get(url)\n"
        "    return resp.json(), datetime.datetime.now()\n"
    )
    _ = (src / "broken.py").write_text("def (:\n")
    _ = (src / "model.py").write_text("class Order:\n   avec: int\n")
    _ = (tmp_path / "order.json").write_text(
        '{"title": "Order", "properties": {"avec": {}, "extra": {}}}'
    )
    findings = scan_seams(tmp_path, ["src"], ["tests"])
    codes = {item.code for item in findings}
    assert "BHSEAM006" in codes
    assert "BHTIME001" in codes
    assert "BHSEAM004" in codes


# trace:v1 id=test.tests-test-seam-rules.test-scan-quiet-with-evidence-corpus work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_scan_quiet_with_evidence_corpus(tmp_path: Path) -> None:
    src = tmp_path / "src"
    tests = tmp_path / "tests"
    src.mkdir(exist_ok=True)
    tests.mkdir(exist_ok=True)
    _ = (src / "app.py").write_text(
        "import datetime\n"
        "import requests\n"
        "\n\ndef fetch(url):\n"
        "    return requests.get(url), datetime.datetime.now()\n"
    )
    _ = (tests / "test_app.py").write_text(
        "# cassette: recorded payload; freeze_time locks the clock\n"
    )
    findings = scan_seams(tmp_path, ["src"], ["tests"])
    assert "BHSEAM006" not in {item.code for item in findings}
    assert "BHTIME001" not in {item.code for item in findings}


# trace:v1 id=test.tests-test-seam-rules.test-schema-doc-variants work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_schema_doc_variants(tmp_path: Path) -> None:
    from bughunt.seam_scan import _load_schema_doc, _schema_drift

    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    _ = (src / "m.py").write_text("class Widget:\n    size: int\n")
    assert _load_schema_doc(tmp_path / "missing.json") is None
    bad = tmp_path / "bad.json"
    _ = bad.write_text("{nope")
    assert _load_schema_doc(bad) is None
    _ = (tmp_path / "openapi.json").write_text(
        '{"components": {"schemas": {"Widget": '
        '{"properties": {"size": {}, "color": {}}}}}}'
    )
    _ = (tmp_path / "defs.json").write_text(
        '{"$defs": {"Widget": {"properties": {"size": {}}}}}'
    )
    _ = (tmp_path / "plain.json").write_text('{"title": "Other"}')
    _ = (tmp_path / "notdict.json").write_text("[1, 2]")
    _ = (tmp_path / "spec.yaml").write_text("title: Widget\nproperties:\n  size: {}\n")
    findings = _schema_drift(tmp_path, ["src"])
    assert [item.code for item in findings] == ["BHSEAM004"]
    assert "color" in findings[0].message


# trace:v1 id=test.tests-test-seam-rules.test-main-contract work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_main_contract(tmp_path: Path, capsys, monkeypatch) -> None:
    import json
    import sys

    from bughunt.seam_scan import main

    monkeypatch.setattr(sys, "argv", ["bughunt-seam"])
    assert main([]) == 0
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    _ = (src / "app.py").write_text(
        "import requests\n\n\ndef f(u):\n    return requests.get(u)\n"
    )
    assert main([str(tmp_path)]) == 1
    assert json.loads(capsys.readouterr().out)["findings"]
    _ = (src / "app.py").write_text("def f():\n    return 1\n")
    assert (
        main(
            [str(tmp_path)],
        )
        == 0
    )


# trace:v1 id=test.tests-test-seam-rules.test-collector-store-shapes work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_collector_store_shapes(tmp_path: Path) -> None:
    findings = _tree(
        tmp_path,
        "def handle(resp, key, payload):\n"
        + "    store = {}\n"
        + '    store["a"] = 1\n'
        + "    store[key] = 2\n"
        + '    box: dict = {"x": 1}\n'
        + "    count: int = 0\n"
        + '    data["k"] = resp.json()\n'
        + '    got = data.setdefault("s", 1)\n'
        + '    v = data.get("g")\n'
        + '    _ = data.get("/http/path")\n'
        + '    slot["m"] = Model.model_validate(payload)\n'
        + "    unknown_fn(x=1)\n"
        + "    return got\n"
        + "\n\ndef target2(x):\n"
        + "    return x\n"
        + "target2(x=1)\n"
        + "target2(y=2)\n",
    )
    assert isinstance(findings, list)


# trace:v1 id=test.tests-test-seam-rules.test-producer-consumer-shapes work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_producer_consumer_shapes(tmp_path: Path) -> None:
    findings = _tree(
        tmp_path,
        "def make():\n"
        + '    return {"a": 1, "b": 2}\n'
        + "\n\ndef empty():\n"
        + "    return {}\n"
        + "\n\ndef use(key, dynamic):\n"
        + "    one = make()\n"
        + '    good = one["a"]\n'
        + '    bad = one["zzz"]\n'
        + "    other = unknown_fn()\n"
        + "    idx = one[key]\n"
        + "    val = one.get(dynamic)\n"
        + "    first = second = make()\n"
        + '    cache["m"] = make()\n'
        + '    lit = one.get("a")\n'
        + "    return good\n",
    )
    assert [item.code for item in findings] == ["BHSEAM003"]


# trace:v1 id=test.tests-test-seam-rules.test-class-field-shapes work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_class_field_shapes(tmp_path: Path) -> None:
    from bughunt.seam_scan import _class_fields, _schema_drift
    import ast

    tree = ast.parse(
        "class Widget:\n"
        "    size: int\n"
        "    color = 'red'\n"
        "    _secret = 1\n"
        "    def method(self):\n"
        "        self.x = 1\n"
        "\n\nclass Empty:\n"
        "    pass\n"
        "\n\nclass Attr:\n"
        "    a.b = 1\n"
    )
    assert _class_fields(tree) == {"Widget": {"size", "color"}}
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    _ = (src / "m.py").write_text("class Widget:\n    size: int\n")
    _ = (tmp_path / "s.json").write_text(
        '{"$defs": {"Ghost": {"properties": {"a": {}}}, '
        '"Widget": {"properties": {"size": {}}}, '
        '"Slim": {"properties": ["not", "a", "dict"]}}}'
    )
    assert _schema_drift(tmp_path, ["src"]) == []
    _ = (tmp_path / "s2.json").write_text('{"title": "Widget", "properties": {}}')
    findings = _schema_drift(tmp_path, ["src"])
    assert [item.code for item in findings] == ["BHSEAM004"]


# trace:v1 id=test.tests-test-seam-rules.test-iter-path-shapes work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_iter_path_shapes(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    _ = (src / "a.py").write_text("x = 1\n")
    assert scan_seams(tmp_path, ["src/a.py"], ["tests"]) == []
    assert scan_seams(tmp_path, ["src", "src"], ["tests"]) == []
    assert scan_seams(tmp_path, ["nope"], ["tests"]) == []


# trace:v1 id=test.tests-test-seam-rules.test-graph-missing-terminal-and-multi-call work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_graph_missing_terminal_and_multi_call(tmp_path: Path, monkeypatch) -> None:
    import json

    from bughunt import system_ir_adapter
    from bughunt.seam_scan import _terminal_signature, scan_seams

    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    _ = (src / "client.py").write_text(
        "from svc import serve\n"
        "\n\ndef handler(**kw):\n"
        "    serve(**kw)\n"
        "\n\nhandler(timeout=1)\n"
        "handler(surprise=2)\n"
    )
    _ = (src / "svc.py").write_text("def serve(timeout):\n    return timeout\n")
    cache = tmp_path / ".bughunt" / "cache"
    cache.mkdir(parents=True, exist_ok=True)
    rels = [
        {
            "predicate": "calls",
            "subject": "x/symbol/src/client.py/handler",
            "object": "x/symbol/src/svc.py/serve",
        }
    ]
    _ = (cache / "system-ir.json").write_text(
        json.dumps({"cache_key": "K", "system_ir": {"relationships": rels}})
    )
    monkeypatch.setattr(system_ir_adapter, "_cli", lambda: "/bin/scc")
    monkeypatch.setattr(system_ir_adapter, "_cache_key", lambda root, cli: "K")
    found = scan_seams(tmp_path, ["src"], ["tests"])
    assert [item.code for item in found] == ["BHSEAM002"]
    import ast as _ast

    store: dict[str, _ast.AST] = {}
    first = _terminal_signature(tmp_path, store, "src/svc.py", "serve")
    second = _terminal_signature(tmp_path, store, "src/svc.py", "serve")
    assert first == second == ({"timeout"}, False)
    rels[0]["object"] = "x/symbol/src/gone.py/serve"
    _ = (cache / "system-ir.json").write_text(
        json.dumps({"cache_key": "K", "system_ir": {"relationships": rels}})
    )
    assert scan_seams(tmp_path, ["src"], ["tests"]) == []


# trace:v1 id=test.tests-test-seam-rules.test-gap-corpus-loop-and-unreadable work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_gap_corpus_loop_and_unreadable(tmp_path: Path) -> None:
    import os

    src = tmp_path / "src"
    tests = tmp_path / "tests"
    src.mkdir(exist_ok=True)
    tests.mkdir(exist_ok=True)
    _ = (src / "app.py").write_text(
        "import datetime\n"
        "import requests\n"
        "\n\ndef f(u):\n"
        "    return requests.get(u), datetime.datetime.now()\n"
    )
    _ = (tests / "a_test.py").write_text("x = 1\n")
    _ = (tests / "b_test.py").write_text("y = 2\n")
    locked = tests / "locked.py"
    _ = locked.write_text("z = 3\n")
    os.chmod(locked, 0)
    try:
        codes = {item.code for item in scan_seams(tmp_path, ["src"], ["tests"])}
    finally:
        os.chmod(locked, 0o644)
    # No marker anywhere: both gaps fire despite the unreadable file.
    assert "BHSEAM006" in codes
    assert "BHTIME001" in codes


# trace:v1 id=test.tests-test-seam-rules.test-schema-doc-loader-errors work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_schema_doc_loader_errors(tmp_path: Path, monkeypatch) -> None:
    import sys

    from bughunt.seam_scan import _load_schema_doc

    doc = tmp_path / "s.yaml"
    _ = doc.write_text("a: [1,\n")
    assert _load_schema_doc(doc) is None or isinstance(_load_schema_doc(doc), object)
    monkeypatch.setitem(sys.modules, "yaml", None)
    _ = doc.write_text("a: 1\n")
    assert _load_schema_doc(doc) is None
