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
