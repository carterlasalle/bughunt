# Copyright (c) 2026 Carter LaSalle
"""Graph facts: normalization, confidence, malformed payloads."""

import json
from pathlib import Path

from bughunt.graph.facts import load


def _payload() -> dict:
    return {
        "system_ir": {
            "relationships": [
                {
                    "predicate": "calls",
                    "subject": "repo://r/symbol/a.py/main",
                    "object": "repo://r/symbol/a.py/helper",
                    "confidence": 0.9,
                },
                {
                    "predicate": "calls",
                    "subject": "repo://r/symbol/a.py/main",
                    "object": "repo://r/symbol/a.py/helper",
                    "confidence": "high",
                },
                {
                    "predicate": "crosses_boundary",
                    "subject": "repo://r/symbol/a.py/main",
                    "object": "repo://r/external_api/time.sleep",
                    "confidence": 0.9,
                },
                {
                    "predicate": "tested_by",
                    "subject": "repo://r/symbol/a.py/main",
                    "object": "repo://r/test/tests/test-a.py/test-main",
                    "confidence": 0.65,
                },
                {"predicate": "contains", "subject": "x", "object": "y"},
                "nope",
            ],
            "evidence": [
                {"symbol": "main", "start_line": 10},
                {"symbol": "main", "start_line": "ten"},
                "nope",
            ],
        }
    }


# trace:v1 id=test.tests-test-graph-facts.test-load-normalizes work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_load_normalizes(tmp_path: Path) -> None:
    cache = tmp_path / "system-ir.json"
    cache.write_text(json.dumps(_payload()))
    facts = load(cache)
    assert len(facts.calls) == 1
    edge = facts.calls[0]
    assert (edge.caller.file, edge.caller.name) == ("a.py", "main")
    assert (edge.callee.file, edge.callee.name) == ("a.py", "helper")
    assert facts.calls_from["repo://r/symbol/a.py/main"] == [edge]
    assert facts.calls_to["repo://r/symbol/a.py/helper"] == [edge]
    assert facts.sinks[0].external == "time.sleep"
    assert facts.tests[0].test == "test-main"
    assert facts.evidence_lines == {"main": 10}


# trace:v1 id=test.tests-test-graph-facts.test-load-malformed work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def test_load_malformed(tmp_path: Path) -> None:
    assert load(tmp_path / "missing.json").calls == []
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert load(bad).calls == []
    lst = tmp_path / "list.json"
    lst.write_text("[1, 2]")
    assert load(lst).calls == []
    empty = tmp_path / "empty.json"
    empty.write_text("{}")
    assert load(empty).calls == []
