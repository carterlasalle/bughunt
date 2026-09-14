# Copyright (c) 2026 Carter LaSalle
"""Import-time profiler: thresholds, invalid names, failures."""

import json


def test_no_modules_is_clean(capsys) -> None:
    from bughunt.importtime_runner import main

    assert main(["1000"]) == 0


def test_stdlib_import_under_generous_budget(capsys) -> None:
    from bughunt.importtime_runner import main

    assert main(["60000", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"] == []
    assert payload["samples"][0]["module"] == "json"


def test_zero_budget_flags_any_import(capsys) -> None:
    from bughunt.importtime_runner import main

    assert main(["0", "json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"][0]["code"] == "BHPERF001"


def test_invalid_module_name_is_finding_not_exec(capsys) -> None:
    from bughunt.importtime_runner import main

    assert main(["1000", "x;evil()"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert "not a valid Python module name" in payload["findings"][0]["message"]


def test_missing_module_is_failure_finding(capsys) -> None:
    from bughunt.importtime_runner import main

    assert main(["1000", "no_such_module_xyz"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert "failed during startup profiling" in payload["findings"][0]["message"]


def test_bare_argv_is_clean(monkeypatch) -> None:
    import sys

    from bughunt.importtime_runner import main

    monkeypatch.setattr(sys, "argv", ["bughunt-importtime"])
    assert main([]) == 0
