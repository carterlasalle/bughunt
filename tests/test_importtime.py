# Copyright (c) 2026 Carter LaSalle
"""Import-time profiler: thresholds, invalid names, failures."""

import json


from tests.conftest import serialized


@serialized
def test_no_modules_is_clean(capsys) -> None:
    from bughunt.importtime_runner import main

    assert main(["1000"]) == 0


@serialized
def test_stdlib_import_under_generous_budget(capsys) -> None:
    from bughunt.importtime_runner import main

    assert main(["60000", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"] == []
    assert payload["samples"][0]["module"] == "json"


@serialized
def test_zero_budget_flags_any_import(capsys) -> None:
    from bughunt.importtime_runner import main

    assert main(["0", "json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"][0]["code"] == "BHPERF001"


@serialized
def test_invalid_module_name_is_finding_not_exec(capsys) -> None:
    from bughunt.importtime_runner import main

    assert main(["1000", "x;evil()"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert "not a valid Python module name" in payload["findings"][0]["message"]


@serialized
def test_missing_module_is_failure_finding(capsys) -> None:
    from bughunt.importtime_runner import main

    assert main(["1000", "no_such_module_xyz"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert "failed during startup profiling" in payload["findings"][0]["message"]


def test_python_flag_profiles_target_interpreter(capsys, tmp_path) -> None:
    """A venv-only module must profile clean under --python, not BHPERF001."""
    import subprocess
    import sys

    from bughunt.importtime_runner import main

    venv = tmp_path / "venv"
    subprocess.run(  # noqa: S603 - audited: fixed argv, tmp venv creation
        [sys.executable, "-m", "venv", str(venv)],
        check=True,
        capture_output=True,
    )
    interp = str(venv / "bin" / "python")
    site = next((venv / "lib").glob("python*/site-packages"))
    pkg = site / "venv_only_pkg"
    pkg.mkdir()
    _ = (pkg / "__init__.py").write_text("VALUE = 1\n")

    # Without the flag the BugHunt interpreter cannot see the module.
    assert main(["1000", "venv_only_pkg"]) == 1
    _ = capsys.readouterr()
    # With the target interpreter the same import profiles clean.
    assert main(["--python", interp, "1000", "venv_only_pkg"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"] == []
    assert payload["samples"][0]["returncode"] == 0


def test_failure_message_leads_with_traceback(capsys) -> None:
    """Failure detail must not start mid-word in `-X importtime` noise."""
    from bughunt.importtime_runner import main

    assert main(["1000", "no_such_module_xyz"]) == 1
    payload = json.loads(capsys.readouterr().out)
    message = payload["findings"][0]["message"]
    assert "Traceback" in message
    assert "ModuleNotFoundError" in message
    assert not message.split("profiling: ", 1)[1].startswith("ime:")


def test_bare_argv_is_clean(monkeypatch) -> None:
    import sys

    from bughunt.importtime_runner import main

    monkeypatch.setattr(sys, "argv", ["bughunt-importtime"])
    assert main([]) == 0
