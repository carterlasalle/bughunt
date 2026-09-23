# Copyright (c) 2026 Carter LaSalle
"""Data-invariant rules: missingness, derived columns, intervals, artifacts."""

from pathlib import Path

from tests.conftest import serialized


def _scan(tmp_path: Path, source: str):
    from bughunt.data_scan import scan

    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    _ = (src / "mod.py").write_text(source)
    return scan(tmp_path, ["src"])


def test_miss_into_integrator(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        'import pandas as pd\ndef f(df):\n    vals = pd.to_numeric(df["uv_index"], errors="coerce").fillna(0)\n    return integrate_tandose(df["t"], vals)\n',
    )
    assert [item.code for item in findings] == ["BHMISS001"]


def test_fillna_without_sink_is_quiet(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        'import pandas as pd\ndef f(df):\n    return df["x"].fillna(0)\n',
    )
    assert findings == []


def test_stale_derived_column(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        'def f(out):\n    out["pigment"] = out["uva"] + out["uvb"]\n    out["uva"] = out["uva"] * 1.6\n    return out\n',
    )
    assert [item.code for item in findings] == ["BHDF001"]


def test_recomputed_column_is_quiet(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        'def f(out):\n    out["pigment"] = out["uva"] + out["uvb"]\n    out["uva"] = out["uva"] * 1.6\n    out["pigment"] = out["uva"] + out["uvb"]\n    return out\n',
    )
    assert findings == []


def test_half_open_into_integrator(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        'def f(df, start, end):\n    mask = (df["t"] >= start) & (df["t"] < end)\n    return integrate_tandose(df["t"][mask], df["v"][mask])\n',
    )
    assert [item.code for item in findings] == ["BHINT001"]


def test_closed_mask_is_quiet(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        'def f(df, start, end):\n    mask = (df["t"] >= start) & (df["t"] <= end)\n    return integrate_tandose(df["t"][mask], df["v"][mask])\n',
    )
    assert findings == []


def test_trailing_as_forward(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "def f(tan_dose_30m_j_m2):\n    best_30m_start = tan_dose_30m_j_m2\n    return best_30m_start\n",
    )
    assert [item.code for item in findings] == ["BHINT002"]


def test_local_as_utc(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "def f(local_times):\n    return pd.to_datetime(local_times, utc=True)\n",
    )
    assert [item.code for item in findings] == ["BHTIME002"]


def test_localized_is_quiet(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "def f(s):\n    loc = s.dt.tz_localize('US/Eastern')\n    return pd.to_datetime(loc, utc=True)\n",
    )
    assert [item.code for item in findings if item.code == "BHTIME002"] == []


def test_contradictory_metadata(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        'def f(dose_val):\n    return {"dose": dose_val, "complete": True, "coverage": 1.0}\n',
    )
    assert [item.code for item in findings] == ["BHMETA001"]


def test_predicate_contradiction(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        'def a(tier):\n    if tier == "provisional":\n        raise ValueError("bad")\n    return True\ndef b(tier):\n    if tier != "canonical":\n        raise ValueError("bad")\n    return True\n',
    )
    assert [item.code for item in findings] == ["BHINV001"]


def test_matching_predicates_quiet(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        'def a(tier):\n    if tier != "canonical":\n        raise ValueError("bad")\n    return True\ndef b(tier):\n    if tier != "canonical":\n        raise ValueError("bad")\n    return True\n',
    )
    assert findings == []


def test_artifact_before_validation(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        'def f(root):\n    import pickle\n    data = pickle.load(open(root / "local_reference.parquet", "rb"))\n    return data\n',
    )
    assert "BHART001" in [item.code for item in findings]


def test_quality_metadata_gap(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "def build(sed_day_total, sed_complete):\n"
        '    return {"sed_day_total": sed_day_total}\n',
    )
    assert "BHMETA002" in [item.code for item in findings]


def test_quality_complete_is_quiet(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "def build(sed_day_total, sed_complete):\n"
        '    return {"sed_day_total": sed_day_total, "sed_complete": sed_complete}\n',
    )
    assert "BHMETA002" not in [item.code for item in findings]


# trace:v1 id=test.tests-test-data-scan.test-main-contract work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
@serialized
def test_main_contract(tmp_path: Path, capsys) -> None:
    import json

    from bughunt import data_scan

    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    _ = (src / "a.py").write_text("x = 1\n")
    assert data_scan.main([str(tmp_path), "src"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload == {"findings": []}
