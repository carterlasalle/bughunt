# Copyright (c) 2026 Carter LaSalle
"""Output parsers: valid samples and malformed-input degradation."""

import json


def test_deal_json_lines_and_fallback() -> None:
    from bughunt.cli import parse_deal

    sample = json.dumps(
        {
            "filename": "a.py",
            "row": 3,
            "col": 1,
            "code": "DEAL001",
            "text": "contract",
        }
    )
    found = parse_deal(sample + "\nnot json\n", "", 1)
    assert found and found[0].code == "DEAL001"
    assert parse_deal("", "", 0) == []


def test_bandit_valid_and_malformed() -> None:
    from bughunt.cli import parse_bandit

    sample = json.dumps(
        {
            "results": [
                {
                    "filename": "a.py",
                    "line_number": 5,
                    "col_offset": 2,
                    "test_id": "B101",
                    "issue_text": "assert",
                    "issue_severity": "LOW",
                }
            ]
        }
    )
    found = parse_bandit(sample, "", 1)
    assert [(item.code, item.severity) for item in found] == [("B101", "low")]
    assert parse_bandit("broken", "", 1) != []


def test_ruff_malformed_falls_back_to_text() -> None:
    from bughunt.cli import parse_ruff

    assert parse_ruff("not json", "boom", 1) != []


def test_ast_grep_valid_shape() -> None:
    import json

    from bughunt.cli import parse_ast_grep

    sample = json.dumps(
        [
            {
                "file": "a.py",
                "ruleId": "R1",
                "message": "hit",
                "range": {"start": {"line": 4, "column": 2}},
            },
            {"file": "b.py"},
        ]
    )
    found = parse_ast_grep(sample, "", 1)
    assert [(item.path, item.line, item.column) for item in found] == [
        ("a.py", 5, 3),
        ("b.py", None, None),
    ]


def test_pylint_dict_form_and_skips() -> None:
    import json

    from bughunt.cli import parse_pylint

    sample = json.dumps(
        {"messages": [{"path": "a.py", "line": 1, "type": "error"}, "junk"]}
    )
    found = parse_pylint(sample, "", 1)
    assert len(found) == 1


def test_pyrefly_dict_unwrap_and_nested() -> None:
    import json

    from bughunt.cli import parse_pyrefly

    sample = json.dumps(
        {
            "errors": [
                {
                    "name": "missing-annotation",
                    "path": {"path": "a.py"},
                    "start": {"start": {"line": 3, "column": 1}},
                },
                "junk",
            ]
        }
    )
    found = parse_pyrefly(sample, "", 1)
    assert [(item.code, item.path, item.line) for item in found] == [
        ("missing-annotation", "a.py", 3)
    ]


def test_ast_grep_valid_and_malformed() -> None:
    from bughunt.cli import parse_ast_grep

    assert parse_ast_grep("broken", "", 1) != []
    assert parse_ast_grep("[]", "", 0) == []


def test_golangci_and_clippy_shapes() -> None:
    from bughunt.cli import parse_clippy, parse_golangci

    go = json.dumps(
        {
            "Issues": [
                {
                    "FromLinter": "govet",
                    "Text": "suspicious",
                    "Pos": {"Filename": "a.go", "Line": 7, "Column": 2},
                }
            ]
        }
    )
    found = parse_golangci(go, "", 1)
    assert [(item.code, item.line) for item in found] == [("govet", 7)]
    clippy = json.dumps(
        {
            "reason": "compiler-message",
            "message": {
                "level": "warning",
                "message": "lint",
                "spans": [
                    {
                        "is_primary": True,
                        "file_name": "a.rs",
                        "line_start": 4,
                        "column_start": 1,
                    }
                ],
            },
        }
    )
    clipped = parse_clippy(clippy + "\n", "", 1)
    assert [(item.path, item.line) for item in clipped] == [("a.rs", 4)]


def test_cppcheck_xml_and_bad_xml() -> None:
    from bughunt.cli import parse_cppcheck

    xml = (
        '<?xml version="1.0"?><results><errors>'
        '<error id="nullPointer" severity="error" verbose="deref" msg="d">'
        '<location file="a.c" line="9" column="3"/></error>'
        "</errors></results>"
    )
    found = parse_cppcheck("", xml, 1)
    assert [(item.code, item.line) for item in found] == [("nullPointer", 9)]
    assert parse_cppcheck("", "not xml", 1) != []


def test_phpstan_files_and_errors() -> None:
    from bughunt.cli import parse_phpstan

    sample = json.dumps(
        {
            "files": {"a.php": {"messages": [{"line": 2, "message": "bad"}]}},
            "errors": ["global boom"],
        }
    )
    found = parse_phpstan(sample, "", 1)
    assert len(found) == 2
    assert parse_phpstan("broken", "", 1) != []


def test_squawk_dict_and_fallback() -> None:
    from bughunt.cli import parse_squawk

    sample = json.dumps({"messages": [{"code": "SQ001", "message": "m"}]})
    assert parse_squawk(sample, "", 1) != []
    assert parse_squawk("broken", "", 1) != []


def test_buf_lines_and_empty() -> None:
    from bughunt.cli import parse_buf_json_lines

    sample = json.dumps({"path": "a.proto", "start_line": 3, "message": "m"})
    found = parse_buf_json_lines(sample + "\nbad\n", "", 1)
    assert [(item.code, item.tool) for item in found] == [(None, "buf")]
    assert parse_buf_json_lines("", "", 0) == []


def test_sarif_file_and_missing(tmp_path) -> None:
    from bughunt.cli import parse_sarif

    assert parse_sarif(tmp_path / "missing.sarif", "codeql") == []
    sarif = tmp_path / "r.sarif"
    _ = sarif.write_text(
        json.dumps(
            {
                "runs": [
                    {
                        "results": [
                            {
                                "ruleId": "R1",
                                "level": "error",
                                "message": {"text": "bad"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "a.py"},
                                            "region": {
                                                "startLine": 8,
                                                "startColumn": 1,
                                            },
                                        }
                                    }
                                ],
                            }
                        ]
                    }
                ]
            }
        )
    )
    found = parse_sarif(sarif, "codeql")
    assert [(item.code, item.line) for item in found] == [("R1", 8)]


def test_bughunt_helper_round_trip() -> None:
    from bughunt.cli import parse_bughunt_helper

    sample = json.dumps(
        {
            "findings": [
                {
                    "tool": "seam",
                    "code": "BHSEAM001",
                    "message": "drift",
                    "path": "a.py",
                    "line": 4,
                    "severity": "error",
                }
            ]
        }
    )
    found = parse_bughunt_helper("seam", sample, "", 1)
    assert [(item.code, item.line) for item in found] == [("BHSEAM001", 4)]
    assert parse_bughunt_helper("seam", "broken", "", 1) != []


def test_pylint_severity_ranking() -> None:
    from bughunt.cli import parse_pylint

    sample = json.dumps(
        [
            {
                "path": "a.py",
                "line": 1,
                "symbol": "unused-import",
                "type": "warning",
                "message": "unused",
            },
            {
                "path": "a.py",
                "line": 2,
                "symbol": "convention",
                "type": "convention",
                "message": "style",
            },
        ]
    )
    found = parse_pylint(sample, "", 1)
    assert len(found) == 2
    assert parse_pylint("broken", "", 1) != []
