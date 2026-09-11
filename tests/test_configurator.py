from pathlib import Path
import tomllib

from bughunt.configurator import configure_custom_checks
from bughunt.discovery import DiscoveredTarget
from bughunt.cli import load_config


def test_custom_checks_are_managed_and_loadable(tmp_path: Path):
    targets = [
        DiscoveredTarget(
            kind="custom-differential",
            name="demo.score:differential",
            confidence="high",
            runnable=True,
            reason="test",
            command=["uv", "run", "pytest", "-q", "generated.py"],
            metadata={"timeout": 123},
        )
    ]
    configure_custom_checks(tmp_path, targets)
    text = (tmp_path / "bughunt.toml").read_text()
    assert "[[custom.checks]]" in text
    assert tomllib.loads(text)["custom"]["checks"][0]["timeout"] == 123
    cfg = load_config(tmp_path)
    assert "ruff" in cfg.tools("fast")
    assert cfg.raw["custom"]["checks"][0]["generated"] is True

    configure_custom_checks(tmp_path, targets)
    assert (tmp_path / "bughunt.toml").read_text().count("BEGIN BUGHUNT MANAGED CUSTOM CHECKS") == 1


def test_configure_all_generates_complexity_and_env_contract(tmp_path: Path) -> None:
    from bughunt.configurator import configure_all

    src = tmp_path / "src" / "demo"
    src.mkdir(parents=True)
    (src / "__init__.py").write_text("")
    (src / "settings_use.py").write_text("import os\nTOKEN = os.environ['API_TOKEN']\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "pyproject.toml").write_text('[project]\nname="demo"\nversion="0"\n')

    artifacts = configure_all(tmp_path, ["src", "tests"], ["src"], ["tests"])
    assert (tmp_path / ".bughunt/configs/complexipy.toml").exists()
    assert (tmp_path / ".env.example").exists()
    assert "API_TOKEN=" in (tmp_path / ".env.example").read_text()
    assert "[complexity]" in (tmp_path / "bughunt.toml").read_text()
    assert any(item.name == "BugHunt policy pack" for item in artifacts)


def test_shipped_astgrep_rules_have_positive_negative_tests(tmp_path):
    from bughunt.configurator import configure_all

    (tmp_path / "src/pkg").mkdir(parents=True)
    (tmp_path / "src/pkg/__init__.py").write_text("")
    (tmp_path / "tests").mkdir()
    (tmp_path / "pyproject.toml").write_text('[project]\nname="pkg"\nversion="0"\n')
    configure_all(tmp_path, ["src", "tests"], ["src"], ["tests"])
    tests_dir = tmp_path / ".bughunt/configs/ast-grep/tests"
    finally_test = (tests_dir / "bughunt-return-in-finally-test.yml").read_text()
    swallowed_test = (tests_dir / "bughunt-swallowed-exception-test.yml").read_text()
    assert "valid:" in finally_test and "invalid:" in finally_test
    assert "valid:" in swallowed_test and "invalid:" in swallowed_test



def test_configure_all_ships_correctness_first_semgrep_rules(tmp_path: Path) -> None:
    from bughunt.configurator import configure_all

    (tmp_path / "src/pkg").mkdir(parents=True)
    (tmp_path / "src/pkg/__init__.py").write_text("")
    (tmp_path / "tests").mkdir()
    (tmp_path / "pyproject.toml").write_text('[project]\nname="pkg"\nversion="0"\n')
    artifacts = configure_all(tmp_path, ["src", "tests"], ["src"], ["tests"])
    rules = (tmp_path / ".bughunt/configs/semgrep/rules/bughunt-correctness.yml").read_text()
    assert rules.count("  - id: bughunt.") == 7
    assert "bughunt.cached-generator" in rules
    assert "bughunt.unconsumed-threadpool-map" in rules
    semgrep = next(item for item in artifacts if item.name == "Semgrep")
    assert "correctness-first" in semgrep.detail
    assert "security-audit/secrets are opt-in" in semgrep.detail


def test_existing_user_mutmut_config_is_coverage_checked(tmp_path: Path) -> None:
    from bughunt.configurator import configure_all

    (tmp_path / "src/pkg").mkdir(parents=True)
    (tmp_path / "src/pkg/__init__.py").write_text("")
    (tmp_path / "tests").mkdir()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="pkg"\nversion="0"\n\n[tool.mutmut]\nsource_paths=["other/"]\npytest_add_cli_args_test_selection=["tests/"]\n'
    )
    artifacts = configure_all(tmp_path, ["src", "tests"], ["src"], ["tests"])
    mm = next(item for item in artifacts if item.name == "mutmut")
    assert mm.state == "REVIEW"
    assert "source_paths miss" in mm.detail
    assert 'source_paths=["other/"]' in (tmp_path / "pyproject.toml").read_text()


def test_managed_mutmut_config_refreshes_inferred_paths(tmp_path: Path) -> None:
    from bughunt.configurator import configure_all

    (tmp_path / "src/pkg").mkdir(parents=True)
    (tmp_path / "src/pkg/__init__.py").write_text("")
    (tmp_path / "tests").mkdir()
    (tmp_path / "pyproject.toml").write_text('[project]\nname="pkg"\nversion="0"\n')
    configure_all(tmp_path, ["src", "tests"], ["src"], ["tests"])
    (tmp_path / "lib").mkdir()
    artifacts = configure_all(tmp_path, ["lib", "tests"], ["lib"], ["tests"])
    text = (tmp_path / "pyproject.toml").read_text()
    assert 'source_paths = ["lib/"]' in text
    assert text.count("[tool.mutmut]") == 1
    mm = next(item for item in artifacts if item.name == "mutmut")
    assert mm.state == "READY"
    assert "refreshed and verified" in mm.detail
