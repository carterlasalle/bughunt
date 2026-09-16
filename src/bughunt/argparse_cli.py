# Copyright (c) 2026 Carter LaSalle
"""CLI parser construction."""

from __future__ import annotations

import argparse
from pathlib import Path


# trace:v1 id=impl.src-bughunt-cli-main.add-all-options work=WORK-BUG-JZ02ASSD satisfies=REQ-BUG-SY8DHSTC
def add_all_options(target: argparse.ArgumentParser) -> None:
    _ = target.add_argument(
        "--install-missing",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="install missing analyzers before running (default: true)",
    )
    _ = target.add_argument(
        "--skip",
        action="append",
        default=[],
        metavar="DEFENSE",
        help="skip a defense while keeping all other all-profile defenses",
    )
    _ = target.add_argument(
        "--skip-mutmut",
        action="store_true",
        help="skip mutation testing (same as --skip mutmut)",
    )
    _ = target.add_argument("--no-auto-config", action="store_true")


# trace:v1 id=impl.src-bughunt-argparse-cli.build-parser work=WORK-BUG-06107X2Q satisfies=REQ-BUG-5XJWASR4
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bughunt",
        description=(
            "Run independent bug-finding defenses and compile one agent-ready report."
        ),
    )
    _ = parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="repository root",
    )
    _ = parser.add_argument("--config", type=Path, help="path to bughunt.toml")

    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="run a bug-hunting profile")
    _ = run_p.add_argument(
        "profile_positional",
        nargs="?",
        choices=("fast", "pr", "deep", "all"),
        help="profile (also accepted as --profile)",
    )
    _ = run_p.add_argument(
        "--profile",
        choices=("fast", "pr", "deep", "all"),
        default=None,
    )
    _ = run_p.add_argument(
        "--skip",
        action="append",
        default=[],
        metavar="DEFENSE",
        help="skip a defense while keeping the selected profile (repeatable)",
    )
    _ = run_p.add_argument(
        "--skip-mutmut",
        action="store_true",
        help="skip mutation testing",
    )
    _ = run_p.add_argument(
        "--no-auto-config",
        action="store_true",
        help="do not refresh strict configs or auto-discovered targets",
    )

    for alias, help_text in (
        ("quick", "run the fast feedback profile"),
        ("pr", "run the pull-request profile"),
        ("deep", "run the deep profile"),
    ):
        alias_p = sub.add_parser(alias, help=help_text)
        _ = alias_p.add_argument("--no-auto-config", action="store_true")

    all_p = sub.add_parser(
        "all",
        help="bootstrap, auto-configure, and run every available defense",
    )
    add_all_options(all_p)

    full_p = sub.add_parser(
        "full",
        help="alias for `all`: bootstrap, configure, and run everything",
    )
    add_all_options(full_p)

    skipmutmut_p = sub.add_parser(
        "skipmutmut",
        help="run the all profile but explicitly skip mutation testing",
    )
    add_all_options(skipmutmut_p)

    install_p = sub.add_parser(
        "install",
        help="auto-install the analysis stack using uv (plus CodeQL/Watchman on macOS)",
    )
    _ = install_p.add_argument("--dry-run", action="store_true")
    _ = install_p.add_argument(
        "--only",
        action="append",
        metavar="COMPONENT",
        help="install/repair only this component (repeatable; e.g. --only atheris)",
    )

    config_p = sub.add_parser(
        "configure",
        help="discover and generate safe deep-analysis targets",
    )
    _ = config_p.add_argument("--auto", action="store_true", default=True)

    _ = sub.add_parser(
        "rules",
        help="list the shipped BugHunt-native default rule pack",
    )
    _ = sub.add_parser(
        "doctor",
        help="show available defenses and missing configuration",
    )
    debt_p = sub.add_parser(
        "debt",
        help="snapshot or review accepted finding debt",
    )
    debt_sub = debt_p.add_subparsers(dest="debt_command", required=True)
    snap_p = debt_sub.add_parser(
        "snapshot",
        help="record current findings as accepted debt in debt.toml",
    )
    _ = snap_p.add_argument("--signal", action="append", default=[])
    _ = snap_p.add_argument("--reason", default="")
    _ = snap_p.add_argument(
        "--path",
        action="append",
        default=[],
        help="only record entries under these paths (exact file or directory prefix)",
    )
    _ = debt_sub.add_parser(
        "review",
        help="diff debt.toml against the latest report",
    )

    return parser
