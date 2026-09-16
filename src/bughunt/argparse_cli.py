# Copyright (c) 2026 Carter LaSalle
"""CLI parser construction."""

from __future__ import annotations

import argparse


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
