"""Command-line interface: `passcheck` (prompts) or `passcheck --json < file`."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys

from .analyzer import analyze

BAR = ["#----", "##---", "###--", "####-", "#####"]


def main(argv: list[str] | None = None) -> int:
    """Entry point. Wraps the real work so that piping into `head` — which closes
    the pipe early — ends quietly instead of printing a BrokenPipeError."""
    try:
        return _run(argv)
    except BrokenPipeError:
        # The reader went away. Point stdout at the void so the interpreter's
        # own flush on exit does not raise the same error again.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        return 0
    except KeyboardInterrupt:
        print(file=sys.stderr)
        return 130


def _run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="passcheck",
        description="Check how strong a password is. Nothing is sent anywhere.",
    )
    parser.add_argument("--json", action="store_true", help="print a JSON report")
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="read one password per line from standard input (for batch checks)",
    )
    parser.add_argument("--min-score", type=int, default=None, metavar="N",
                        help="exit with status 1 if any password scores below N (0-4)")
    args = parser.parse_args(argv)

    if args.stdin:
        passwords = [line.rstrip("\n") for line in sys.stdin if line.strip()]
    else:
        # never accept the password as an argument: it would end up in shell history
        passwords = [getpass.getpass("Password (hidden): ")]

    failed = False
    reports = []
    for pw in passwords:
        report = analyze(pw)
        reports.append(report)
        if args.min_score is not None and report.score < args.min_score:
            failed = True

    if args.json:
        print(json.dumps([r.to_dict() for r in reports], indent=2))
    else:
        for r in reports:
            print(f"Strength: [{BAR[r.score]}] {r.label}  ({r.entropy_bits} bits)")
            print(f"Offline crack time: {r.crack_time_display}")
            for w in r.warnings:
                print(f"  ! {w}")
            for s in r.suggestions:
                print(f"  - {s}")
            if len(reports) > 1:
                print()
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
