"""Command line interface for LeakHound."""
from __future__ import annotations

import argparse
import sys
from typing import List

from . import __version__
from .rules import DEFAULT_RULES, GENERIC_ENTROPY_RULE
from .scanner import Config, scan_git_history, scan_paths
from . import report


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leakhound",
        description="Catch leaked secrets before they ship.",
    )
    parser.add_argument("--version", action="version", version=f"leakhound {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Scan files or directories for secrets.")
    scan.add_argument("paths", nargs="*", default=["."],
                      help="Files or directories to scan. Defaults to the current directory.")
    scan.add_argument("--format", choices=["text", "json", "sarif"], default="text",
                      help="Output format.")
    scan.add_argument("--git-history", action="store_true",
                      help="Also scan every blob in the git history.")
    scan.add_argument("--no-entropy", action="store_true",
                      help="Turn off the high entropy detector and use only the named rules.")
    scan.add_argument("--entropy-threshold", type=float, default=4.3,
                      help="Bits per character required to flag a random looking string.")
    scan.add_argument("--min-length", type=int, default=20,
                      help="Shortest token length the entropy detector will consider.")
    scan.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                      help="A glob to skip. May be given more than once.")
    scan.add_argument("--exit-zero", action="store_true",
                      help="Always exit 0, even when findings exist.")
    scan.add_argument("--no-color", action="store_true", help="Disable colored output.")

    rules = sub.add_parser("rules", help="List the built in detection rules.")
    rules.add_argument("--json", action="store_true", help="Print the rules as json.")

    sub.add_parser("version", help="Print the version.")
    return parser


def _run_scan(args: argparse.Namespace) -> int:
    paths = args.paths if args.paths else ["."]
    cfg = Config(
        paths=paths,
        use_entropy=not args.no_entropy,
        entropy_threshold=args.entropy_threshold,
        min_token_len=args.min_length,
        excludes=list(args.exclude),
        scan_git_history=args.git_history,
    )

    findings = scan_paths(cfg)
    if args.git_history:
        for base in paths:
            findings.extend(scan_git_history(base, cfg))

    # Deduplicate identical findings.
    seen = set()
    unique = []
    for f in findings:
        key = (f.source, f.path, f.line, f.column, f.fingerprint())
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)

    if args.format == "json":
        print(report.format_json(unique, __version__))
    elif args.format == "sarif":
        print(report.format_sarif(unique, __version__))
    else:
        use_color = (not args.no_color) and sys.stdout.isatty()
        print(report.format_text(unique, use_color=use_color))

    if unique and not args.exit_zero:
        return 1
    return 0


def _run_rules(args: argparse.Namespace) -> int:
    all_rules = list(DEFAULT_RULES) + [GENERIC_ENTROPY_RULE]
    if args.json:
        import json
        payload = [
            {"id": r.id, "name": r.name, "severity": r.severity, "description": r.description}
            for r in all_rules
        ]
        print(json.dumps(payload, indent=2))
        return 0
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for r in sorted(all_rules, key=lambda x: (order.get(x.severity, 9), x.id)):
        print(f"{r.severity.upper():<8}  {r.id:<26}  {r.description}")
    return 0


def main(argv: List[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "scan":
            return _run_scan(args)
        if args.command == "rules":
            return _run_rules(args)
        if args.command == "version":
            print(f"leakhound {__version__}")
            return 0
        parser.print_help()
        return 0
    except BrokenPipeError:
        # Happens when output is piped to a reader that closes early, such as
        # head. Redirect stdout so the interpreter does not flush again on exit.
        import os
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        return 0


if __name__ == "__main__":
    sys.exit(main())
