"""CLI: python -m app.masking check <file> [--tier foreign] [--customer NAME]."""
from __future__ import annotations
import argparse
import sys
from pathlib import Path

from . import MemoryVault, guard_mask, rehydrate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.masking")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="Inspect local redacted fixture (no network request)")
    check.add_argument("file", type=Path)
    check.add_argument("--tier", choices=["foreign", "trusted", "local"], default="foreign")
    check.add_argument("--customer", action="append", default=[])
    args = parser.parse_args(argv)
    if args.command != "check":
        return 2
    try:
        source = args.file.read_text(encoding="utf-8")
        vault = MemoryVault()
        masked, delta = guard_mask(source, vault=vault, tier=args.tier,
                                   customer_names=args.customer)
        _, unresolved = rehydrate(masked, vault)
        print(masked, end="" if masked.endswith("\n") else "\n")
        print("\n--- MASKING CHECK ---")
        print("placeholders:", delta["count"])
        print("unresolved:", unresolved)
        print("tier:", args.tier)
        return 1 if unresolved else 0
    except (OSError, UnicodeError, ValueError, RuntimeError) as exc:
        print("MASKING_CHECK_FAILED: " + type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
