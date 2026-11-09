#!/usr/bin/env python3
"""Create an opt-in OpenCode MCP config for the locally installed SECRA server."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def build_config(major: int) -> dict:
    launcher = ROOT / "scripts" / "run_opencode_mcp.sh"
    command = ["bash", str(launcher)]
    if major == 1:
        return {
            "$schema": "https://opencode.ai/config.json",
            "mcp": {"secra": {"type": "local", "command": command, "enabled": True}},
        }
    if major == 2:
        return {
            "$schema": "https://opencode.ai/config.json",
            "mcp": {"servers": {"secra": {
                "type": "local", "command": command,
                "cwd": str(ROOT), "disabled": False,
            }}},
        }
    raise ValueError("Unsupported OpenCode major version")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--major", type=int, choices=(1, 2), required=True,
                        help="Use 1 for OpenCode v1 and 2 for OpenCode v2")
    parser.add_argument("--output", type=Path,
                        default=ROOT / ".opencode" / "opencode.json")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    text = json.dumps(build_config(args.major), indent=2) + "\n"
    if args.dry_run:
        print(text, end="")
        return 0
    if not (ROOT / ".venv" / "bin" / "python").exists():
        print("Install a local SECRA .venv and requirements.txt before enabling MCP.",
              file=sys.stderr)
        return 1
    if args.output.is_symlink() or args.output.exists():
        print("Config already exists; refusing overwrite. Merge the dry-run JSON manually.",
              file=sys.stderr)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text, encoding="utf-8")
    print("Created:", args.output)
    print("MCP execution remains subject to SECRA scope and kernel fence gates.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
