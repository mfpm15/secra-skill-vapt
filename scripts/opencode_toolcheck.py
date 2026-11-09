#!/usr/bin/env python3
"""Offline Kali dependency and SECRA MCP tool-readiness inventory.

This only checks command resolution and manifest metadata. It never runs
pentest tools or connects to assessment targets.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

TOOL_GROUPS = {
    "recon": ("nmap", "masscan", "subfinder", "amass", "dnsx", "whatweb", "whois", "dig"),
    "web": ("httpx", "katana", "ffuf", "gobuster", "feroxbuster", "nikto", "nuclei", "wpscan", "dirsearch"),
    "api": ("curl", "arjun", "kr", "graphql-cop"),
    "tls": ("sslscan", "testssl.sh", "ssh-audit"),
    "ctf-pwn": ("gdb", "readelf", "objdump", "checksec", "radare2", "rizin"),
    "ctf-reverse": ("ghidra", "ghidraRun", "r2", "file", "strings", "binwalk"),
    "ctf-crypto": ("sage", "python3", "openssl"),
    "ctf-forensics": ("exiftool", "tshark", "foremost", "vol", "volatility"),
}


def command_exists(command: str) -> bool:
    return shutil.which(command) is not None


def describe_manifest() -> list[dict]:
    data = json.loads((ROOT / "app" / "mcp" / "manifest.json").read_text(encoding="utf-8"))
    result = []
    for t in data.get("tools", []):
        result.append({"name": t.get("name"), "risk": t.get("risk"),
                       "mode": t.get("mode"), "adapter": t.get("adapter")})
    return result


def report() -> dict:
    return {
        "python": sys.version.split()[0],
        "opencode_binary_found": command_exists("opencode"),
        "mcp_venv_found": (ROOT / ".venv" / "bin" / "python").is_file(),
        "groups": {
            name: {"available": [cmd for cmd in commands if command_exists(cmd)],
                   "missing": [cmd for cmd in commands if not command_exists(cmd)]}
            for name, commands in TOOL_GROUPS.items()
        },
        "manifest": describe_manifest(),
        "disclaimer": "Tool presence is not execution authorization or a successful live test.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Output machine-readable inventory")
    args = parser.parse_args()
    data = report()
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print("OpenCode on PATH:", "yes" if data["opencode_binary_found"] else "no")
        print("SECRA .venv Python:", "yes" if data["mcp_venv_found"] else "no")
        for name, info in data["groups"].items():
            print(name + ":")
            print("  available:", ", ".join(info["available"]) or "(none)")
            print("  missing:  ", ", ".join(info["missing"]) or "(none)")
        print("SECRA MCP manifest exposes %d reviewed entries" % len(data["manifest"]))
        print(data["disclaimer"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
