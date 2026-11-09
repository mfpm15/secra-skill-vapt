#!/usr/bin/env python3
"""Prepare reviewed OpenCode skill SOURCES from explicit GitHub HTTPS URLs.

This clones source TEXT for manual inspection; it never executes fetched
scripts, hooks, dependency installers or knowledge instructions. A separate
operator approval is required before importing third-party SKILL.md content.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

SOURCES = {
    "claude-red": "https://github.com/SnailSploit/Claude-Red.git",
    "ctf-skills": "https://github.com/ljagiello/ctf-skills.git",
    "trailofbits-skills": "https://github.com/trailofbits/skills.git",
    "secskills": "https://github.com/trilwu/secskills.git",
    "cloudflare-security": "https://github.com/cloudflare/security-audit-skill.git",
    "anthropic-cyber": "https://github.com/mukul975/Anthropic-Cybersecurity-Skills.git",
    "reverse-skill": "https://github.com/zhaoxuya520/reverse-skill.git",
    "superpowers": "https://github.com/obra/superpowers.git",
    "planning-with-files": "https://github.com/OthmanAdi/planning-with-files.git",
}
SHA = re.compile(r"^[0-9a-f]{40}$")


def _git(*args: str) -> str:
    proc = subprocess.run(
        ["git", "-c", "protocol.file.allow=never",
         "-c", "protocol.ext.allow=never",
         "-c", "core.hooksPath=/dev/null",
         "-c", "filter.lfs.smudge=",
         "-c", "filter.lfs.required=false",
         *args],
        capture_output=True, text=True, timeout=120, check=False,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1",
             "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_LFS_SKIP_SMUDGE": "1"},
    )
    if proc.returncode:
        raise ValueError("git failed (no source content executed): " +
                         " ".join(args[:2]))
    return proc.stdout.strip()


def prepare(root: Path, *, apply: bool = False) -> list[dict]:
    if root.is_symlink() or (root.exists() and not root.is_dir()):
        raise ValueError("Unsafe source root")
    if apply:
        root.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(root, 0o700)
    result = []
    for key, url in SOURCES.items():
        folder = root / key
        if folder.is_symlink():
            raise ValueError("Source directory symlink")
        if folder.exists():
            if not (folder / ".git").exists():
                raise ValueError("Existing source directory is not a Git checkout: " + key)
            origin = _git("-C", str(folder), "remote", "get-url", "origin")
            if origin.rstrip("/") != url.rstrip("/"):
                raise ValueError("Unexpected source origin: " + key)
            commit = _git("-C", str(folder), "rev-parse", "HEAD")
            if not SHA.fullmatch(commit):
                raise ValueError("Invalid source commit for " + key)
            result.append({
                "source": key, "status": "existing_not_updated",
                "origin": url, "commit": commit,
                "manual_review_required": True,
            })
            continue
        if not apply:
            result.append({"source": key, "status": "dry_run_missing",
                           "origin": url, "manual_review_required": True})
            continue
        _git("clone", "--no-checkout", "--depth", "1", "--", url, str(folder))
        # The working-tree checkout is static text; no scripts are invoked.
        _git("-C", str(folder), "checkout", "-f", "HEAD")
        commit = _git("-C", str(folder), "rev-parse", "HEAD")
        if not SHA.fullmatch(commit):
            raise ValueError("Cloned source commit invalid: " + key)
        result.append({
            "source": key, "status": "cloned_unreviewed",
            "origin": url, "commit": commit,
            "manual_review_required": True,
        })
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=(
        Path.home() / ".local" / "share" / "secra" / "sources"))
    parser.add_argument("--apply", action="store_true",
                        help="Actually clone missing allowlisted sources; never execute their code")
    args = parser.parse_args()
    try:
        status = prepare(args.root.expanduser(), apply=args.apply)
        print(json.dumps({"schema": 1, "imported_skills": 0,
                          "must_review_each_source_before_import": True,
                          "sources": status}, indent=2))
        return 0
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print("Source preparation blocked: " + str(exc)[:160], file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
