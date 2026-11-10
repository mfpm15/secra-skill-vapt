#!/usr/bin/env python3
"""Offline checkpoint of SECRA/OpenCode installation metadata.

Never reads credential values, evidence bytes, SQLite rows, or remote services.
A recorded repo commit is a source checkpoint, not proof of Kali validation.
This is a compatibility signal, not a backup/rollback implementation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

SCHEMA = "secra-install-checkpoint-v1"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha(path: Path) -> str | None:
    # Never follow a symlink for metadata snapshots.
    if path.is_symlink():
        raise ValueError("CHECKPOINT_SYMLINK_DENIED")
    return _sha(path.read_bytes()) if path.is_file() else None


def file_names(folder: Path, pattern: str, *, include_dirs: bool = False) -> list[str]:
    if folder.is_symlink():
        raise ValueError("CHECKPOINT_SYMLINK_DENIED")
    if not folder.is_dir():
        return []
    return sorted(
        p.name for p in folder.glob(pattern)
        if (p.is_dir() if include_dirs else p.is_file()) and not p.is_symlink()
    )


def git_head(repo: Path) -> str | None:
    if not (repo / ".git").exists():
        return None
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--verify", "HEAD"],
            capture_output=True, text=True, check=False, timeout=5,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    value = result.stdout.strip()
    if result.returncode or len(value) != 40 or any(c not in "0123456789abcdef" for c in value):
        return None
    return value


def tool_fingerprints(repo: Path) -> dict[str, str]:
    path = repo / "app" / "mcp" / "manifest.json"
    if path.is_symlink():
        raise ValueError("CHECKPOINT_SYMLINK_DENIED")
    if not path.is_file():
        return {}
    obj = json.loads(path.read_text(encoding="utf-8"))
    if obj.get("schema") != 1 or not isinstance(obj.get("tools"), list):
        raise ValueError("CHECKPOINT_MANIFEST_INVALID")
    result = {}
    for item in obj["tools"]:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise ValueError("CHECKPOINT_MANIFEST_INVALID")
        name = item["name"]
        if name in result:
            raise ValueError("CHECKPOINT_MANIFEST_DUPLICATE")
        result[name] = _sha(json.dumps(
            item, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("utf-8"))
    return dict(sorted(result.items()))


def snapshot(repo: Path, config: Path, data: Path, launcher: Path) -> dict:
    """No credentials, target names, customer content or absolute paths emitted."""
    for path in (repo, config, data):
        if path.is_symlink():
            raise ValueError("CHECKPOINT_SYMLINK_DENIED")
    return {
        "schema": SCHEMA,
        "repo_head": git_head(repo),
        "python_version": list(sys.version_info[:3]),
        "opencode_available": bool(shutil.which("opencode")),
        "venv_python_present": (repo / ".venv/bin/python").is_file(),
        "launcher_sha256": file_sha(launcher),
        "config_sha256": {
            name: file_sha(config / name)
            for name in ("opencode.json", "opencode.jsonc")
        },
        "agents": file_names(config / "agents", "secra*.md"),
        "skills": file_names(config / "skills", "secra-*", include_dirs=True),
        "tool_contract_sha256": tool_fingerprints(repo),
        "data_root_present": data.is_dir(),
        "task_database_present": (data / "agent-events.sqlite3").is_file(),
        "vault_directory_present": (data / "evidence").is_dir(),
    }


def compare(previous: dict, current: dict) -> dict:
    if previous.get("schema") != SCHEMA or current.get("schema") != SCHEMA:
        raise ValueError("CHECKPOINT_SCHEMA_INVALID")
    failures = []
    def ensure(condition: bool, code: str) -> None:
        if not condition:
            failures.append(code)
    for field in ("opencode_available", "venv_python_present",
                  "data_root_present", "task_database_present",
                  "vault_directory_present"):
        if previous.get(field) is True:
            ensure(current.get(field) is True, field.upper() + "_LOST")
    if previous.get("launcher_sha256") is not None:
        ensure(current.get("launcher_sha256") is not None,
               "LAUNCHER_REMOVED")
        if current.get("launcher_sha256") is not None:
            ensure(current.get("launcher_sha256") == previous["launcher_sha256"],
                   "LAUNCHER_CHANGED")
    for name, old_hash in previous.get("config_sha256", {}).items():
        if old_hash is not None:
            ensure(current.get("config_sha256", {}).get(name) == old_hash,
                   "OPENCODE_CONFIG_CHANGED_" + name.replace(".", "_").upper())
    for field in ("agents", "skills"):
        missing = set(previous.get(field, [])) - set(current.get(field, []))
        ensure(not missing, field.upper() + "_REMOVED")
    old_tools = previous.get("tool_contract_sha256", {})
    newer = current.get("tool_contract_sha256", {})
    for name, digest in old_tools.items():
        ensure(newer.get(name) == digest, "MCP_CONTRACT_CHANGED_" + name)
    return {
        "schema": "secra-install-comparison-v1",
        "compatible": not failures,
        "checks_failed": failures,
        "previous_tool_count": len(old_tools),
        "current_tool_count": len(newer),
        "previous_agent_count": len(previous.get("agents", [])),
        "current_agent_count": len(current.get("agents", [])),
        "previous_skill_count": len(previous.get("skills", [])),
        "current_skill_count": len(current.get("skills", [])),
        "source_commit_changed": previous.get("repo_head") != current.get("repo_head"),
        "note": "Metadata comparison only; Kali functions, live fence and provider are NOT tested.",
    }


def capture(path: Path, data: dict) -> None:
    if path.exists() or path.is_symlink() or path.parent.is_symlink():
        raise ValueError("CHECKPOINT_FILE_ALREADY_EXISTS_OR_SYMLINK")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Exclusive create: never overwrite an existing checkpoint.
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def main() -> int:
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=("capture", "compare"))
    p.add_argument("--repo", type=Path,
                   default=Path.home() / ".local/share/secra/repo")
    p.add_argument("--config-dir", type=Path,
                   default=Path.home() / ".config/opencode")
    p.add_argument("--launcher", type=Path,
                   default=Path.home() / ".local/bin/secra")
    p.add_argument("--data-dir", type=Path, default=None)
    p.add_argument("--output", type=Path)
    p.add_argument("--baseline", type=Path)
    args = p.parse_args()
    repo = args.repo.expanduser()
    data = (args.data_dir or Path(
        os.environ.get("SECRA_DATA_DIR", str(repo / "data"))
    )).expanduser()
    try:
        current = snapshot(repo, args.config_dir.expanduser(), data,
                           args.launcher.expanduser())
        if args.command == "capture":
            if args.output is None:
                raise ValueError("CHECKPOINT_OUTPUT_REQUIRED")
            capture(args.output.expanduser(), current)
            print("Local metadata checkpoint captured; no credentials or evidence exported.")
            return 0
        if args.baseline is None or args.baseline.is_symlink():
            raise ValueError("CHECKPOINT_BASELINE_REQUIRED")
        previous = json.loads(args.baseline.read_text(encoding="utf-8"))
        verdict = compare(previous, current)
        print(json.dumps(verdict, indent=2, sort_keys=True))
        return 0 if verdict["compatible"] else 2
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("SECRA_CHECKPOINT_ERROR: " + type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
