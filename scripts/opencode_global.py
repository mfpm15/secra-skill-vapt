#!/usr/bin/env python3
"""Install SECRA OpenCode skills and agents *globally*, without changing shell cwd.

This uses user-owned OpenCode config. It never runs source installers or alters
model/provider settings; MCP is a separate, explicit opt-in.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AGENTS = (
    "secra",
    "secra-vapt", "secra-ctf",
    "secra-recon", "secra-web", "secra-api", "secra-network",
    "secra-verifier", "secra-reporter", "secra-ctf-web",
    "secra-ctf-pwn", "secra-ctf-reverse", "secra-ctf-crypto",
    "secra-ctf-forensics",
    "secra-bounty",
    "secra-bounty-scope",
    "secra-auth",
    "secra-business-logic",
    "secra-graphql",
    "secra-cloud",
    "secra-kubernetes",
    "secra-mobile",
    "secra-ad-identity",
    "secra-forensics",
    "secra-supply-chain",
    "secra-executive",
    "secra-ctf-misc",
    "secra-ctf-mobile",
)
RECEIPT = ".secra-global-agents.json"


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def agent_text(agent_name: str, major: int) -> str:
    if agent_name not in AGENTS:
        raise ValueError("Unknown SECRA agent")
    source = ROOT / ".opencode" / "agents" / (agent_name + ".md")
    content = source.read_text(encoding="utf-8")
    if major == 2:
        if "permissions:\n" not in content or "  - action:" not in content:
            raise ValueError("OpenCode v2 template must define native permissions")
        return content.replace(".local/secra-learning/", "~/.local/share/secra-learning/")
    if not content.startswith("---\n"):
        raise ValueError("Expected template YAML frontmatter")
    _, marker, body = content.partition("\n---\n")
    if not marker:
        raise ValueError("Missing template frontmatter terminator")
    desc = (
        "Unified SECRA coordinator for VAPT, CTF, code and bug bounty."
        if agent_name == "secra"
        else "Scoped SECRA security specialist for authorized work."
    )
    bash_effect = "ask" if agent_name == "secra-ctf" else "deny"
    # Avoid mixed V1 and V2 frontmatter fields. Generate each natively.
    if major == 1:
        frontmatter = (
            "---\n"
            + "description: " + desc + "\n"
            + "mode: primary\n"
            + "permission:\n"
            + "  bash: " + bash_effect + "\n"
            + "  edit: ask\n"
            + "  skill: allow\n"
            + "  external_directory: ask\n"
            + "  websearch: deny\n"
            + "  webfetch: deny\n"
            + "---\n"
        )
    elif major == 2:
        rules = [
            ("shell", bash_effect),
            ("edit", "ask"),
            ("skill", "allow"),
            ("external_directory", "ask"),
            ("websearch", "deny"),
            ("webfetch", "deny"),
        ]
        frontmatter = "---\ndescription: " + desc + "\nmode: primary\npermissions:\n"
        for action, effect in rules:
            frontmatter += (
                "  - action: " + action + "\n"
                '    resource: "*"\n'
                "    effect: " + effect + "\n"
            )
        frontmatter += "---\n"
    else:
        raise ValueError("Unsupported OpenCode major version")

    # Global learning path must not resolve relative to the active project.
    body = body.replace(
        ".local/secra-learning/",
        "~/.local/share/secra-learning/",
    )
    return frontmatter + body


def safe_receipt(path: Path) -> dict:
    if not path.exists():
        return {"schema": 1, "agents": {}}
    if path.is_symlink():
        raise ValueError("Refusing symlink receipt")
    obj = json.loads(path.read_text(encoding="utf-8"))
    if obj.get("schema") != 1 or not isinstance(obj.get("agents"), dict):
        raise ValueError("Invalid global agent receipt")
    return obj


def write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".secra-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write(text)
        os.chmod(name, stat.S_IRUSR | stat.S_IWUSR)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def agents_install(destination: Path, major: int, replace: bool, dry_run: bool) -> None:
    folder = destination / "agents"
    receipt_path = destination / RECEIPT
    receipt = safe_receipt(receipt_path)
    for name in AGENTS:
        file = folder / (name + ".md")
        expected = agent_text(name, major)
        checksum = digest(expected.encode())
        old = receipt["agents"].get(name)
        if file.is_symlink():
            raise ValueError("Refusing symlink agent path " + str(file))
        if file.exists():
            if not isinstance(old, dict) or not old.get("sha256"):
                print("SKIP unmanaged agent:", name)
                continue
            existing_hash = digest(file.read_bytes())
            if existing_hash != old.get("sha256"):
                print("SKIP modified agent:", name)
                continue
            if existing_hash == checksum:
                print("UNCHANGED agent:", name)
                continue
            if not replace:
                print("SKIP agent update (use --replace):", name)
                continue
        if dry_run:
            print("DRY-RUN agent:", name)
            continue
        if file.exists():
            backup_dir = destination / ".secra-agent-backups"
            backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            backup = backup_dir / (name + "-" + stamp + ".md")
            if backup.exists():
                raise ValueError("Backup file exists")
            shutil.copy2(file, backup)
        write_atomic(file, expected)
        receipt["agents"][name] = {"sha256": checksum, "major": major}
        write_atomic(receipt_path, json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        print("INSTALLED global agent:", name)


def agents_verify(destination: Path) -> None:
    receipt = safe_receipt(destination / RECEIPT)
    if set(receipt["agents"]) != set(AGENTS):
        raise ValueError("Expected all managed global SECRA agents")
    for name, entry in receipt["agents"].items():
        path = destination / "agents" / (name + ".md")
        if not path.is_file() or path.is_symlink():
            raise ValueError("Missing global agent " + name)
        if digest(path.read_bytes()) != entry.get("sha256"):
            raise ValueError("Tampered global agent " + name)
    print("Verified %d global agent profiles" % len(AGENTS))


def global_mcp_preview(major: int) -> dict:
    try:
        from scripts.opencode_mcp_config import build_config
    except ModuleNotFoundError:  # Direct execution from scripts/ on Kali.
        from opencode_mcp_config import build_config
    return build_config(major)["mcp"]


def mcp_preflight(destination: Path, major: int) -> None:
    main = destination / "opencode.json"
    alt = destination / "opencode.jsonc"
    if main.is_symlink() or alt.is_symlink():
        raise ValueError("Cannot modify symlink OpenCode config")
    if alt.exists():
        raise ValueError("Existing opencode.jsonc: merge MCP manually using --mcp-preview")
    if main.exists():
        obj = json.loads(main.read_text(encoding="utf-8"))
        if not isinstance(obj, dict):
            raise ValueError("Invalid OpenCode JSON config")
        mcp = obj.get("mcp", {})
        if not isinstance(mcp, dict):
            raise ValueError("Invalid existing MCP config")
        servers = mcp if major == 1 else mcp.get("servers", {})
        if not isinstance(servers, dict):
            raise ValueError("Invalid existing MCP servers")
        if "secra" in servers:
            raise ValueError("Global MCP secra already configured; will not overwrite")
    if not (ROOT / ".venv" / "bin" / "python").is_file():
        raise ValueError("SECRA venv is missing; setup .venv before --with-mcp")


def mcp_install(destination: Path, major: int, dry_run: bool) -> None:
    mcp_preflight(destination, major)
    if dry_run:
        print("DRY-RUN MCP:", json.dumps(global_mcp_preview(major), indent=2))
        return
    main = destination / "opencode.json"
    config = json.loads(main.read_text()) if main.exists() else {
        "$schema": "https://opencode.ai/config.json"
    }
    incoming = global_mcp_preview(major)
    if major == 1:
        config.setdefault("mcp", {})["secra"] = incoming["secra"]
    else:
        config.setdefault("mcp", {}).setdefault("servers", {})["secra"] = incoming["servers"]["secra"]
    if main.exists():
        backup_dir = destination / ".secra-config-backups"
        backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = backup_dir / ("opencode-" + stamp + ".json")
        if backup.exists():
            raise ValueError("Config backup already exists")
        shutil.copy2(main, backup)
    write_atomic(main, json.dumps(config, indent=2, ensure_ascii=False) + "\n")
    print("INSTALLED opt-in global MCP; backend scope/fence checks remain enforced")


def run_skills(destination: Path, args: argparse.Namespace) -> None:
    installer = ROOT / "scripts" / "opencode_security.py"
    command = [
        sys.executable, str(installer), args.command,
        "--destination", str(destination / "skills"),
    ]
    if args.dry_run:
        command.append("--dry-run")
    if args.replace:
        command.append("--replace")
    if args.with_external:
        command.extend(["--with-external", "--external-root", str(args.external_root)])
        if args.reviewed_external:
            command.append("--reviewed-external")
    proc = subprocess.run(command, check=False)
    if proc.returncode:
        raise ValueError("OpenCode skill install/verification failed; exit " + str(proc.returncode))


def main() -> int:
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=("install", "verify"))
    p.add_argument("--major", type=int, choices=(1, 2), default=2,
                   help="OpenCode major version (default: 2)")
    p.add_argument("--config-dir", type=Path, default=Path.home() / ".config" / "opencode",
                   help="Override user config location (mainly for automated tests)")
    p.add_argument("--learning-dir", type=Path, default=Path.home() / ".local" / "share" / "secra-learning")
    p.add_argument("--with-external", action="store_true")
    p.add_argument("--external-root", type=Path)
    p.add_argument("--reviewed-external", action="store_true")
    p.add_argument("--with-mcp", action="store_true", help="Explicitly opt in to global MCP integration")
    p.add_argument("--with-launcher", action="store_true",
                   help="Install/verify the user-owned one-command secra launcher")
    p.add_argument("--launcher-dir", type=Path,
                   default=Path.home() / ".local" / "bin",
                   help="Override CLI launcher directory (default ~/.local/bin)")
    p.add_argument("--mcp-preview", action="store_true", help="Print only version-specific MCP fragment")
    p.add_argument("--replace", action="store_true", help="Backup/upgrade only previously managed profiles/skills")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()
    try:
        if args.mcp_preview:
            print(json.dumps(global_mcp_preview(args.major), indent=2))
            return 0
        destination = args.config_dir.expanduser()
        learning = args.learning_dir.expanduser()
        if args.with_launcher and args.major != 2:
            raise ValueError("Unified secra launcher requires OpenCode v2")
        launcher_path = args.launcher_dir.expanduser() / "secra"
        if args.with_launcher and args.launcher_dir.expanduser().is_symlink():
            raise ValueError("Launcher directory symlink not allowed")
        if destination.is_symlink() or learning.is_symlink():
            raise ValueError("Global install destination must not be a symlink")
        if args.with_external and (not args.reviewed_external or args.external_root is None):
            raise ValueError("External skill imports require --reviewed-external and --external-root")
        if args.with_mcp and args.command == "install":
            mcp_preflight(destination, args.major)
        if args.command == "verify":
            run_skills(destination, args)
            agents_verify(destination)
            if args.with_launcher:
                from scripts.secra_launcher import verify as verify_launcher
                verify_launcher(launcher_path)
            return 0
        run_skills(destination, args)
        agents_install(destination, args.major, args.replace, args.dry_run)
        if args.with_launcher:
            from scripts.secra_launcher import install as install_launcher
            print(install_launcher(
                launcher_path, replace=args.replace, dry_run=args.dry_run))
        if args.with_mcp:
            mcp_install(destination, args.major, args.dry_run)
        if not args.dry_run:
            for folder in (learning / "inbox", learning / "reviewed"):
                folder.mkdir(parents=True, mode=0o700, exist_ok=True)
        if args.with_launcher:
            print("One-command launcher:", launcher_path)
            if str(args.launcher_dir.expanduser()) not in os.environ.get("PATH", "").split(os.pathsep):
                print("Add this directory to PATH in your own shell profile:", args.launcher_dir.expanduser())
        print("OpenCode global config:", destination)
        print("Reviewed learning folder:", learning / "reviewed")
        return 0
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError) as err:
        print("SECRA global setup error:", err, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
